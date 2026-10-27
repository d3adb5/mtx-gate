package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

// Marker on every refusal the gate makes itself, so clients can tell it from MediaMTX's 404 (a JSON body).
const gateRefusal = "X-Mtx-Gate"

// Counters are all the gate records: no paths, logins, tickets or addresses.
type Counters struct {
	Allowed, Denied, WouldDeny atomic.Int64
}

type Server struct {
	g        *Gate
	trusted  []netip.Prefix
	enforce  bool
	counters *Counters
	failWait time.Duration
}

// decide applies permissive mode: when not enforcing, a denial is only counted.
func (s *Server) decide(ok bool) bool {
	switch {
	case ok:
		s.counters.Allowed.Add(1)
	case s.enforce:
		s.counters.Denied.Add(1)
	default:
		s.counters.WouldDeny.Add(1)
		return true
	}
	return ok
}

// clientIP takes the right-most X-Forwarded-For entry that isn't a trusted proxy.
func (s *Server) clientIP(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if !s.isTrusted(ip) {
		return ip, true
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return netip.Addr{}, false
		}
		if h = h.Unmap(); !s.isTrusted(h) {
			return h, true
		}
	}
	return netip.Addr{}, false
}

func (s *Server) isTrusted(ip netip.Addr) bool {
	for _, p := range s.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func refuse(w http.ResponseWriter, code int) {
	w.Header().Set(gateRefusal, "1")
	w.WriteHeader(code)
}

// owner checks Basic auth; every failure looks the same and costs the caller failWait.
func (s *Server) owner(w http.ResponseWriter, r *http.Request) (string, bool) {
	u, p, ok := r.BasicAuth()
	if ok && s.g.Owner(u, p) {
		return u, true
	}
	time.Sleep(s.failWait)
	w.Header().Set("WWW-Authenticate", `Basic realm="mtx-gate"`)
	refuse(w, http.StatusUnauthorized)
	return "", false
}

func writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errForbidden):
		refuse(w, http.StatusForbidden)
	case errors.Is(err, errLimit):
		refuse(w, http.StatusTooManyRequests)
	case errors.Is(err, errExpired):
		refuse(w, http.StatusGone)
	default:
		refuse(w, http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// APIHandler serves /gate/v1/* (through the ingress) and /forward (Traefik forwardAuth, not routed by the ingress).
func (s *Server) APIHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /forward", func(w http.ResponseWriter, r *http.Request) {
		ip, ok := s.clientIP(r)
		if s.decide(ok && s.g.IsOpen(ip)) {
			w.WriteHeader(http.StatusOK)
			return
		}
		refuse(w, http.StatusNotFound)
	})
	m.HandleFunc("POST /gate/v1/open", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.owner(w, r); !ok {
			return
		}
		ip, ok := s.clientIP(r)
		if !ok {
			refuse(w, http.StatusBadRequest)
			return
		}
		if err := s.g.Open(ip); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"ip": ip.String(), "ttl_s": int(openTTL.Seconds())})
	})
	m.HandleFunc("POST /gate/v1/redeem", func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.owner(w, r)
		if !ok {
			return
		}
		var body struct{ ID, Secret string }
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body); err != nil {
			refuse(w, http.StatusBadRequest)
			return
		}
		ip, ok := s.clientIP(r)
		if !ok {
			refuse(w, http.StatusBadRequest)
			return
		}
		if err := s.g.Redeem(user, ip, body.ID, body.Secret); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"ip": ip.String(), "ttl_s": int(openTTL.Seconds())})
	})
	m.HandleFunc("/gate/v1/shares/", func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.owner(w, r)
		if !ok {
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/gate/v1/shares/")
		path, sub, tickets := strings.Cut(rest, "/tickets")
		var err error
		switch {
		case !tickets && r.Method == http.MethodPut:
			ip, ok := s.clientIP(r)
			if !ok {
				refuse(w, http.StatusBadRequest)
				return
			}
			created, e := s.g.PutShare(user, path, ip)
			if err = e; err == nil {
				if created {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
				}
				writeJSON(w, map[string]any{"ip": ip.String(), "ttl_s": int(shareTTL.Seconds())})
				return
			}
		case !tickets && r.Method == http.MethodDelete:
			if err = s.g.DeleteShare(user, path); err == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		case tickets && sub == "" && r.Method == http.MethodPost:
			id, secret, _, e := s.g.NewTicket(user, path)
			if err = e; err == nil {
				writeJSON(w, map[string]any{"id": id, "secret": secret, "redeem_in_s": int(redeemWindow.Seconds())})
				return
			}
		case tickets && strings.HasPrefix(sub, "/") && r.Method == http.MethodDelete:
			if err = s.g.DeleteTicket(user, path, sub[1:]); err == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		default:
			err = errNotFound
		}
		writeErr(w, err)
	})
	return m
}

// AuthHandler answers MediaMTX's authHTTPAddress; it listens on loopback only.
func (s *Server) AuthHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /auth", func(w http.ResponseWriter, r *http.Request) {
		var req AuthRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ok := s.g.Authorize(&req)
		if req.Action == "api" || req.Action == "metrics" {
			// Permissive mode never opens the API or metrics.
			s.decide(ok)
		} else {
			ok = s.decide(ok)
		}
		if ok {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	m.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"allowed": s.counters.Allowed.Load(), "denied": s.counters.Denied.Load(),
			"would_deny": s.counters.WouldDeny.Load(), "enforce": s.enforce,
		})
	})
	return m
}
