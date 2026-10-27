package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/netip"
	"time"
)

// MTX kicks MediaMTX sessions through its API, logged in as the gate's internal user.
type MTX struct {
	base, pass string
	client     *http.Client
}

func NewMTX(base, pass string) *MTX {
	return &MTX{base: base, pass: pass, client: &http.Client{Timeout: 5 * time.Second}}
}

type mtxSession struct {
	ID, Path, User, RemoteAddr string
}

func (m *MTX) do(method, url string, out any) error {
	req, err := http.NewRequest(method, m.base+url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(internalUser, m.pass)
	res, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return &statusError{res.StatusCode}
	}
	if out != nil {
		return json.NewDecoder(res.Body).Decode(out)
	}
	return nil
}

type statusError struct{ code int }

func (e *statusError) Error() string { return http.StatusText(e.code) }

func matches(s mtxSession, path, user string, ip netip.Addr) bool {
	if (path != "" && s.Path != path) || (user != "" && s.User != user) {
		return false
	}
	if ip.IsValid() {
		ap, err := netip.ParseAddrPort(s.RemoteAddr)
		return err == nil && key(ap.Addr()) == key(ip)
	}
	return true
}

// Kick ends every RTSPS and WebRTC session that matches. Errors are logged without any detail of the session.
func (m *MTX) Kick(path, user string, ip netip.Addr) {
	for _, kind := range []string{"rtsps", "webrtc"} {
		var list struct{ Items []mtxSession }
		if err := m.do(http.MethodGet, "/v3/"+kind+"/sessions/list?itemsPerPage=1000", &list); err != nil {
			log.Printf("kick: listing %s sessions failed: %v", kind, err)
			continue
		}
		for _, s := range list.Items {
			if matches(s, path, user, ip) {
				if err := m.do(http.MethodPost, "/v3/"+kind+"/sessions/kick/"+s.ID, nil); err != nil {
					log.Printf("kick: a %s kick failed: %v", kind, err)
				}
			}
		}
	}
}
