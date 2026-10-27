package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func newTestServer(t *testing.T, enforce bool) (*Server, *Gate, *kickLog) {
	g, _, k := newTestGate(t)
	s := &Server{g: g, trusted: []netip.Prefix{netip.MustParsePrefix("10.244.0.0/16")}, enforce: enforce,
		counters: &Counters{}}
	return s, g, k
}

// call sends r as if Traefik (10.244.1.5) forwarded it for client.
func call(h http.Handler, method, url, user, pass, client string, body any) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, url, rd)
	r.RemoteAddr = "10.244.1.5:40000"
	r.Header.Set("X-Forwarded-For", client)
	if user != "" {
		r.SetBasicAuth(user, pass)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAPIFlow(t *testing.T) {
	s, g, _ := newTestServer(t, true)
	h := s.APIHandler()
	if w := call(h, "GET", "/forward", "", "", "203.0.113.10", nil); w.Code != 404 || w.Header().Get(gateRefusal) == "" {
		t.Fatalf("forward before open: %d", w.Code)
	}
	if w := call(h, "POST", "/gate/v1/open", "beaver", "nope", "203.0.113.10", nil); w.Code != 401 {
		t.Fatalf("bad login: %d", w.Code)
	}
	if w := call(h, "POST", "/gate/v1/open", "admin", pwA, "203.0.113.10", nil); w.Code != 401 {
		t.Fatalf("admin is not an owner: %d", w.Code)
	}
	// A spoofed left-most X-Forwarded-For entry must not be the one opened.
	if w := call(h, "POST", "/gate/v1/open", "beaver", pwB, "192.0.2.99, 203.0.113.10", nil); w.Code != 200 {
		t.Fatalf("open: %d", w.Code)
	}
	if g.IsOpen(ipX) || !g.IsOpen(ipB) {
		t.Fatal("opened the right-most untrusted hop only")
	}
	if w := call(h, "GET", "/forward", "", "", "203.0.113.10", nil); w.Code != 200 {
		t.Fatalf("forward after open: %d", w.Code)
	}
	if w := call(h, "PUT", "/gate/v1/shares/"+camShare, "beaver", pwB, "203.0.113.10", nil); w.Code != 201 {
		t.Fatalf("put share: %d", w.Code)
	}
	if w := call(h, "PUT", "/gate/v1/shares/"+camShare, "beaver", pwB, "203.0.113.10", nil); w.Code != 200 {
		t.Fatalf("renew share: %d", w.Code)
	}
	w := call(h, "POST", "/gate/v1/shares/"+camShare+"/tickets", "beaver", pwB, "203.0.113.10", nil)
	var tk struct{ ID, Secret string }
	json.Unmarshal(w.Body.Bytes(), &tk)
	if w.Code != 200 || len(tk.ID) != 16 || len(tk.Secret) != 32 {
		t.Fatalf("ticket: %d %q", w.Code, w.Body.String())
	}
	if w := call(h, "POST", "/gate/v1/redeem", "eevee", pwE, "198.51.100.20", tk); w.Code != 200 {
		t.Fatalf("redeem: %d", w.Code)
	}
	if !g.Authorize(req("eevee", pwE, "read", camShare, ipE)) {
		t.Fatal("viewer reads after redeem")
	}
	if w := call(h, "DELETE", "/gate/v1/shares/"+camShare+"/tickets/"+tk.ID, "eevee", pwE, "198.51.100.20", nil); w.Code != 403 {
		t.Fatalf("viewer revokes: %d", w.Code)
	}
	if w := call(h, "DELETE", "/gate/v1/shares/"+camShare+"/tickets/"+tk.ID, "beaver", pwB, "203.0.113.10", nil); w.Code != 204 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if w := call(h, "DELETE", "/gate/v1/shares/"+camShare, "beaver", pwB, "203.0.113.10", nil); w.Code != 204 {
		t.Fatalf("delete share: %d", w.Code)
	}
	if w := call(h, "PUT", "/gate/v1/shares/beaver", "beaver", pwB, "203.0.113.10", nil); w.Code != 404 {
		t.Fatalf("fixed paths aren't shares: %d", w.Code)
	}
	if w := call(h, "GET", "/gate/v1/shares/"+camShare, "beaver", pwB, "203.0.113.10", nil); w.Code != 404 {
		t.Fatalf("unknown method: %d", w.Code)
	}
}

func TestDirectClientIgnoresForwardedFor(t *testing.T) {
	s, g, _ := newTestServer(t, true)
	r := httptest.NewRequest("POST", "/gate/v1/open", nil)
	r.RemoteAddr = "192.0.2.99:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.10")
	r.SetBasicAuth("beaver", pwB)
	s.APIHandler().ServeHTTP(httptest.NewRecorder(), r)
	if g.IsOpen(ipB) || !g.IsOpen(ipX) {
		t.Fatal("untrusted peer's X-Forwarded-For was believed")
	}
}

func authCall(h http.Handler, r *AuthRequest) int {
	b, _ := json.Marshal(r)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/auth", bytes.NewReader(b)))
	return w.Code
}

func TestPermissiveModeCountsOnly(t *testing.T) {
	s, _, _ := newTestServer(t, false)
	h := s.AuthHandler()
	if authCall(h, req("eevee", pwE, "read", camShare, ipE)) != 200 {
		t.Fatal("permissive mode lets reads through")
	}
	if authCall(h, req("beaver", pwB, "api", "", ipB)) != 401 {
		t.Fatal("permissive mode never opens the API")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/stats", nil))
	if !strings.Contains(w.Body.String(), `"would_deny":2`) {
		t.Fatalf("stats: %s", w.Body.String())
	}
	s2, g2, _ := newTestServer(t, true)
	if authCall(s2.AuthHandler(), req("eevee", pwE, "read", camShare, ipE)) != 401 {
		t.Fatal("enforcing")
	}
	g2.Open(ipE)
	if authCall(s2.AuthHandler(), req("eevee", pwE, "read", "beaver", ipE)) != 200 {
		t.Fatal("enforcing allows a valid read")
	}
}
