package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestWatchPageHeadersAndNoInlineCode(t *testing.T) {
	s, _, _ := newTestServer(t, true)
	h := s.APIHandler()
	for _, f := range []string{"", "watch.js", "watch.css"} {
		w := call(h, "GET", "/gate/v1/watch/"+f, "", "", "203.0.113.10", nil)
		if w.Code != 200 || w.Header().Get("Content-Security-Policy") != watchCSP ||
			w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%q: %d %v", f, w.Code, w.Header())
		}
	}
	page := call(h, "GET", "/gate/v1/watch/", "", "", "203.0.113.10", nil).Body.String()
	if regexp.MustCompile(`<script[^>]*>\s*[^<\s]|\sstyle=|\son[a-z]+=|<style`).MatchString(page) {
		t.Fatal("inline script, style or handler: the CSP would block it")
	}
	if strings.Contains(page, "muted") || strings.Contains(page, "autoplay") {
		t.Fatal("the player must never start muted")
	}
	for _, f := range []string{"../config.go", "index.html", "x.js"} {
		if w := call(h, "GET", "/gate/v1/watch/"+f, "", "", "203.0.113.10", nil); w.Code == 200 {
			t.Fatalf("%q served: %d", f, w.Code)
		}
	}
}

func TestChannelsAndLiveNeedOwnerLogin(t *testing.T) {
	s, _, _ := newTestServer(t, true)
	asked := ""
	s.live = func(p string) (bool, error) { asked = p; return p == "beaver", nil }
	h := s.APIHandler()
	if w := call(h, "GET", "/gate/v1/channels", "", "", "203.0.113.10", nil); w.Code != 401 {
		t.Fatalf("channels without login: %d", w.Code)
	}
	w := call(h, "GET", "/gate/v1/channels", "eevee", pwE, "203.0.113.10", nil)
	if w.Code != 200 || w.Body.String() != `{"channels":["beaver","beaver-phone","eevee"]}`+"\n" {
		t.Fatalf("channels: %d %s", w.Code, w.Body.String())
	}
	if w := call(h, "GET", "/gate/v1/live/beaver", "admin", pwA, "203.0.113.10", nil); w.Code != 401 {
		t.Fatalf("live for a non-owner: %d", w.Code)
	}
	if w := call(h, "GET", "/gate/v1/live/beaver", "eevee", pwE, "203.0.113.10", nil); w.Body.String() != `{"live":true}`+"\n" {
		t.Fatalf("live: %s", w.Body.String())
	}
	asked = ""
	if w := call(h, "GET", "/gate/v1/live/"+camShare, "eevee", pwE, "203.0.113.10", nil); w.Code != 404 || asked != "" {
		t.Fatalf("webcam paths aren't probed: %d", w.Code)
	}
}

func TestMTXLive(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != internalUser || p != "pw" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v3/paths/get/beaver":
			w.Write([]byte(`{"name":"beaver","ready":true}`))
		case "/v3/paths/get/eevee":
			w.Write([]byte(`{"name":"eevee","ready":false}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer api.Close()
	m := NewMTX(api.URL, "pw")
	for p, want := range map[string]bool{"beaver": true, "eevee": false, "beaver-phone": false} {
		if got, err := m.Live(p); err != nil || got != want {
			t.Fatalf("%s: %v %v", p, got, err)
		}
	}
	if _, err := NewMTX(api.URL, "bad").Live("beaver"); err == nil {
		t.Fatal("API refusal is an error, not offline")
	}
}
