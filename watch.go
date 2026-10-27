package main

import (
	"embed"
	"net/http"
	"slices"
	"strings"
)

// The browser watch page: a WHEP player of its own (MediaMTX's starts muted and can't open the gate).
//
//go:embed watch
var watchFiles embed.FS

const watchCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; " +
	"media-src 'self' blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func secureHeaders(h http.Header) {
	h.Set("Content-Security-Policy", watchCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), display-capture=(), autoplay=(self), fullscreen=(self)")
}

var watchAssets = map[string]string{
	"":          "text/html; charset=utf-8",
	"watch.js":  "text/javascript; charset=utf-8",
	"watch.css": "text/css; charset=utf-8",
}

func (s *Server) watchRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /gate/v1/watch/{file...}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("file")
		ct, ok := watchAssets[name]
		if !ok {
			refuse(w, http.StatusNotFound)
			return
		}
		if name == "" {
			name = "index.html"
		}
		b, err := watchFiles.ReadFile("watch/" + name)
		if err != nil {
			refuse(w, http.StatusNotFound)
			return
		}
		secureHeaders(w.Header())
		w.Header().Set("Content-Type", ct)
		w.Write(b)
	})
	m.HandleFunc("GET /gate/v1/watch", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/gate/v1/watch/", http.StatusMovedPermanently)
	})
	// Channels and liveness are for owners only: a stranger learns no channel names.
	m.HandleFunc("GET /gate/v1/channels", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.owner(w, r); !ok {
			return
		}
		secureHeaders(w.Header())
		writeJSON(w, map[string]any{"channels": s.g.Channels()})
	})
	m.HandleFunc("GET /gate/v1/live/{path...}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.owner(w, r); !ok {
			return
		}
		path := r.PathValue("path")
		if !slices.Contains(s.g.Channels(), path) || s.live == nil {
			refuse(w, http.StatusNotFound)
			return
		}
		live, err := s.live(path)
		if err != nil {
			refuse(w, http.StatusBadGateway)
			return
		}
		secureHeaders(w.Header())
		writeJSON(w, map[string]any{"live": live})
	})
}

// Channels lists the owners' fixed (Teevee) paths. Webcam shares aren't watchable in a browser: they're E2E.
func (g *Gate) Channels() []string {
	var c []string
	for p := range g.fixed {
		c = append(c, p)
	}
	slices.SortFunc(c, strings.Compare)
	return c
}
