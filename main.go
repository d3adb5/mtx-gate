// mtx-gate: login, ticket and IP gate in front of MediaMTX. See DESIGN.md.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"
)

func main() {
	cfgPath := flag.String("config", "/etc/mtx-gate/config.json", "config file")
	enforce := flag.Bool("enforce", false, "refuse; without it denials are only counted (GET /stats on the auth port)")
	flag.Parse()
	log.SetFlags(0)

	cfg, pass, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	trusted, err := parsePrefixes(cfg.TrustedProxies)
	if err != nil {
		log.Fatalf("trustedProxies: %v", err)
	}
	var mtx *MTX
	g := NewGate(cfg, pass, func(path, user string, ip netip.Addr) { go mtx.Kick(path, user, ip) })
	mtx = NewMTX(cfg.MTXAPI, g.internal)
	s := &Server{g: g, trusted: trusted, enforce: *enforce, counters: &Counters{}, failWait: time.Second,
		live: mtx.Live}

	go func() {
		for range time.Tick(5 * time.Second) {
			g.Sweep()
		}
	}()
	pl, err := net.Listen("tcp", cfg.ProxyListen)
	if err != nil {
		log.Fatal(err)
	}
	go func() { log.Fatal((&Proxy{g: g, srv: s, target: cfg.ProxyTarget}).Serve(pl)) }()
	go func() { log.Fatal(serve(cfg.Auth, s.AuthHandler())) }()
	log.Printf("mtx-gate up, enforce=%v", *enforce)
	log.Fatal(serveTLS(cfg.API, s.APIHandler(), cfg.APICert, cfg.APIKey))
}

func serve(addr string, h http.Handler) error { return serveTLS(addr, h, "", "") }

func serveTLS(addr string, h http.Handler, cert, key string) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
	if cert != "" {
		return srv.ListenAndServeTLS(cert, key)
	}
	return srv.ListenAndServe()
}
