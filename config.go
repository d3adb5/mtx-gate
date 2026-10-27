package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Config is the gate's JSON config file. Passwords are files named after each user in PasswordsDir
// (the mounted mediamtx-auth secret), never part of this file.
type Config struct {
	API            string              `json:"api"`         // gate API and forwardAuth, behind Traefik
	Auth           string              `json:"auth"`        // MediaMTX authHTTPAddress listener
	ProxyListen    string              `json:"proxyListen"` // public RTSPS port
	ProxyTarget    string              `json:"proxyTarget"` // MediaMTX rtspsAddress (loopback)
	MTXAPI         string              `json:"mtxAPI"`      // MediaMTX API, for kicks
	PasswordsDir   string              `json:"passwordsDir"`
	Owners         map[string][]string `json:"owners"` // owner → fixed (Teevee) paths
	Admins         []string            `json:"admins"` // api and metrics only
	TrustedProxies []string            `json:"trustedProxies"`
	APICert        string              `json:"apiCert"` // local test relay only; production has Traefik's TLS
	APIKey         string              `json:"apiKey"`
}

func loadConfig(path string) (*Config, map[string]string, error) {
	c := &Config{
		API: ":9080", Auth: "127.0.0.1:9000", ProxyListen: ":8322", ProxyTarget: "127.0.0.1:18322",
		MTXAPI: "http://127.0.0.1:9997", PasswordsDir: "/etc/mtx-gate/passwords",
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	pw := map[string]string{}
	for _, u := range append(ownerNames(c), c.Admins...) {
		b, err := os.ReadFile(filepath.Join(c.PasswordsDir, u))
		if err != nil {
			return nil, nil, fmt.Errorf("no password for a configured user: %w", err)
		}
		p := strings.TrimRight(string(b), "\r\n")
		if len(p) < 16 {
			return nil, nil, fmt.Errorf("password of a configured user is shorter than 16 characters")
		}
		pw[u] = p
	}
	return c, pw, nil
}

func ownerNames(c *Config) []string {
	var n []string
	for u := range c.Owners {
		n = append(n, u)
	}
	return n
}

func parsePrefixes(s []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, v := range s {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
