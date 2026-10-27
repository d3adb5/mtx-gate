package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"sync"
	"time"
)

const (
	openTTL      = 120 * time.Second // POST open / redeem; clients renew every 60 s
	connGrace    = 60 * time.Second  // an IP stays open this long after its last proxied connection
	shareTTL     = 90 * time.Second  // senders renew every 30 s
	redeemWindow = 60 * time.Second
	maxOpens     = 256
	maxShares    = 8 // per owner
	maxTickets   = 32
	internalUser = "mtx-gate"
)

var camPath = regexp.MustCompile(`^mcam/[0-9a-f]{32}$`)

var (
	errLimit     = errors.New("limit reached")
	errNotFound  = errors.New("not found")
	errForbidden = errors.New("forbidden")
	errExpired   = errors.New("redeem window over")
)

// AuthRequest is MediaMTX's authHTTPAddress payload.
type AuthRequest struct {
	IP       string `json:"ip"`
	User     string `json:"user"`
	Password string `json:"password"`
	Action   string `json:"action"`
	Path     string `json:"path"`
	Protocol string `json:"protocol"`
}

type open struct {
	until time.Time
	conns int
}

type share struct {
	owner   string
	until   time.Time
	pubIP   netip.Addr // last publish; its live RTSPS connections hold the share too
	tickets map[string]*ticket
}

type ticket struct {
	id, path string
	hash     [32]byte
	redeemBy time.Time
	user     string // owner login that redeemed it; "" until then
	ip       netip.Addr
}

// Kick ends MediaMTX sessions on path; user and ip narrow it when set.
type Kick func(path, user string, ip netip.Addr)

// Gate holds every decision. State is memory only: a restart drops all shares, tickets and open IPs.
type Gate struct {
	mu       sync.Mutex
	now      func() time.Time
	owners   map[string]map[string]bool // owner → fixed paths
	fixed    map[string]bool
	admins   map[string]bool
	pass     map[string]string
	internal string // MediaMTX API password for the gate's own kicks
	kick     Kick
	opens    map[netip.Addr]*open
	shares   map[string]*share
	tickets  map[string]*ticket
}

func NewGate(c *Config, pass map[string]string, kick Kick) *Gate {
	g := &Gate{
		now: time.Now, owners: map[string]map[string]bool{}, fixed: map[string]bool{}, admins: map[string]bool{},
		pass: pass, internal: randHex(32), kick: kick,
		opens: map[netip.Addr]*open{}, shares: map[string]*share{}, tickets: map[string]*ticket{},
	}
	for u, paths := range c.Owners {
		g.owners[u] = map[string]bool{}
		for _, p := range paths {
			g.owners[u][p] = true
			g.fixed[p] = true
		}
	}
	for _, a := range c.Admins {
		g.admins[a] = true
	}
	return g
}

func randHex(n int) string {
	b := make([]byte, n/2)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (g *Gate) login(user, pass string) bool {
	want, ok := g.pass[user]
	if !ok {
		want = "\x00 no such user, compared anyway"
	}
	return subtle.ConstantTimeCompare([]byte(pass), []byte(want)) == 1 && ok
}

// Owner checks an owner login (not an admin's).
func (g *Gate) Owner(user, pass string) bool {
	return g.owners[user] != nil && g.login(user, pass)
}

// key folds IPv6 privacy addresses into their /64.
func key(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.Addr()
	}
	return ip
}

func (g *Gate) isOpen(ip netip.Addr) bool {
	ip = key(ip)
	o := g.opens[ip]
	return o != nil && (o.conns > 0 || o.until.After(g.now()))
}

// IsOpen answers Traefik's forwardAuth and the RTSPS proxy.
func (g *Gate) IsOpen(ip netip.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.isOpen(ip)
}

func (g *Gate) openLocked(ip netip.Addr) error {
	ip = key(ip)
	o := g.opens[ip]
	if o == nil {
		if len(g.opens) >= maxOpens {
			return errLimit
		}
		o = &open{}
		g.opens[ip] = o
	}
	if u := g.now().Add(openTTL); u.After(o.until) {
		o.until = u
	}
	return nil
}

// Open opens ip for an owner who logged in from it.
func (g *Gate) Open(ip netip.Addr) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.openLocked(ip)
}

// ConnStart and ConnEnd count proxied RTSPS connections, which keep their IP open.
func (g *Gate) ConnStart(ip netip.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.isOpen(ip) {
		return false
	}
	g.opens[key(ip)].conns++
	return true
}

func (g *Gate) ConnEnd(ip netip.Addr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	o := g.opens[key(ip)]
	if o == nil {
		return
	}
	o.conns--
	if u := g.now().Add(connGrace); o.conns == 0 && u.After(o.until) {
		o.until = u
	}
}

// live: the sender renews, or its publish connection is still up.
func (g *Gate) live(s *share) bool {
	if s.until.After(g.now()) {
		return true
	}
	o := g.opens[s.pubIP]
	return s.pubIP.IsValid() && o != nil && o.conns > 0
}

// PutShare claims or renews a webcam path for owner and opens the owner's IP. created tells a sender whose share
// the gate forgot (restart, expiry) to mint fresh tickets for its viewers.
func (g *Gate) PutShare(owner, path string, ip netip.Addr) (created bool, err error) {
	if !camPath.MatchString(path) {
		return false, errNotFound
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.shares[path]
	if s != nil && s.owner != owner {
		return false, errForbidden
	}
	if s == nil {
		n := 0
		for _, o := range g.shares {
			if o.owner == owner {
				n++
			}
		}
		if n >= maxShares {
			return false, errLimit
		}
		s = &share{owner: owner, tickets: map[string]*ticket{}}
		g.shares[path] = s
		created = true
	}
	s.until = g.now().Add(shareTTL)
	return created, g.openLocked(ip)
}

func (g *Gate) ownShare(owner, path string) (*share, error) {
	s := g.shares[path]
	if s == nil {
		return nil, errNotFound
	}
	if s.owner != owner {
		return nil, errForbidden
	}
	return s, nil
}

// DeleteShare ends a share and every session on it.
func (g *Gate) DeleteShare(owner, path string) error {
	g.mu.Lock()
	s, err := g.ownShare(owner, path)
	if err == nil {
		g.dropShareLocked(path, s)
	}
	g.mu.Unlock()
	if err == nil {
		g.kick(path, "", netip.Addr{})
	}
	return err
}

func (g *Gate) dropShareLocked(path string, s *share) {
	for id := range s.tickets {
		delete(g.tickets, id)
	}
	delete(g.shares, path)
}

// NewTicket returns a ticket id and its secret; the secret is kept only as a hash. The window bounds only the
// first redeem: after that the ticket lives as long as its share.
func (g *Gate) NewTicket(owner, path string) (id, secret string, redeemBy time.Time, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, err := g.ownShare(owner, path)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if len(s.tickets) >= maxTickets {
		return "", "", time.Time{}, errLimit
	}
	id, secret = randHex(16), randHex(32)
	t := &ticket{id: id, path: path, hash: sha256.Sum256([]byte(secret)), redeemBy: g.now().Add(redeemWindow)}
	s.tickets[id] = t
	g.tickets[id] = t
	return id, secret, t.redeemBy, nil
}

// DeleteTicket revokes one viewer and ends their sessions on the share.
func (g *Gate) DeleteTicket(owner, path, id string) error {
	g.mu.Lock()
	s, err := g.ownShare(owner, path)
	var t *ticket
	if err == nil {
		if t = s.tickets[id]; t == nil {
			err = errNotFound
		} else {
			delete(s.tickets, id)
			delete(g.tickets, id)
		}
	}
	g.mu.Unlock()
	if err == nil && t.user != "" {
		g.kick(path, t.user, netip.Addr{})
	}
	return err
}

// Redeem binds a ticket to the viewer's login and IP, and opens the IP. Redeeming again from another IP moves it.
func (g *Gate) Redeem(user string, ip netip.Addr, id, secret string) error {
	ip = key(ip)
	g.mu.Lock()
	t := g.tickets[id]
	h := sha256.Sum256([]byte(secret))
	switch {
	case t == nil || subtle.ConstantTimeCompare(h[:], t.hash[:]) != 1:
		g.mu.Unlock()
		return errNotFound
	case t.user == "" && g.now().After(t.redeemBy):
		g.mu.Unlock()
		return errExpired
	case t.user != "" && t.user != user:
		g.mu.Unlock()
		return errForbidden
	}
	if err := g.openLocked(ip); err != nil {
		g.mu.Unlock()
		return err
	}
	old := t.ip
	t.user, t.ip = user, ip
	g.mu.Unlock()
	if old.IsValid() && old != ip {
		g.kick(t.path, user, old)
	}
	return nil
}

// Authorize decides one MediaMTX action.
func (g *Gate) Authorize(r *AuthRequest) bool {
	ip, err := netip.ParseAddr(r.IP)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	switch r.Action {
	case "api", "metrics":
		if r.User == internalUser {
			return r.Action == "api" && ip.IsLoopback() &&
				subtle.ConstantTimeCompare([]byte(r.Password), []byte(g.internal)) == 1
		}
		return g.admins[r.User] && g.login(r.User, r.Password)
	case "publish", "read":
	default:
		return false
	}
	if !g.Owner(r.User, r.Password) {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.isOpen(ip) {
		return false
	}
	if r.Action == "publish" {
		if g.owners[r.User][r.Path] {
			return true
		}
		s := g.shares[r.Path]
		if s == nil || s.owner != r.User || !g.live(s) {
			return false
		}
		s.pubIP = key(ip)
		return true
	}
	if g.fixed[r.Path] {
		return true
	}
	s := g.shares[r.Path]
	if s == nil || !g.live(s) {
		return false
	}
	for _, t := range s.tickets {
		if t.user == r.User && t.ip == key(ip) {
			return true
		}
	}
	return false
}

// Sweep drops what expired and ends the sessions that depended on it.
func (g *Gate) Sweep() {
	now := g.now()
	var paths []string
	g.mu.Lock()
	for p, s := range g.shares {
		if !g.live(s) {
			g.dropShareLocked(p, s)
			paths = append(paths, p)
			continue
		}
		for id, t := range s.tickets {
			if t.user == "" && now.After(t.redeemBy) {
				delete(s.tickets, id)
				delete(g.tickets, id)
			}
		}
	}
	for ip, o := range g.opens {
		if o.conns == 0 && !o.until.After(now) {
			delete(g.opens, ip) // never kicks: a lapsed IP only stops new sessions
		}
	}
	g.mu.Unlock()
	for _, p := range paths {
		g.kick(p, "", netip.Addr{})
	}
}
