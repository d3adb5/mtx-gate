package main

import (
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	pwB = "beaver-password-0123"
	pwE = "eevee-password-01234"
	pwA = "admin-password-01234"
)

type kickLog struct {
	mu    sync.Mutex
	calls []string
}

func (k *kickLog) kick(path, user string, ip netip.Addr) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := ""
	if ip.IsValid() {
		s = ip.String()
	}
	k.calls = append(k.calls, path+"|"+user+"|"+s)
}

func (k *kickLog) take() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	c := k.calls
	k.calls = nil
	return c
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestGate(t *testing.T) (*Gate, *clock, *kickLog) {
	t.Helper()
	cfg := &Config{
		Owners: map[string][]string{"beaver": {"beaver", "beaver-phone"}, "eevee": {"eevee"}},
		Admins: []string{"admin"},
	}
	k := &kickLog{}
	g := NewGate(cfg, map[string]string{"beaver": pwB, "eevee": pwE, "admin": pwA}, k.kick)
	c := &clock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	g.now = c.now
	return g, c, k
}

var (
	ipB      = netip.MustParseAddr("203.0.113.10")
	ipE      = netip.MustParseAddr("198.51.100.20")
	ipX      = netip.MustParseAddr("192.0.2.99")
	camShare = "mcam/" + strings.Repeat("ab", 16)
)

func put(g *Gate, owner, path string) error {
	_, err := g.PutShare(owner, path, ipB)
	return err
}

func req(user, pass, action, path string, ip netip.Addr) *AuthRequest {
	return &AuthRequest{IP: ip.String(), User: user, Password: pass, Action: action, Path: path, Protocol: "rtsp"}
}

func TestClosedIPRefusesEvenValidLogins(t *testing.T) {
	g, _, _ := newTestGate(t)
	if g.Authorize(req("beaver", pwB, "publish", "beaver", ipB)) {
		t.Fatal("publish from a closed IP")
	}
	g.Open(ipB)
	if !g.Authorize(req("beaver", pwB, "publish", "beaver", ipB)) {
		t.Fatal("publish to own fixed path from an open IP")
	}
	if g.Authorize(req("beaver", pwB, "publish", "eevee", ipB)) {
		t.Fatal("publish to another owner's path")
	}
	if g.Authorize(req("beaver", "wrong", "read", "eevee", ipB)) {
		t.Fatal("bad password")
	}
	if !g.Authorize(req("beaver", pwB, "read", "eevee", ipB)) {
		t.Fatal("owners read each other's fixed paths from an open IP")
	}
	if g.Authorize(req("admin", pwA, "read", "eevee", ipB)) {
		t.Fatal("admin is api/metrics only")
	}
	if g.Authorize(req("", "", "read", camShare, ipB)) {
		t.Fatal("anonymous read")
	}
}

func TestOpenExpiresUnlessConnected(t *testing.T) {
	g, c, _ := newTestGate(t)
	g.Open(ipB)
	c.add(openTTL + time.Second)
	if g.IsOpen(ipB) {
		t.Fatal("open outlived its TTL")
	}
	g.Open(ipB)
	if !g.ConnStart(ipB) {
		t.Fatal("conn from an open IP")
	}
	c.add(10 * openTTL)
	if !g.IsOpen(ipB) {
		t.Fatal("a live connection keeps the IP open")
	}
	g.ConnEnd(ipB)
	c.add(connGrace - time.Second)
	if !g.IsOpen(ipB) {
		t.Fatal("grace after the last connection")
	}
	c.add(2 * time.Second)
	if g.IsOpen(ipB) || g.ConnStart(ipB) {
		t.Fatal("closed after the grace")
	}
}

func TestIPv6FoldsIntoSlash64(t *testing.T) {
	g, _, _ := newTestGate(t)
	g.Open(netip.MustParseAddr("2001:db8:1:2::aaaa"))
	if !g.IsOpen(netip.MustParseAddr("2001:db8:1:2:ffff::1")) {
		t.Fatal("same /64")
	}
	if g.IsOpen(netip.MustParseAddr("2001:db8:1:3::aaaa")) {
		t.Fatal("other /64")
	}
}

func TestWebcamShareNeedsTicketAndLogin(t *testing.T) {
	g, _, k := newTestGate(t)
	g.Open(ipB)
	if g.Authorize(req("beaver", pwB, "publish", camShare, ipB)) {
		t.Fatal("publish to an unclaimed share path")
	}
	if err := put(g, "beaver", camShare); err != nil {
		t.Fatal(err)
	}
	if !g.Authorize(req("beaver", pwB, "publish", camShare, ipB)) {
		t.Fatal("owner publishes the claimed share")
	}
	if put(g, "eevee", camShare) != errForbidden {
		t.Fatal("another owner claims the path")
	}
	g.Open(ipE)
	if g.Authorize(req("eevee", pwE, "read", camShare, ipE)) {
		t.Fatal("login without a ticket")
	}
	id, secret, _, err := g.NewTicket("beaver", camShare)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := g.NewTicket("eevee", camShare); err != errForbidden {
		t.Fatal("tickets only from the share's owner")
	}
	if g.Redeem("eevee", ipE, id, "00"+secret[2:]) == nil {
		t.Fatal("wrong secret")
	}
	if err := g.Redeem("eevee", ipX, id, secret); err != nil {
		t.Fatal(err)
	}
	if !g.IsOpen(ipX) {
		t.Fatal("redeem opens the viewer's IP")
	}
	if !g.Authorize(req("eevee", pwE, "read", camShare, ipX)) {
		t.Fatal("redeemed ticket + login + IP")
	}
	if g.Authorize(req("eevee", pwE, "read", camShare, ipE)) {
		t.Fatal("ticket is bound to the redeeming IP")
	}
	if g.Authorize(req("beaver", pwB, "read", camShare, ipX)) {
		t.Fatal("ticket is bound to the redeeming login")
	}
	if g.Redeem("beaver", ipX, id, secret) != errForbidden {
		t.Fatal("another login redeems a bound ticket")
	}
	// Moving networks: the binding follows, the old IP's sessions are kicked.
	if err := g.Redeem("eevee", ipE, id, secret); err != nil {
		t.Fatal(err)
	}
	if got := k.take(); len(got) != 1 || got[0] != camShare+"|eevee|"+ipX.String() {
		t.Fatalf("kick on move: %v", got)
	}
	if g.Authorize(req("eevee", pwE, "read", camShare, ipX)) || !g.Authorize(req("eevee", pwE, "read", camShare, ipE)) {
		t.Fatal("binding moved")
	}
	if err := g.DeleteTicket("beaver", camShare, id); err != nil {
		t.Fatal(err)
	}
	if got := k.take(); len(got) != 1 || got[0] != camShare+"|eevee|" {
		t.Fatalf("kick on revoke: %v", got)
	}
	if g.Authorize(req("eevee", pwE, "read", camShare, ipE)) {
		t.Fatal("revoked")
	}
}

func TestTicketRedeemWindowAndShareExpiry(t *testing.T) {
	g, c, k := newTestGate(t)
	put(g, "beaver", camShare)
	id, secret, _, _ := g.NewTicket("beaver", camShare)
	c.add(redeemWindow + time.Second)
	if g.Redeem("eevee", ipE, id, secret) != errExpired {
		t.Fatal("redeemed after its window")
	}
	put(g, "beaver", camShare)
	id, secret, _, _ = g.NewTicket("beaver", camShare)
	g.Redeem("eevee", ipE, id, secret)
	c.add(shareTTL + time.Second)
	if g.Authorize(req("eevee", pwE, "read", camShare, ipE)) {
		t.Fatal("read on an expired share")
	}
	g.Sweep()
	if got := k.take(); len(got) != 1 || got[0] != camShare+"||" {
		t.Fatalf("expired share kicks its sessions: %v", got)
	}
	if g.Redeem("eevee", ipE, id, secret) == nil {
		t.Fatal("tickets go with their share")
	}
}

func TestSweepNeverKicksLapsedIPs(t *testing.T) {
	g, c, k := newTestGate(t)
	g.Open(ipB)
	c.add(openTTL + time.Second)
	g.Sweep()
	if got := k.take(); len(got) != 0 {
		t.Fatalf("lapsed IP kicked sessions: %v", got)
	}
}

func TestDeleteShareKicksAndLimits(t *testing.T) {
	g, _, k := newTestGate(t)
	if put(g, "beaver", "beaver") != errNotFound || put(g, "beaver", "mcam/ABC") != errNotFound {
		t.Fatal("only mcam/<32 hex> shares")
	}
	put(g, "beaver", camShare)
	if g.DeleteShare("eevee", camShare) != errForbidden {
		t.Fatal("delete by another owner")
	}
	g.DeleteShare("beaver", camShare)
	if got := k.take(); len(got) != 1 || got[0] != camShare+"||" {
		t.Fatalf("delete kicks: %v", got)
	}
	for i := 0; i < maxShares; i++ {
		if err := put(g, "beaver", "mcam/"+randHex(32)); err != nil {
			t.Fatal(err)
		}
	}
	if put(g, "beaver", "mcam/"+randHex(32)) != errLimit {
		t.Fatal("share limit")
	}
}

func TestAPIActions(t *testing.T) {
	g, _, _ := newTestGate(t)
	lo := netip.MustParseAddr("127.0.0.1")
	if !g.Authorize(req("admin", pwA, "api", "", ipX)) || g.Authorize(req("beaver", pwB, "api", "", ipB)) {
		t.Fatal("api is the admin's")
	}
	if !g.Authorize(req(internalUser, g.internal, "api", "", lo)) {
		t.Fatal("internal kick login from loopback")
	}
	if g.Authorize(req(internalUser, g.internal, "api", "", ipX)) || g.Authorize(req(internalUser, g.internal, "metrics", "", lo)) {
		t.Fatal("internal login is loopback api only")
	}
	if g.Authorize(req("admin", pwA, "playback", "beaver", ipX)) {
		t.Fatal("other actions refused")
	}
}

func TestPutShareCreatedOpensAndLivePublisherHolds(t *testing.T) {
	g, c, k := newTestGate(t)
	if created, _ := g.PutShare("beaver", camShare, ipB); !created || !g.IsOpen(ipB) {
		t.Fatal("first PUT creates and opens the sender's IP")
	}
	if created, _ := g.PutShare("beaver", camShare, ipB); created {
		t.Fatal("renewal is not a creation")
	}
	if !g.Authorize(req("beaver", pwB, "publish", camShare, ipB)) || !g.ConnStart(ipB) {
		t.Fatal("publish")
	}
	id, secret, _, _ := g.NewTicket("beaver", camShare)
	g.Redeem("eevee", ipE, id, secret)
	g.ConnStart(ipE)
	c.add(5 * shareTTL) // renewals missed during a handover
	g.Sweep()
	if len(k.take()) != 0 || !g.Authorize(req("eevee", pwE, "read", camShare, ipE)) {
		t.Fatal("a live publish connection holds the share")
	}
	// A ticket keeps working after its first-redeem window, e.g. from a new network.
	if err := g.Redeem("eevee", ipX, id, secret); err != nil {
		t.Fatal(err)
	}
	g.ConnEnd(ipB)
	c.add(connGrace + time.Second)
	g.Sweep()
	if got := k.take(); len(got) != 2 || got[1] != camShare+"||" {
		t.Fatalf("share ends once the publisher is gone: %v", got)
	}
	if created, _ := g.PutShare("beaver", camShare, ipB); !created {
		t.Fatal("a forgotten share is created again")
	}
}
