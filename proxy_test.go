package main

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestProxyHeaderV4(t *testing.T) {
	h := proxyHeader(netip.MustParseAddrPort("203.0.113.10:40000"), netip.MustParseAddrPort("10.0.0.1:8322"))
	want := append(append([]byte{}, proxyV2Sig...), 0x21, 0x11, 0, 12, 203, 0, 113, 10, 10, 0, 0, 1, 0x9c, 0x40, 0x20, 0x82)
	if !bytes.Equal(h, want) {
		t.Fatalf("% x", h)
	}
	h6 := proxyHeader(netip.MustParseAddrPort("[2001:db8::1]:1"), netip.MustParseAddrPort("10.0.0.1:8322"))
	if len(h6) != 16+36 || h6[13] != 0x21 {
		t.Fatalf("mixed families become v6: % x", h6)
	}
}

func TestProxyResetsClosedAndForwardsOpen(t *testing.T) {
	s, g, _ := newTestServer(t, true)
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		b := make([]byte, 28+5)
		io.ReadFull(c, b)
		got <- b
		c.Write([]byte("pong"))
		c.Close()
	}()
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	go (&Proxy{g: g, srv: s, target: up.Addr().String()}).Serve(front)

	c, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("closed IP must be dropped")
	}
	c.Close()

	g.Open(netip.MustParseAddr("127.0.0.1"))
	if c, err = net.Dial("tcp", front.Addr().String()); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hello"))
	b := <-got
	if !bytes.Equal(b[:12], proxyV2Sig) || !bytes.Equal(b[16:20], []byte{127, 0, 0, 1}) || string(b[28:]) != "hello" {
		t.Fatalf("upstream got % x", b)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	r, _ := io.ReadAll(c)
	if string(r) != "pong" {
		t.Fatalf("reply %q", r)
	}
}
