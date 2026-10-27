package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

var proxyV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

// proxyHeader is a PROXY protocol v2 header (PROXY command, TCP) for src → dst.
func proxyHeader(src, dst netip.AddrPort) []byte {
	s, d := src.Addr().Unmap(), dst.Addr().Unmap()
	if s.Is4() != d.Is4() {
		d = netip.IPv6Unspecified()
		s = netip.AddrFrom16(s.As16())
	}
	h := append([]byte{}, proxyV2Sig...)
	if s.Is4() {
		h = append(h, 0x21, 0x11, 0, 12)
	} else {
		h = append(h, 0x21, 0x21, 0, 36)
	}
	h = append(h, s.AsSlice()...)
	h = append(h, d.AsSlice()...)
	h = binary.BigEndian.AppendUint16(h, src.Port())
	h = binary.BigEndian.AppendUint16(h, dst.Port())
	return h
}

// Proxy forwards RTSPS from open IPs to MediaMTX. Any other IP gets a reset before TLS.
type Proxy struct {
	g      *Gate
	srv    *Server
	target string
}

func (p *Proxy) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go p.handle(c)
	}
}

func (p *Proxy) handle(c net.Conn) {
	src, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		c.Close()
		return
	}
	counted := p.g.ConnStart(src.Addr())
	if !p.srv.decide(counted) {
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		c.Close()
		return
	}
	if counted {
		defer p.g.ConnEnd(src.Addr())
	}
	up, err := net.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		c.Close()
		return
	}
	dst, _ := netip.ParseAddrPort(c.LocalAddr().String())
	if _, err := up.Write(proxyHeader(src, dst)); err != nil {
		up.Close()
		c.Close()
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(a, b net.Conn) {
		defer wg.Done()
		io.Copy(a, b)
		if tc, ok := a.(*net.TCPConn); ok {
			tc.CloseWrite()
		} else {
			a.Close()
		}
	}
	go pipe(up, c)
	go pipe(c, up)
	wg.Wait()
	up.Close()
	c.Close()
}
