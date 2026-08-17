package transport

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
)

const MaxDatagram = 65535
var ErrNoPeer = errors.New("transport: alamat peer belum diketahui")

type Conn struct {
	pc   *net.UDPConn
	peer atomic.Pointer[net.UDPAddr]
}

func Listen(bind, peer string) (*Conn, error) {
	laddr, err := net.ResolveUDPAddr("udp4", bind)
	if err != nil {
		return nil, fmt.Errorf("transport: alamat bind %q tidak valid: %w", bind, err)
	}

	pc, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, fmt.Errorf("transport: gagal bind UDP di %s: %w", bind, err)
	}

	c := &Conn{pc: pc}

	if peer != "" {
		raddr, err := net.ResolveUDPAddr("udp4", peer)
		if err != nil {
			pc.Close()
			return nil, fmt.Errorf("transport: alamat peer %q tidak valid: %w", peer, err)
		}
		if raddr.Port == 0 {
			pc.Close()
			return nil, fmt.Errorf("transport: alamat peer %q harus menyertakan port", peer)
		}
		c.peer.Store(raddr)
	}

	return c, nil
}

func (c *Conn) Send(b []byte) error {
	peer := c.peer.Load()
	if peer == nil {
		return ErrNoPeer
	}
	if _, err := c.pc.WriteToUDP(b, peer); err != nil {
		return fmt.Errorf("transport: gagal mengirim ke %s: %w", peer, err)
	}
	return nil
}

func (c *Conn) Receive(buf []byte) (int, *net.UDPAddr, error) {
	n, addr, err := c.pc.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}
	return n, addr, nil
}

func (c *Conn) Peer() *net.UDPAddr {
	return c.peer.Load()
}

func (c *Conn) UpdatePeer(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	cur := c.peer.Load()
	if cur != nil && cur.IP.Equal(addr.IP) && cur.Port == addr.Port {
		return false
	}
	next := &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
	c.peer.Store(next)
	return true
}

func (c *Conn) LocalAddr() net.Addr { return c.pc.LocalAddr() }

func (c *Conn) Close() error { return c.pc.Close() }
