package vpn

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"sistervpn/internal/crypto"
	"sistervpn/internal/netcfg"
	"sistervpn/internal/protocol"
	"sistervpn/internal/transport"
	"sistervpn/internal/tun"
)

type Tunnel struct {
	cfg    Config
	dev    tun.Device
	conn   *transport.Conn
	cipher *crypto.Cipher
	window *protocol.Window
	logger *log.Logger
	epoch   uint32
	counter atomic.Uint64
	stats stats
	closeOnce sync.Once
}

type stats struct {
	txPackets     atomic.Uint64
	txBytes       atomic.Uint64
	rxPackets     atomic.Uint64
	rxBytes       atomic.Uint64
	dropMalformed atomic.Uint64
	dropAuth      atomic.Uint64
	dropReplay    atomic.Uint64
	dropNoPeer    atomic.Uint64
	dropTUNWrite  atomic.Uint64
}

var ErrCounterExhausted = errors.New("vpn: counter packet habis, restart tunnel untuk mendapatkan epoch baru")

func New(cfg Config, psk []byte, logger *log.Logger) (*Tunnel, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	}

	cipher, err := crypto.New(psk, cfg.Role)
	if err != nil {
		return nil, err
	}

	epoch, err := randomEpoch()
	if err != nil {
		return nil, err
	}

	dev, err := tun.Open(tun.Config{Name: cfg.TUNName, MTU: cfg.MTU})
	if err != nil {
		return nil, err
	}

	t := &Tunnel{
		cfg:    cfg,
		dev:    dev,
		cipher: cipher,
		window: protocol.NewWindow(),
		logger: logger,
		epoch:  epoch,
	}

	if cfg.Configure {
		netcfg.Logf = func(format string, args ...any) { logger.Printf(format, args...) }
		if err := t.configureInterface(); err != nil {
			dev.Close()
			return nil, err
		}
	}

	conn, err := transport.Listen(cfg.Listen, cfg.Peer)
	if err != nil {
		dev.Close()
		return nil, err
	}
	t.conn = conn

	logger.Printf("tunnel siap: role=%s tun=%s mtu=%d udp=%s epoch=%08x",
		cfg.Role, dev.Name(), cfg.MTU, conn.LocalAddr(), epoch)
	if p := conn.Peer(); p != nil {
		logger.Printf("peer awal: %s", p)
	} else {
		logger.Printf("peer belum diketahui, menunggu packet sah pertama")
	}

	return t, nil
}

func (t *Tunnel) configureInterface() error {
	name := t.dev.Name()

	if err := netcfg.AddAddr(name, t.cfg.TUNAddr); err != nil {
		return err
	}
	if err := netcfg.SetMTU(name, t.cfg.MTU); err != nil {
		return err
	}
	if err := netcfg.SetUp(name); err != nil {
		return err
	}
	for _, r := range t.cfg.Routes {
		if err := netcfg.AddRoute(name, r); err != nil {
			return err
		}
	}
	if t.cfg.IPForward {
		if err := netcfg.EnableIPForward(); err != nil {
			return err
		}
	}
	return nil
}

func (t *Tunnel) Run(ctx context.Context) error {
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		stopOnce sync.Once
		runErr   error
	)

	stop := make(chan struct{})
	closeStop := func() { stopOnce.Do(func() { close(stop) }) }
	finish := func(err error) {
		if err != nil {
			errOnce.Do(func() { runErr = err })
		}
		closeStop()
		t.shutdown()
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		finish(t.outbound(stop))
	}()
	go func() {
		defer wg.Done()
		finish(t.inbound(stop))
	}()

	if t.cfg.Keepalive > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.keepaliveLoop(stop)
		}()
	}
	if t.cfg.StatsInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.statsLoop(stop)
		}()
	}
	go func() {
		select {
		case <-ctx.Done():
			closeStop()
			t.shutdown()
		case <-stop:
		}
	}()

	wg.Wait()
	return runErr
}

func (t *Tunnel) outbound(stop <-chan struct{}) error {
	readBuf := make([]byte, t.cfg.MTU+64)
	sendBuf := make([]byte, protocol.HeaderSize+t.cfg.MTU+64+protocol.TagSize)

	for {
		n, err := t.dev.Read(readBuf)
		if err != nil {
			if isClosed(err) || isStopped(stop) {
				return nil
			}
			return fmt.Errorf("outbound: %w", err)
		}
		if n == 0 {
			continue
		}

		packet, err := t.seal(sendBuf, protocol.TypeData, readBuf[:n])
		if err != nil {
			return fmt.Errorf("outbound: %w", err)
		}

		if err := t.conn.Send(packet); err != nil {
			if errors.Is(err, transport.ErrNoPeer) {
				t.stats.dropNoPeer.Add(1)
				continue
			}
			if isClosed(err) || isStopped(stop) {
				return nil
			}
			t.stats.dropNoPeer.Add(1)
			if t.cfg.Verbose {
				t.logger.Printf("outbound: %v", err)
			}
			continue
		}

		t.stats.txPackets.Add(1)
		t.stats.txBytes.Add(uint64(n))
		if t.cfg.Verbose {
			t.logger.Printf("tx  %-9s %4d byte plaintext -> %4d byte UDP  %s",
				protocol.TypeData, n, len(packet), describeIP(readBuf[:n]))
		}
	}
}

func (t *Tunnel) inbound(stop <-chan struct{}) error {
	recvBuf := make([]byte, transport.MaxDatagram)
	plainBuf := make([]byte, 0, t.cfg.MTU+128)

	for {
		n, from, err := t.conn.Receive(recvBuf)
		if err != nil {
			if isClosed(err) || isStopped(stop) {
				return nil
			}
			return fmt.Errorf("inbound: %w", err)
		}
		datagram := recvBuf[:n]
		header, headerBytes, ciphertext, err := protocol.Parse(datagram)
		if err != nil {
			t.stats.dropMalformed.Add(1)
			if t.cfg.Verbose {
				t.logger.Printf("drop packet dari %s: %v", from, err)
			}
			continue
		}
		plaintext, err := t.cipher.Open(plainBuf[:0], headerBytes, ciphertext, header.Epoch, header.Counter)
		if err != nil {
			t.stats.dropAuth.Add(1)
			t.logger.Printf("drop packet dari %s: autentikasi gagal (counter=%d)", from, header.Counter)
			continue
		}
		if err := t.window.Check(header.Epoch, header.Counter); err != nil {
			t.stats.dropReplay.Add(1)
			t.logger.Printf("drop packet dari %s: %v", from, err)
			continue
		}
		if t.conn.UpdatePeer(from) {
			t.logger.Printf("alamat peer diperbarui: %s (epoch=%08x)", from, header.Epoch)
		}

		t.stats.rxPackets.Add(1)
		t.stats.rxBytes.Add(uint64(len(plaintext)))

		if header.Type == protocol.TypeKeepalive {
			if t.cfg.Verbose {
				t.logger.Printf("rx  %-9s dari %s", protocol.TypeKeepalive, from)
			}
			continue
		}

		if len(plaintext) == 0 {
			t.stats.dropMalformed.Add(1)
			continue
		}

		if _, err := t.dev.Write(plaintext); err != nil {
			if isClosed(err) || isStopped(stop) {
				return nil
			}
			t.stats.dropTUNWrite.Add(1)
			t.logger.Printf("gagal menulis ke TUN: %v", err)
			continue
		}

		if t.cfg.Verbose {
			t.logger.Printf("rx  %-9s %4d byte UDP -> %4d byte plaintext  %s",
				protocol.TypeData, n, len(plaintext), describeIP(plaintext))
		}
	}
}

func (t *Tunnel) seal(buf []byte, typ protocol.Type, payload []byte) ([]byte, error) {
	if len(payload) > protocol.MaxPayload {
		return nil, fmt.Errorf("%w: %d byte", protocol.ErrPayloadTooLarge, len(payload))
	}
	if len(buf) < protocol.HeaderSize+len(payload)+protocol.TagSize {
		return nil, fmt.Errorf("%w: butuh %d byte", protocol.ErrBufferTooSmall,
			protocol.HeaderSize+len(payload)+protocol.TagSize)
	}

	counter := t.counter.Add(1)
	if counter == 0 {
		return nil, ErrCounterExhausted
	}

	header := protocol.Header{
		Version: protocol.Version,
		Type:    typ,
		Epoch:   t.epoch,
		Counter: counter,
		Length:  uint16(len(payload)),
	}
	headerBytes := buf[:protocol.HeaderSize]
	if err := header.Encode(headerBytes); err != nil {
		return nil, err
	}

	return t.cipher.Seal(headerBytes, headerBytes, payload, t.epoch, counter), nil
}

func (t *Tunnel) keepaliveLoop(stop <-chan struct{}) {
	buf := make([]byte, protocol.Overhead)

	send := func() {
		if t.conn.Peer() == nil {
			return
		}
		packet, err := t.seal(buf, protocol.TypeKeepalive, nil)
		if err != nil {
			t.logger.Printf("keepalive: %v", err)
			return
		}
		if err := t.conn.Send(packet); err != nil && !errors.Is(err, transport.ErrNoPeer) && !isClosed(err) {
			if t.cfg.Verbose {
				t.logger.Printf("keepalive: %v", err)
			}
		}
	}

	send()

	ticker := time.NewTicker(t.cfg.Keepalive)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			send()
		}
	}
}

func (t *Tunnel) statsLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(t.cfg.StatsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			t.logger.Print(t.StatsLine())
		}
	}
}

func (t *Tunnel) StatsLine() string {
	accepted, rejected, epochChanges := t.window.Stats()
	peer := "belum diketahui"
	if p := t.conn.Peer(); p != nil {
		peer = p.String()
	}
	return fmt.Sprintf(
		"stats: tx=%d packet/%d byte rx=%d packet/%d byte | drop: malformed=%d auth=%d replay=%d no-peer=%d tun-write=%d | window: ok=%d tolak=%d epoch-peer-berganti=%d | peer=%s",
		t.stats.txPackets.Load(), t.stats.txBytes.Load(),
		t.stats.rxPackets.Load(), t.stats.rxBytes.Load(),
		t.stats.dropMalformed.Load(), t.stats.dropAuth.Load(), t.stats.dropReplay.Load(),
		t.stats.dropNoPeer.Load(), t.stats.dropTUNWrite.Load(),
		accepted, rejected, epochChanges, peer,
	)
}

func (t *Tunnel) shutdown() {
	t.closeOnce.Do(func() {
		if err := t.dev.Close(); err != nil && !isClosed(err) {
			t.logger.Printf("gagal menutup TUN: %v", err)
		}
		if err := t.conn.Close(); err != nil && !isClosed(err) {
			t.logger.Printf("gagal menutup socket UDP: %v", err)
		}
	})
}

func (t *Tunnel) Close() error {
	t.shutdown()
	return nil
}

func randomEpoch() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("vpn: gagal membuat epoch acak: %w", err)
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed)
}

func isStopped(stop <-chan struct{}) bool {
	select {
	case <-stop:
		return true
	default:
		return false
	}
}

func describeIP(p []byte) string {
	if len(p) < 1 {
		return "?"
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return "IPv4 (terpotong)"
		}
		return fmt.Sprintf("IPv4 %s -> %s proto=%d",
			net.IP(p[12:16]), net.IP(p[16:20]), p[9])
	case 6:
		if len(p) < 40 {
			return "IPv6 (terpotong)"
		}
		return fmt.Sprintf("IPv6 %s -> %s next=%d",
			net.IP(p[8:24]), net.IP(p[24:40]), p[6])
	default:
		return "bukan IP"
	}
}
