package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sistervpn/internal/crypto"
	"sistervpn/internal/vpn"
)

const usage = `sister-b2-vpn — Layer 3 VPN point-to-point terenkripsi (UDP + TUN + AES-256-GCM)

Penggunaan:
  vpn genkey [-out FILE]
  vpn server -config FILE
  vpn client -config FILE

Contoh:
  # Sekali saja, lalu salin file key ke endpoint lawan lewat jalur aman
  vpn genkey -out secret.key

  # Endpoint A dan B
  sudo ./bin/vpn server -config configs/endpoint-a.conf
  sudo ./bin/vpn client -config configs/endpoint-b.conf

Seluruh opsi juga dapat diberikan langsung sebagai flag; flag command line
menimpa nilai yang ada di berkas konfigurasi.

Jalankan "vpn <subcommand> -h" untuk daftar opsi lengkap.
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "genkey":
		err = runGenkey(os.Args[2:])
	case "server":
		err = runTunnel(crypto.RoleServer, os.Args[2:])
	case "client":
		err = runTunnel(crypto.RoleClient, os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "subcommand tidak dikenal: %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func runGenkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	out := fs.String("out", "secret.key", "file tujuan penyimpanan key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	if err := crypto.SaveKeyFile(*out, key); err != nil {
		return err
	}

	fmt.Printf("key 256-bit tersimpan di %s (permission 0600)\n", *out)
	fmt.Printf("fingerprint: %s\n", crypto.Fingerprint(key))
	return nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func runTunnel(role crypto.Role, args []string) error {
	fs := flag.NewFlagSet(role.String(), flag.ExitOnError)

	defaultListen := "0.0.0.0:0"
	if role == crypto.RoleServer {
		defaultListen = fmt.Sprintf("0.0.0.0:%d", vpn.DefaultPort)
	}

	var (
		configPath = fs.String("config", "", "berkas konfigurasi `kunci = nilai`; ditimpa oleh flag command line")
		keyFile    = fs.String("key", "secret.key", "file berisi pre-shared key hex (buat dengan `vpn genkey`)")
		listen     = fs.String("listen", defaultListen, "alamat bind UDP (host:port)")
		peer       = fs.String("peer", "", "alamat UDP endpoint lawan (host:port); wajib untuk client")
		tunName    = fs.String("tun", "vpn0", "nama interface TUN")
		tunAddr    = fs.String("tun-addr", "", "alamat interface TUN dalam CIDR, mis. 10.9.0.1/24")
		mtu        = fs.Int("mtu", vpn.DefaultMTU, "MTU interface TUN")
		keepalive  = fs.Duration("keepalive", 15*time.Second, "interval keepalive (0 untuk mematikan)")
		statsIntv  = fs.Duration("stats", 0, "interval pencetakan statistik (0 untuk mematikan)")
		noConfig   = fs.Bool("no-configure", false, "jangan jalankan perintah ip; konfigurasi manual oleh operator")
		ipForward  = fs.Bool("ip-forward", false, "nyalakan net.ipv4.ip_forward (untuk meneruskan trafik LAN ke tunnel)")
		verbose    = fs.Bool("v", false, "log per-packet")
		routes     stringList
	)
	fs.Var(&routes, "route", "prefix yang diarahkan ke tunnel, boleh diulang (mis. -route 192.168.2.0/24)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Penggunaan: vpn %s [opsi]\n\nOpsi:\n", role)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *configPath != "" {
		if err := applyConfigFile(fs, *configPath); err != nil {
			return err
		}
		log.Printf("konfigurasi dimuat dari %s", *configPath)
	}

	key, warn, err := crypto.LoadKeyFile(*keyFile)
	if err != nil {
		return err
	}
	if warn != "" {
		log.Printf("peringatan: %s", warn)
	}
	log.Printf("pre-shared key dimuat dari %s (fingerprint %s)", *keyFile, crypto.Fingerprint(key))

	cfg := vpn.Config{
		Role:          role,
		Listen:        *listen,
		Peer:          *peer,
		TUNName:       *tunName,
		TUNAddr:       *tunAddr,
		MTU:           *mtu,
		Routes:        routes,
		Keepalive:     *keepalive,
		StatsInterval: *statsIntv,
		Configure:     !*noConfig,
		IPForward:     *ipForward,
		Verbose:       *verbose,
	}

	tunnel, err := vpn.New(cfg, key, log.Default())
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			log.Print("sinyal berhenti diterima, menutup tunnel")
		case <-finished:
		}
	}()

	runErr := tunnel.Run(ctx)
	close(finished)
	log.Print(tunnel.StatsLine())
	return runErr
}
