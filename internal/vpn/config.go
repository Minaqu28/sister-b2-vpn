package vpn

import (
	"fmt"
	"net"
	"strings"
	"time"

	"sistervpn/internal/crypto"
	"sistervpn/internal/protocol"
)

const (
	MinMTU = 576
	MaxMTU = 1500 - 20 - 8 - protocol.Overhead
	DefaultMTU  = 1400
	DefaultPort = 51820
)

type Config struct {
	Role   crypto.Role
	Listen string
	Peer    string
	TUNName string
	TUNAddr string
	MTU     int
	Routes []string
	Keepalive     time.Duration
	StatsInterval time.Duration
	Configure     bool
	IPForward     bool
	Verbose       bool
}

func (c *Config) Validate() error {
	if c.Role != crypto.RoleServer && c.Role != crypto.RoleClient {
		return fmt.Errorf("config: role tidak dikenal: %d", c.Role)
	}

	if c.Listen == "" {
		return fmt.Errorf("config: alamat listen wajib diisi")
	}
	if _, err := net.ResolveUDPAddr("udp4", c.Listen); err != nil {
		return fmt.Errorf("config: alamat listen %q tidak valid: %w", c.Listen, err)
	}

	if c.Peer != "" {
		addr, err := net.ResolveUDPAddr("udp4", c.Peer)
		if err != nil {
			return fmt.Errorf("config: alamat peer %q tidak valid: %w", c.Peer, err)
		}
		if addr.Port == 0 {
			return fmt.Errorf("config: alamat peer %q harus menyertakan port", c.Peer)
		}
	} else if c.Role == crypto.RoleClient {
		return fmt.Errorf("config: client wajib mengetahui alamat peer (-peer host:port)")
	}

	if c.TUNName == "" {
		return fmt.Errorf("config: nama interface TUN wajib diisi")
	}
	if strings.ContainsAny(c.TUNName, " /") {
		return fmt.Errorf("config: nama interface %q mengandung karakter tidak valid", c.TUNName)
	}

	if c.MTU < MinMTU || c.MTU > MaxMTU {
		return fmt.Errorf("config: MTU harus antara %d dan %d, diterima %d", MinMTU, MaxMTU, c.MTU)
	}

	if c.Configure {
		if c.TUNAddr == "" {
			return fmt.Errorf("config: alamat TUN wajib diisi (-tun-addr 10.9.0.1/24)")
		}
		if err := checkCIDRHost(c.TUNAddr); err != nil {
			return fmt.Errorf("config: -tun-addr: %w", err)
		}
		for _, r := range c.Routes {
			if _, _, err := net.ParseCIDR(r); err != nil {
				return fmt.Errorf("config: route %q bukan CIDR yang valid: %w", r, err)
			}
		}
	}

	if c.Keepalive < 0 {
		return fmt.Errorf("config: interval keepalive tidak boleh negatif")
	}
	if c.StatsInterval < 0 {
		return fmt.Errorf("config: interval statistik tidak boleh negatif")
	}

	return nil
}

func checkCIDRHost(s string) error {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("%q bukan CIDR yang valid (contoh: 10.9.0.1/24): %w", s, err)
	}
	if ip.To4() == nil {
		return fmt.Errorf("%q bukan alamat IPv4", s)
	}
	if ones, bits := ipnet.Mask.Size(); bits-ones >= 2 && ip.Equal(ipnet.IP) {
		return fmt.Errorf("%q adalah alamat network, gunakan alamat host di dalam subnet tersebut", s)
	}
	return nil
}
