package netcfg

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var Logf = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func run(name string, args ...string) error {
	Logf("[netcfg] %s %s", name, strings.Join(args, " "))

	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("netcfg: `%s %s` gagal: %w", name, strings.Join(args, " "), err)
		}
		return fmt.Errorf("netcfg: `%s %s` gagal: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return nil
}

func AddAddr(dev, cidr string) error {
	if err := validateCIDR(cidr); err != nil {
		return err
	}
	return run("ip", "addr", "add", cidr, "dev", dev)
}

func SetMTU(dev string, mtu int) error {
	if mtu <= 0 {
		return fmt.Errorf("netcfg: MTU harus positif, diterima %d", mtu)
	}
	return run("ip", "link", "set", "dev", dev, "mtu", strconv.Itoa(mtu))
}

func SetUp(dev string) error {
	return run("ip", "link", "set", "dev", dev, "up")
}

func AddRoute(dev, cidr string) error {
	if err := validateCIDR(cidr); err != nil {
		return err
	}
	return run("ip", "route", "add", cidr, "dev", dev)
}

func EnableIPForward() error {
	const path = "/proc/sys/net/ipv4/ip_forward"
	Logf("[netcfg] echo 1 > %s", path)
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("netcfg: gagal menyalakan ip_forward: %w", err)
	}
	return nil
}

func validateCIDR(cidr string) error {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("netcfg: %q bukan CIDR yang valid (contoh: 10.9.0.1/24)", cidr)
	}
	return nil
}
