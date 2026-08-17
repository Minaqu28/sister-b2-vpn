package tun

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	cloneDevice = "/dev/net/tun"
	iffTUN = 0x0001
	iffNoPI = 0x1000
	tunSetIff = 0x400454ca
	ifNameSize = 16
)

type ifreq struct {
	Name  [ifNameSize]byte
	Flags uint16
	_     [22]byte
}

type device struct {
	f    *os.File
	name string
	mtu  int
}

func Open(cfg Config) (Device, error) {
	if len(cfg.Name) >= ifNameSize {
		return nil, fmt.Errorf("tun: nama interface %q terlalu panjang (maksimum %d karakter)", cfg.Name, ifNameSize-1)
	}
	if cfg.MTU <= 0 {
		return nil, fmt.Errorf("tun: MTU harus positif, diterima %d", cfg.MTU)
	}

	fd, err := syscall.Open(cloneDevice, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, describeOpenError(err)
	}

	req := ifreq{Flags: iffTUN | iffNoPI}
	copy(req.Name[:], cfg.Name)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(tunSetIff),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		syscall.Close(fd)
		return nil, describeIoctlError(cfg.Name, errno)
	}

	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun: gagal mengatur mode non-blocking: %w", err)
	}
	f := os.NewFile(uintptr(fd), cloneDevice)

	name := string(bytes.TrimRight(req.Name[:], "\x00"))
	if name == "" {
		name = cfg.Name
	}

	return &device{f: f, name: name, mtu: cfg.MTU}, nil
}

func (d *device) Read(p []byte) (int, error) {
	n, err := d.f.Read(p)
	if err != nil {
		return n, fmt.Errorf("tun %s: gagal membaca: %w", d.name, err)
	}
	return n, nil
}

func (d *device) Write(p []byte) (int, error) {
	n, err := d.f.Write(p)
	if err != nil {
		return n, fmt.Errorf("tun %s: gagal menulis: %w", d.name, err)
	}
	return n, nil
}

func (d *device) Close() error { return d.f.Close() }

func (d *device) Name() string { return d.name }

func (d *device) MTU() int { return d.mtu }

func describeOpenError(err error) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("tun: %s tidak ada; muat modul kernel dengan `modprobe tun`: %w", cloneDevice, err)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("tun: tidak punya izin membuka %s; jalankan sebagai root atau beri CAP_NET_ADMIN: %w", cloneDevice, err)
	default:
		return fmt.Errorf("tun: gagal membuka %s: %w", cloneDevice, err)
	}
}

func describeIoctlError(name string, errno syscall.Errno) error {
	switch errno {
	case syscall.EPERM:
		return fmt.Errorf("tun: ioctl TUNSETIFF ditolak; butuh root atau CAP_NET_ADMIN: %w", errno)
	case syscall.EBUSY:
		return fmt.Errorf("tun: interface %q sedang dipakai proses lain: %w", name, errno)
	case syscall.EINVAL:
		return fmt.Errorf("tun: parameter TUNSETIFF tidak valid untuk interface %q: %w", name, errno)
	default:
		return fmt.Errorf("tun: ioctl TUNSETIFF gagal untuk interface %q: %w", name, errno)
	}
}
