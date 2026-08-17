package tun

import (
	"fmt"
	"runtime"
)

func Open(cfg Config) (Device, error) {
	return nil, fmt.Errorf("tun: TUN interface hanya didukung di Linux, sistem saat ini %s", runtime.GOOS)
}
