package tun

import "io"

type Config struct {
	Name string
	MTU  int
}

type Device interface {
	io.ReadWriteCloser
	Name() string
	MTU() int
}
