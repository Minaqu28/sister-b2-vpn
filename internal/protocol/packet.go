package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Version    byte = 1
	HeaderSize      = 16
	TagSize         = 16
	Overhead        = HeaderSize + TagSize
	MaxPayload      = 65535
)

type Type byte

const (
	TypeData Type = 1
	TypeKeepalive Type = 2
)

func (t Type) String() string {
	switch t {
	case TypeData:
		return "DATA"
	case TypeKeepalive:
		return "KEEPALIVE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", byte(t))
	}
}

var (
	ErrShortPacket     = errors.New("protocol: packet terlalu pendek")
	ErrBadVersion      = errors.New("protocol: versi tidak dikenal")
	ErrBadType         = errors.New("protocol: tipe packet tidak dikenal")
	ErrBadLength       = errors.New("protocol: field length tidak konsisten")
	ErrBadCounter      = errors.New("protocol: counter tidak valid")
	ErrBufferTooSmall  = errors.New("protocol: buffer terlalu kecil")
	ErrPayloadTooLarge = errors.New("protocol: payload terlalu besar")
)

type Header struct {
	Version byte
	Type    Type
	Epoch   uint32
	Counter uint64
	Length  uint16
}

func (h Header) Encode(dst []byte) error {
	if len(dst) < HeaderSize {
		return fmt.Errorf("%w: butuh %d byte, tersedia %d", ErrBufferTooSmall, HeaderSize, len(dst))
	}
	dst[0] = h.Version
	dst[1] = byte(h.Type)
	binary.BigEndian.PutUint32(dst[2:6], h.Epoch)
	binary.BigEndian.PutUint64(dst[6:14], h.Counter)
	binary.BigEndian.PutUint16(dst[14:16], h.Length)
	return nil
}

func Parse(datagram []byte) (h Header, header, ciphertext []byte, err error) {
	if len(datagram) < HeaderSize+TagSize {
		return h, nil, nil, fmt.Errorf("%w: %d byte, minimum %d", ErrShortPacket, len(datagram), HeaderSize+TagSize)
	}

	h = Header{
		Version: datagram[0],
		Type:    Type(datagram[1]),
		Epoch:   binary.BigEndian.Uint32(datagram[2:6]),
		Counter: binary.BigEndian.Uint64(datagram[6:14]),
		Length:  binary.BigEndian.Uint16(datagram[14:16]),
	}

	if h.Version != Version {
		return h, nil, nil, fmt.Errorf("%w: %d", ErrBadVersion, h.Version)
	}
	if h.Type != TypeData && h.Type != TypeKeepalive {
		return h, nil, nil, fmt.Errorf("%w: %d", ErrBadType, byte(h.Type))
	}
	if h.Counter == 0 {
		return h, nil, nil, ErrBadCounter
	}

	want := HeaderSize + int(h.Length) + TagSize
	if len(datagram) != want {
		return h, nil, nil, fmt.Errorf("%w: length=%d berarti %d byte, diterima %d",
			ErrBadLength, h.Length, want, len(datagram))
	}

	return h, datagram[:HeaderSize], datagram[HeaderSize:], nil
}
