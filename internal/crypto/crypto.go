package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = 16
)

type Role int

const (
	RoleServer Role = iota
	RoleClient
)

func (r Role) String() string {
	switch r {
	case RoleServer:
		return "server"
	case RoleClient:
		return "client"
	default:
		return "unknown"
	}
}

var (
	labelC2S = []byte("sister-b2-vpn v1 data key client->server")
	labelS2C = []byte("sister-b2-vpn v1 data key server->client")
)

var ErrAuthFailed = errors.New("crypto: authentication failed")

type Cipher struct {
	send cipher.AEAD
	recv cipher.AEAD
}

func New(psk []byte, role Role) (*Cipher, error) {
	if len(psk) != KeySize {
		return nil, fmt.Errorf("crypto: panjang key harus %d byte, diterima %d", KeySize, len(psk))
	}

	c2s, err := newAEAD(deriveKey(psk, labelC2S))
	if err != nil {
		return nil, fmt.Errorf("crypto: gagal membuat AEAD client->server: %w", err)
	}
	s2c, err := newAEAD(deriveKey(psk, labelS2C))
	if err != nil {
		return nil, fmt.Errorf("crypto: gagal membuat AEAD server->client: %w", err)
	}

	switch role {
	case RoleServer:
		return &Cipher{send: s2c, recv: c2s}, nil
	case RoleClient:
		return &Cipher{send: c2s, recv: s2c}, nil
	default:
		return nil, fmt.Errorf("crypto: role tidak dikenal: %d", role)
	}
}

func (c *Cipher) Overhead() int { return c.send.Overhead() }

func (c *Cipher) Seal(dst, header, plaintext []byte, epoch uint32, counter uint64) []byte {
	nonce := makeNonce(epoch, counter)
	return c.send.Seal(dst, nonce[:], plaintext, header)
}

func (c *Cipher) Open(dst, header, ciphertext []byte, epoch uint32, counter uint64) ([]byte, error) {
	nonce := makeNonce(epoch, counter)
	out, err := c.recv.Open(dst, nonce[:], ciphertext, header)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return out, nil
}

func makeNonce(epoch uint32, counter uint64) [NonceSize]byte {
	var nonce [NonceSize]byte
	binary.BigEndian.PutUint32(nonce[0:4], epoch)
	binary.BigEndian.PutUint64(nonce[4:12], counter)
	return nonce
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func deriveKey(psk, info []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(info)
	mac.Write([]byte{0x01})
	return mac.Sum(nil)[:KeySize]
}
