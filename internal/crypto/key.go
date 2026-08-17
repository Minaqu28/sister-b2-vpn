package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

var ErrKeyFileEmpty = errors.New("crypto: file key kosong")

func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("crypto: gagal membaca entropy: %w", err)
	}
	return key, nil
}

func SaveKeyFile(path string, key []byte) error {
	if len(key) != KeySize {
		return fmt.Errorf("crypto: panjang key harus %d byte, diterima %d", KeySize, len(key))
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("crypto: %s sudah ada, hapus dulu bila memang ingin membuat key baru", path)
		}
		return fmt.Errorf("crypto: gagal membuat %s: %w", path, err)
	}
	defer f.Close()

	if _, err := f.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
		return fmt.Errorf("crypto: gagal menulis %s: %w", path, err)
	}
	return f.Close()
}

func LoadKeyFile(path string) (key []byte, warn string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", fmt.Errorf("crypto: gagal membaca file key %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, "", fmt.Errorf("crypto: %s adalah direktori, bukan file key", path)
	}

	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		warn = fmt.Sprintf("permission %s terlalu longgar (%04o), sebaiknya: chmod 600 %s",
			path, info.Mode().Perm(), path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, warn, fmt.Errorf("crypto: gagal membaca file key %s: %w", path, err)
	}

	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, warn, fmt.Errorf("crypto: %s: %w", path, ErrKeyFileEmpty)
	}

	key, err = hex.DecodeString(text)
	if err != nil {
		return nil, warn, fmt.Errorf("crypto: %s bukan hex yang valid (buat dengan `vpn genkey`)", path)
	}
	if len(key) != KeySize {
		return nil, warn, fmt.Errorf("crypto: panjang key pada %s harus %d byte, diterima %d", path, KeySize, len(key))
	}
	return key, warn, nil
}

func Fingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:4])
}
