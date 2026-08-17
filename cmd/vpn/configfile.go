package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

type entry struct {
	key   string
	value string
	line  int
}

func loadConfigFile(path string) ([]entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("gagal membaca konfigurasi: %w", err)
	}
	defer f.Close()

	var entries []entry
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return nil, fmt.Errorf("%s baris %d: format harus `kunci = nilai`", path, n)
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			return nil, fmt.Errorf("%s baris %d: nama opsi kosong", path, n)
		}
		entries = append(entries, entry{key: key, value: value, line: n})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("gagal membaca %s: %w", path, err)
	}
	return entries, nil
}

func applyConfigFile(fs *flag.FlagSet, path string) error {
	entries, err := loadConfigFile(path)
	if err != nil {
		return err
	}

	fromCLI := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { fromCLI[f.Name] = true })

	for _, e := range entries {
		if e.key == "config" {
			return fmt.Errorf("%s baris %d: opsi `config` tidak boleh dipakai di dalam berkas konfigurasi", path, e.line)
		}
		if fs.Lookup(e.key) == nil {
			return fmt.Errorf("%s baris %d: opsi %q tidak dikenal", path, e.line, e.key)
		}
		if fromCLI[e.key] {
			continue
		}
		if err := fs.Set(e.key, e.value); err != nil {
			return fmt.Errorf("%s baris %d: nilai %q untuk opsi %q tidak valid: %w", path, e.line, e.value, e.key, err)
		}
	}
	return nil
}
