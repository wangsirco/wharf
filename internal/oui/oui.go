// Package oui maps MAC address prefixes (IEEE OUI, from Wireshark's manuf file)
// to vendor names.
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

const Source = "https://www.wireshark.org/download/automated/data/manuf"

//go:embed data/oui.txt.gz
var embedded []byte

var (
	once sync.Once
	db   map[string]string
)

func load() {
	db = map[string]string{}
	zr, err := gzip.NewReader(bytes.NewReader(embedded))
	if err != nil {
		return
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "\t")
		if ok {
			db[k] = v
		}
	}
}

// Vendor returns the vendor for a MAC ("" if unknown or locally administered).
func Vendor(mac string) string {
	once.Do(load)
	h := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	if len(h) < 6 {
		return ""
	}
	return db[h[:6]]
}

// Random reports whether a MAC is locally administered (randomised "private" address).
func Random(mac string) bool {
	h := strings.NewReplacer(":", "", "-", "").Replace(mac)
	if len(h) < 2 {
		return false
	}
	var b byte
	for _, c := range []byte(strings.ToLower(h[:2])) {
		b <<= 4
		switch {
		case c >= '0' && c <= '9':
			b |= c - '0'
		case c >= 'a' && c <= 'f':
			b |= c - 'a' + 10
		}
	}
	return b&0x02 != 0
}

var suffixRe = regexp.MustCompile(`(?i)[,.]?\s+(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|gmbh|ag|s\.?a|b\.?v|plc|pte|pty|technology|technologies|electronics|communication|communications|international|holdings?)\.?$`)

func shorten(name string) string {
	name = strings.TrimSpace(name)
	for i := 0; i < 4; i++ {
		n := strings.TrimSpace(strings.TrimRight(suffixRe.ReplaceAllString(name, ""), ",."))
		if n == name || n == "" {
			break
		}
		name = n
	}
	if r := []rune(name); len(r) > 28 {
		name = string(r[:28])
	}
	return name
}

// Build downloads the manuf file and returns "AABBCC\tVendor" lines (24-bit OUIs).
func Build(client *http.Client) ([]byte, error) {
	resp, err := client.Get(Source)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 32<<20))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		prefix := strings.TrimSpace(f[0])
		if len(prefix) != 8 { // only plain 24-bit OUIs
			continue
		}
		name := strings.TrimSpace(f[len(f)-1])
		if len(f) < 3 {
			name = strings.TrimSpace(f[1])
		}
		out.WriteString(strings.ReplaceAll(prefix, ":", "") + "\t" + shorten(name) + "\n")
	}
	return out.Bytes(), sc.Err()
}
