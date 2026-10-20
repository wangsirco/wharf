package tlsutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Local CA for the panel's HTTPS.
//
// A bare self-signed certificate can never be trusted on iOS: it has to name the IP
// it is served on and be valid for at most 825 days, and phones refuse to bypass the
// warning inside a home-screen web app. So the panel keeps a private CA (installed
// once on each device) and issues itself short-lived server certificates for its
// current LAN addresses. The CA is name-constrained to private networks and .lan-style
// names, so even a trusted copy of it cannot be used to impersonate a public website.

var (
	privateNets = mustNets("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "fc00::/7", "::1/128")
	localZones  = []string{"lan", "local", "localhost", "home.arpa", "internal"}
)

func mustNets(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// PrivateIP reports whether ip is one the local CA may sign for.
func PrivateIP(ip net.IP) bool {
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func localName(name string) bool {
	for _, z := range localZones {
		if name == z || strings.HasSuffix(name, "."+z) {
			return true
		}
	}
	return false
}

// LocalCA issues the panel's server certificate and rotates it when the router's
// addresses change or it is about to expire.
type LocalCA struct {
	dir   string
	org   string
	ca    *x509.Certificate
	caDER []byte
	key   crypto.Signer

	mu   sync.RWMutex
	leaf *tls.Certificate
	ips  []string
	exp  time.Time
}

const leafDays = 397 // under every browser's limit for server certificates

// OpenLocalCA loads or creates ca.crt/ca.key in dir. org names the CA (shown when installing).
func OpenLocalCA(dir, org string) (*LocalCA, error) {
	c := &LocalCA{dir: dir, org: org}
	certFile, keyFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if _, err := os.Stat(certFile); err != nil {
		if err := c.create(certFile, keyFile); err != nil {
			return nil, err
		}
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	c.ca, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca key cannot sign")
	}
	c.key, c.caDER = signer, pair.Certificate[0]
	return c, nil
}

func (c *LocalCA) create(certFile, keyFile string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	suffix := make([]byte, 3)
	_, _ = rand.Read(suffix)
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: c.org + " 本地证书 " + hex.EncodeToString(suffix), Organization: []string{c.org}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		PermittedDNSDomains:   localZones,
		PermittedIPRanges:     privateNets,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	return writePair(certFile, keyFile, der, key)
}

func writePair(certFile, keyFile string, der []byte, key *ecdsa.PrivateKey) error {
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(certFile), 0o700)
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// CADER is the CA certificate to install on devices.
func (c *LocalCA) CADER() []byte { return c.caDER }

// CAFingerprint is the hex SHA-256 of the CA certificate.
func (c *LocalCA) CAFingerprint() string {
	h := sha256.Sum256(c.caDER)
	return hex.EncodeToString(h[:])
}

// CAName is the CA's common name, as devices list it after installing.
func (c *LocalCA) CAName() string { return c.ca.Subject.CommonName }

// LocalAddrs lists the router's private addresses (the ones a certificate can cover).
func LocalAddrs() []string {
	addrs, _ := net.InterfaceAddrs()
	var out []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLinkLocalUnicast() || !PrivateIP(n.IP) {
			continue
		}
		out = append(out, n.IP.String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Refresh (re)issues the server certificate when the addresses changed or it expires within 30 days.
func (c *LocalCA) Refresh(names []string) error {
	ips := LocalAddrs()
	c.mu.RLock()
	fresh := c.leaf != nil && slices.Equal(ips, c.ips) && time.Until(c.exp) > 30*24*time.Hour
	c.mu.RUnlock()
	if fresh {
		return nil
	}
	certFile, keyFile := filepath.Join(c.dir, "server.crt"), filepath.Join(c.dir, "server.key")
	if pair, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil && c.covers(leaf, ips) && time.Until(leaf.NotAfter) > 30*24*time.Hour {
			c.set(&pair, ips, leaf.NotAfter)
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	dns := []string{"localhost"}
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSuffix(n, ".")); localName(n) && !slices.Contains(dns, n) {
			dns = append(dns, n)
		}
	}
	var ipList []net.IP
	if !slices.Contains(ips, "127.0.0.1") {
		ipList = append(ipList, net.IPv4(127, 0, 0, 1))
	}
	for _, s := range ips {
		ipList = append(ipList, net.ParseIP(s))
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: c.org, Organization: []string{c.org}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafDays * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ipList,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.ca, &key.PublicKey, c.key)
	if err != nil {
		return err
	}
	if err := writePair(certFile, keyFile, der, key); err != nil {
		return err
	}
	pair := tls.Certificate{Certificate: [][]byte{der, c.caDER}, PrivateKey: key}
	c.set(&pair, ips, tpl.NotAfter)
	return nil
}

func (c *LocalCA) covers(leaf *x509.Certificate, ips []string) bool {
	if leaf.CheckSignatureFrom(c.ca) != nil {
		return false
	}
	for _, s := range ips {
		if !slices.ContainsFunc(leaf.IPAddresses, func(ip net.IP) bool { return ip.Equal(net.ParseIP(s)) }) {
			return false
		}
	}
	return true
}

func (c *LocalCA) set(pair *tls.Certificate, ips []string, exp time.Time) {
	if len(pair.Certificate) == 1 {
		pair.Certificate = append(pair.Certificate, c.caDER) // send the chain
	}
	c.mu.Lock()
	c.leaf, c.ips, c.exp = pair, ips, exp
	c.mu.Unlock()
}

// GetCertificate plugs into tls.Config.
func (c *LocalCA) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.leaf == nil {
		return nil, errors.New("no certificate yet")
	}
	return c.leaf, nil
}

// Watch re-checks the addresses every few minutes (DHCP / LAN IP changes).
func (c *LocalCA) Watch(names func() []string, logf func(string, ...any)) {
	for {
		time.Sleep(5 * time.Minute)
		if err := c.Refresh(names()); err != nil {
			logf("certificate refresh: %v", err)
		}
	}
}
