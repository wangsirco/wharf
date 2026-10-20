package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestLocalCAChain(t *testing.T) {
	dir := t.TempDir()
	ca, err := OpenLocalCA(dir, "Wharf")
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Refresh([]string{"lan", "router.lan", "example.com"}); err != nil {
		t.Fatal(err)
	}
	pair, _ := ca.GetCertificate(nil)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d > 825*24*time.Hour {
		t.Fatalf("leaf valid for %v: iOS rejects > 825 days", d)
	}
	for _, n := range leaf.DNSNames {
		if n == "example.com" {
			t.Fatal("public name must not be in the certificate")
		}
	}
	pool := x509.NewCertPool()
	root, _ := x509.ParseCertificate(ca.CADER())
	pool.AddCert(root)
	for _, host := range append([]string{"127.0.0.1", "localhost", "router.lan"}, LocalAddrs()...) {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: host}); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}

	// the CA cannot vouch for public names even if someone signs one with it
	evil := *leaf
	evil.DNSNames, evil.IPAddresses = []string{"www.google.com"}, []net.IP{net.ParseIP("8.8.8.8")}
	der, err := x509.CreateCertificate(nil, &evil, ca.ca, leaf.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	bad, _ := x509.ParseCertificate(der)
	if _, err := bad.Verify(x509.VerifyOptions{Roots: pool, DNSName: "www.google.com"}); err == nil {
		t.Fatal("name constraints not enforced")
	}

	// reopening reuses both the CA and the server certificate
	ca2, err := OpenLocalCA(dir, "Wharf")
	if err != nil || ca2.CAFingerprint() != ca.CAFingerprint() {
		t.Fatal("CA changed on reopen", err)
	}
	_ = ca2.Refresh(nil)
	p2, _ := ca2.GetCertificate(nil)
	if string(p2.Certificate[0]) != string(pair.Certificate[0]) {
		t.Fatal("server certificate re-issued without reason")
	}
}

func TestSplitListener(t *testing.T) {
	ca, _ := OpenLocalCA(t.TempDir(), "Wharf")
	_ = ca.Refresh(nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn, plainLn := SplitListener(ln)
	defer tlsLn.Close()
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "tls") })
	redir := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
	go (&http.Server{Handler: ok}).Serve(tls.NewListener(tlsLn, &tls.Config{GetCertificate: ca.GetCertificate}))
	go (&http.Server{Handler: redir}).Serve(plainLn)

	addr := ln.Addr().String()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get("http://" + addr + "/x?y=1")
	if err != nil {
		t.Fatal(err)
	}
	if loc := resp.Header.Get("Location"); resp.StatusCode != 301 || loc != "https://"+addr+"/x?y=1" {
		t.Fatalf("plain: %d %q", resp.StatusCode, loc)
	}
	pool := x509.NewCertPool()
	root, _ := x509.ParseCertificate(ca.CADER())
	pool.AddCert(root)
	tc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err = tc.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "tls" {
		t.Fatalf("tls body %q", b)
	}
}
