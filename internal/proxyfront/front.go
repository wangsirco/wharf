// Package proxyfront is the TLS front of the proxy extension (owp-agent proxy-front).
//
// WAN port 443 is redirected here. The front reads the TLS ClientHello without
// terminating it and routes by server name: a node's name goes, untouched, to that
// node's Xray inbound (with a PROXY protocol header so Xray sees the real client);
// anything else gets an ordinary-looking website. The same site is served in plain HTTP
// to Xray's fallbacks. For node and site domains the front obtains Let's Encrypt
// certificates itself (TLS-ALPN-01 on this very port) and exports them to certs/ for Xray.
package proxyfront

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/wangsirco/wharf/internal/tlsutil"
)

type Route struct {
	SNI         []string `json:"sni"`
	Backend     string   `json:"backend"` // host:port of the Xray inbound
	Proxy       bool     `json:"proxy"`   // send a PROXY protocol v2 header
	LANOnly     bool     `json:"lan_only"` // only for clients at home (private addresses); others fall through
	Transparent bool     `json:"-"`
}

type Site struct {
	Mode   string `json:"mode"`   // builtin | html | proxy
	Proxy  string `json:"proxy"`  // upstream URL for mode=proxy
	Title  string `json:"title"`  // builtin page title
	Domain string `json:"domain"` // the site's own name (served here even when a fallback takes the rest)
}

type Config struct {
	Dir        string   `json:"dir"`         // extension directory (certs/, acme/, site/)
	Listen     string   `json:"listen"`      // TLS entry, e.g. ":20443" (WAN 443 is redirected here)
	HTTPListen string   `json:"http_listen"` // plain HTTP site for Xray fallbacks, e.g. "127.0.0.1:20080"
	Routes     []Route  `json:"routes"`
	ACME       []string `json:"acme"`       // domains to get public certificates for
	ACMEEmail  string   `json:"acme_email"` //
	Site       Site     `json:"site"`
	// Fallback takes over a port forward that used to own WAN 443: everything that is
	// not for a node (or our own site domain) goes there unchanged instead of to the site.
	Fallback      string `json:"fallback"`       // host:port
	FallbackProxy bool   `json:"fallback_proxy"` // the server understands PROXY protocol v2
	// FallbackTransparent connects to the fallback from the visitor's own address
	// (IP_TRANSPARENT; the agent routes the replies back to this process), so that
	// server keeps seeing real visitors without any change on its side.
	FallbackTransparent bool `json:"fallback_transparent"`
	// User to run as. Started as root, the front drops to it at once and keeps only
	// CAP_NET_ADMIN (needed for transparent connects).
	User string `json:"user"`
}

type front struct {
	cfg    Config
	routes map[string]Route
	acme   *autocert.Manager
	self   tls.Certificate
	site   http.Handler
}

// Run serves until the process is stopped.
func Run(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	if cfg.User != "" && os.Geteuid() == 0 {
		if err := dropPrivileges(cfg.User); err != nil {
			return fmt.Errorf("drop privileges: %w", err)
		}
	}
	f := &front{cfg: cfg, routes: map[string]Route{}}
	for _, r := range cfg.Routes {
		for _, n := range r.SNI {
			f.routes[strings.ToLower(n)] = r
		}
	}
	certPEM, keyPEM, err := tlsutil.SelfSigned("localhost", "Wharf")
	if err != nil {
		return err
	}
	if f.self, err = tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return err
	}
	if len(cfg.ACME) > 0 {
		f.acme = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(filepath.Join(cfg.Dir, "acme")),
			HostPolicy: autocert.HostWhitelist(cfg.ACME...),
			Email:      cfg.ACMEEmail,
		}
		go f.exportLoop()
	}
	f.site = f.siteHandler()

	errc := make(chan error, 2)
	if cfg.HTTPListen != "" {
		srv := &http.Server{Addr: cfg.HTTPListen, Handler: f.site, ReadHeaderTimeout: 15 * time.Second}
		go func() { errc <- srv.ListenAndServe() }()
	}
	if cfg.Listen != "" {
		ln, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			return err
		}
		log.Printf("proxy front on %s: %d names routed, %d ACME domains", cfg.Listen, len(f.routes), len(cfg.ACME))
		go func() { errc <- f.serve(ln) }()
	}
	return <-errc
}

func (f *front) serve(ln net.Listener) error {
	var tempDelay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				tempDelay = max(5*time.Millisecond, min(2*tempDelay, time.Second))
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0
		go f.handle(c)
	}
}

// ---- ClientHello peeking ----

type peekConn struct {
	net.Conn
	r io.Reader
}

func (c *peekConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// readOnly lets crypto/tls parse a ClientHello without ever writing to the client.
type readOnly struct {
	r io.Reader
	net.Conn
}

func (c readOnly) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c readOnly) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }

var errPeeked = errors.New("peeked")

func peekHello(c net.Conn) (*tls.ClientHelloInfo, []byte, error) {
	var buf bytes.Buffer
	var hello *tls.ClientHelloInfo
	err := tls.Server(readOnly{r: io.TeeReader(c, &buf), Conn: c}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = &tls.ClientHelloInfo{ServerName: h.ServerName, SupportedProtos: h.SupportedProtos}
			return nil, errPeeked
		},
	}).Handshake()
	if hello == nil {
		return nil, buf.Bytes(), err
	}
	return hello, buf.Bytes(), nil
}

func (f *front) handle(c net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("front: %v", r)
			c.Close()
		}
	}()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	in := &peekConn{Conn: c, r: br}
	if first[0] != 0x16 { // not TLS: answer like a web server would
		_ = c.SetReadDeadline(time.Time{})
		if f.cfg.Fallback != "" {
			f.pipe(in, c, f.fallback())
			return
		}
		f.serveHTTP(in)
		return
	}
	hello, raw, err := peekHello(in)
	if hello == nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	replay := &peekConn{Conn: c, r: io.MultiReader(bytes.NewReader(raw), br)}
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))

	if f.acme != nil && slices.Contains(hello.SupportedProtos, "acme-tls/1") && slices.Contains(f.cfg.ACME, name) {
		tc := tls.Server(replay, f.acme.TLSConfig())
		_ = tc.Handshake()
		tc.Close()
		return
	}
	if r, ok := f.routes[name]; ok && (!r.LANOnly || privateClient(c.RemoteAddr())) {
		f.pipe(replay, c, r)
		return
	}
	if f.cfg.Fallback != "" && (f.cfg.Site.Domain == "" || name != f.cfg.Site.Domain) {
		f.pipe(replay, c, f.fallback())
		return
	}
	tc := tls.Server(replay, &tls.Config{
		GetCertificate: f.siteCert,
		NextProtos:     []string{"http/1.1"},
		MinVersion:     tls.VersionTLS12,
	})
	_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})
	f.serveHTTP(tc)
}

func (f *front) siteCert(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if f.acme != nil && h.ServerName != "" {
		if c, err := f.acme.GetCertificate(h); err == nil {
			return c, nil
		}
	}
	return &f.self, nil
}

func (f *front) fallback() Route {
	return Route{Backend: f.cfg.Fallback, Proxy: f.cfg.FallbackProxy, Transparent: f.cfg.FallbackTransparent}
}

var transparentOff sync.Once

// dial connects to a backend; a transparent route uses the client's public address as
// the source (LAN clients, and any failure, fall back to an ordinary connection).
func dial(r Route, client net.Addr) (net.Conn, error) {
	if ta, ok := client.(*net.TCPAddr); ok && r.Transparent {
		if ip, ok := netip.AddrFromSlice(ta.IP); ok && ip.Unmap().Is4() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			up, err := transparentDialer(ip.Unmap()).Dial("tcp", r.Backend)
			if err == nil {
				return up, nil
			}
			if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
				transparentOff.Do(func() {
					log.Printf("front: transparent connect not permitted (%v); visitors reach the server from the router's address", err)
				})
			} else if !errors.Is(err, syscall.EADDRNOTAVAIL) {
				return nil, err
			}
		}
	}
	return net.DialTimeout("tcp", r.Backend, 5*time.Second)
}

// pipe hands a connection to an Xray inbound unchanged (plus PROXY v2 if asked).
func (f *front) pipe(client net.Conn, raw net.Conn, r Route) {
	defer client.Close()
	up, err := dial(r, raw.RemoteAddr())
	if err != nil {
		return
	}
	defer up.Close()
	if r.Proxy {
		if _, err := up.Write(proxyV2(raw.RemoteAddr(), raw.LocalAddr())); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, client)
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(raw, up)
		if tc, ok := raw.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

var v2sig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

func privateClient(a net.Addr) bool {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	ip = ip.Unmap()
	return ok && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

// proxyV2 builds a PROXY protocol v2 header for a TCP connection.
func proxyV2(src, dst net.Addr) []byte {
	s, _ := src.(*net.TCPAddr)
	d, _ := dst.(*net.TCPAddr)
	var b bytes.Buffer
	b.Write(v2sig)
	b.WriteByte(0x21) // v2, PROXY
	if s == nil || d == nil {
		b.WriteByte(0x00)
		_ = binary.Write(&b, binary.BigEndian, uint16(0))
		return b.Bytes()
	}
	s4, d4 := s.IP.To4(), d.IP.To4()
	if s4 != nil && d4 != nil {
		b.WriteByte(0x11)
		_ = binary.Write(&b, binary.BigEndian, uint16(12))
		b.Write(s4)
		b.Write(d4)
	} else {
		b.WriteByte(0x21)
		_ = binary.Write(&b, binary.BigEndian, uint16(36))
		b.Write(s.IP.To16())
		b.Write(d.IP.To16())
	}
	_ = binary.Write(&b, binary.BigEndian, uint16(s.Port))
	_ = binary.Write(&b, binary.BigEndian, uint16(d.Port))
	return b.Bytes()
}

// ---- website ----

type oneConnListener struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.c })
	if c != nil {
		return &closeNotify{Conn: c, l: l}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.c.LocalAddr() }

type closeNotify struct {
	net.Conn
	l    *oneConnListener
	once sync.Once
}

func (c *closeNotify) Close() error {
	c.once.Do(func() { close(c.l.done) })
	return c.Conn.Close()
}

func (f *front) serveHTTP(c net.Conn) {
	l := &oneConnListener{c: c, done: make(chan struct{})}
	srv := &http.Server{Handler: f.site, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	_ = srv.Serve(l)
}

//go:embed site.html
var builtinPage string

var tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

func (f *front) siteHandler() http.Handler {
	siteDir := filepath.Join(f.cfg.Dir, "site")
	var upstream http.Handler
	if f.cfg.Site.Mode == "proxy" {
		if u, err := url.Parse(f.cfg.Site.Proxy); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			rp := httputil.NewSingleHostReverseProxy(u)
			base := rp.Director
			rp.Director = func(r *http.Request) {
				base(r)
				r.Host = u.Host
				r.Header.Del("X-Forwarded-For")
			}
			rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				w.WriteHeader(http.StatusBadGateway)
			}
			upstream = rp
		}
	}
	page := strings.ReplaceAll(builtinPage, "{{title}}", htmlEscape(firstNonEmpty(f.cfg.Site.Title, "Welcome")))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		if tok, ok := strings.CutPrefix(r.URL.Path, "/sub/"); ok {
			if !tokenRe.MatchString(tok) {
				http.NotFound(w, r)
				return
			}
			b, err := os.ReadFile(filepath.Join(siteDir, "subs", tok))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			if info, err := os.ReadFile(filepath.Join(siteDir, "subs", tok+".info")); err == nil {
				w.Header().Set("Subscription-Userinfo", strings.TrimSpace(string(info)))
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Profile-Update-Interval", "12")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(b)
			return
		}
		if upstream != nil {
			upstream.ServeHTTP(w, r)
			return
		}
		if f.cfg.Site.Mode == "html" {
			if b, err := os.ReadFile(filepath.Join(siteDir, "index.html")); err == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(b)
				return
			}
		}
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(404)
			_, _ = io.WriteString(w, "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>\n")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// ---- certificate export ----

// exportLoop obtains / renews certificates and writes them where Xray reads them.
func (f *front) exportLoop() {
	time.Sleep(5 * time.Second)
	for {
		failed := false
		for _, d := range f.cfg.ACME {
			c, err := f.acme.GetCertificate(&tls.ClientHelloInfo{
				ServerName:        d,
				CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				SupportedCurves:   []tls.CurveID{tls.CurveP256},
				SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
				SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
			})
			if err != nil {
				log.Printf("acme %s: %v", d, err)
				writeStatus(f.cfg.Dir, d, "error: "+err.Error())
				failed = true
				continue
			}
			if changed, err := exportCert(f.cfg.Dir, d, c); err != nil {
				log.Printf("export %s: %v", d, err)
			} else if changed {
				log.Printf("certificate for %s updated", d)
			}
			writeStatus(f.cfg.Dir, d, "ok "+c.Leaf.NotAfter.UTC().Format(time.RFC3339))
		}
		if failed {
			time.Sleep(10 * time.Minute)
		} else {
			time.Sleep(6 * time.Hour)
		}
	}
}

func writeStatus(dir, domain, s string) {
	_ = os.WriteFile(filepath.Join(dir, "certs", domain+".status"), []byte(s+"\n"), 0o644)
}

func exportCert(dir, domain string, c *tls.Certificate) (bool, error) {
	var chain bytes.Buffer
	for _, der := range c.Certificate {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	crt := filepath.Join(dir, "certs", domain+".crt")
	if old, err := os.ReadFile(crt); err == nil && bytes.Equal(old, chain.Bytes()) {
		return false, nil
	}
	var kb []byte
	var typ string
	switch k := c.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return false, err
		}
		kb, typ = b, "EC PRIVATE KEY"
	case *rsa.PrivateKey:
		kb, typ = x509.MarshalPKCS1PrivateKey(k), "RSA PRIVATE KEY"
	default:
		return false, errors.New("unsupported key type")
	}
	if err := writeFile(filepath.Join(dir, "certs", domain+".key"), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: kb}), 0o600); err != nil {
		return false, err
	}
	return true, writeFile(crt, chain.Bytes(), 0o644)
}

func writeFile(p string, b []byte, mode os.FileMode) error {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
