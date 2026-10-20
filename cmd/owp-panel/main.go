// owp-panel serves the multi-admin web panel and talks to owp-agent.
//
//	owp-panel -config /etc/owp/panel.json         run
//	owp-panel -config ... reset-super             print a new super-admin password
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
	_ "time/tzdata" // OpenWrt usually ships without zoneinfo

	"github.com/wangsirco/wharf/internal/panel"
	"github.com/wangsirco/wharf/internal/tlsutil"
	"github.com/wangsirco/wharf/web"
)

// setLocalTimezone: OpenWrt keeps its zone in uci (system.@system[0].zonename) and has
// no /etc/localtime, so Go would default to UTC and hourly statistics would be shifted.
func setLocalTimezone() {
	if os.Getenv("TZ") != "" {
		return
	}
	if _, err := os.Stat("/etc/localtime"); err == nil {
		return
	}
	out, err := exec.Command("uci", "-q", "get", "system.@system[0].zonename").Output()
	if err != nil {
		return
	}
	if loc, err := time.LoadLocation(strings.ReplaceAll(strings.TrimSpace(string(out)), " ", "_")); err == nil {
		time.Local = loc
	}
}

func main() {
	setLocalTimezone()
	cfgPath := flag.String("config", "/etc/owp/panel.json", "config file")
	flag.Parse()

	cfg, err := panel.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config %s: %v", *cfgPath, err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	db, err := panel.OpenDB(cfg.Path("panel.db"))
	if err != nil {
		log.Fatal(err)
	}

	if flag.Arg(0) == "reset-super" {
		pw, err := panel.ResetSuper(db, cfg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(pw)
		return
	}
	if flag.Arg(0) == "setting" { // owp-panel setting <key> <value>  (root on the router only)
		if err := panel.SetSettingCLI(panel.NewApp(cfg, db, web.Dist()), flag.Arg(1), flag.Arg(2)); err != nil {
			log.Fatal(err)
		}
		fmt.Println("ok")
		return
	}
	if flag.Arg(0) == "monitor-export" {
		if err := panel.ExportMonitorsCLI(panel.NewApp(cfg, db, web.Dist()), os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
	if flag.Arg(0) == "monitor-add" {
		if err := panel.AddMonitorCLI(panel.NewApp(cfg, db, web.Dist()), flag.Args()[1:]); err != nil {
			log.Fatal(err)
		}
		fmt.Println("ok")
		return
	}
	if flag.Arg(0) == "reset-access" {
		if err := panel.ResetAccess(panel.NewApp(cfg, db, web.Dist())); err != nil {
			log.Fatal(err)
		}
		fmt.Println("ok")
		return
	}
	if err := panel.EnsureSuper(db, cfg); err != nil {
		log.Fatal(err)
	}

	app := panel.NewApp(cfg, db, web.Dist())
	app.Start()
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	switch cfg.TLS {
	case "off":
		log.Printf("owp-panel listening on http://%s (TLS off: only use behind a TLS reverse proxy)", cfg.Listen)
		log.Fatal(srv.ListenAndServe())
	case "files":
		log.Printf("owp-panel listening on https://%s", cfg.Listen)
		log.Fatal(srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile))
	default:
		ca, err := tlsutil.OpenLocalCA(cfg.Path("tls"), "Wharf")
		if err != nil {
			log.Fatal(err)
		}
		if err := ca.Refresh(certNames()); err != nil {
			log.Fatal(err)
		}
		go ca.Watch(certNames, log.Printf)
		app.CA = ca
		srv.TLSConfig = &tls.Config{GetCertificate: ca.GetCertificate, MinVersion: tls.VersionTLS12}
		ln, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			log.Fatal(err)
		}
		tlsLn, plainLn := tlsutil.SplitListener(ln)
		go func() {
			_ = (&http.Server{Handler: http.HandlerFunc(toHTTPS), ReadHeaderTimeout: 10 * time.Second}).Serve(plainLn)
		}()
		log.Printf("owp-panel listening on https://%s (local CA %s, sha256 %s; LAN %v)", cfg.Listen, ca.CAName(), ca.CAFingerprint(), tlsutil.LocalAddrs())
		log.Fatal(srv.Serve(tls.NewListener(tlsLn, srv.TLSConfig)))
	}
}

// toHTTPS answers plain-HTTP requests that hit the TLS port.
func toHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.Host == "" {
		http.Error(w, "use https", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
}

// certNames: <hostname>.<lan domain>, so https://router.lan:7080 is covered too.
func certNames() []string {
	domain := "lan"
	if out, err := exec.Command("uci", "-q", "get", "dhcp.@dnsmasq[0].domain").Output(); err == nil && strings.TrimSpace(string(out)) != "" {
		domain = strings.TrimSpace(string(out))
	}
	names := []string{domain}
	if h, err := os.Hostname(); err == nil && h != "" && !strings.ContainsAny(h, "_ ") {
		names = append(names, h+"."+domain)
	}
	return names
}
