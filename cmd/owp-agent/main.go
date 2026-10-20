// owp-agent runs on the OpenWrt router and exposes a signed API to owp-panel.
//
// Config is read from uci (owp.agent.*); flags override it.
//
//	owp-agent                 run the agent
//	owp-agent genkey          print a new key id + secret
//	owp-agent fingerprint     print the TLS certificate fingerprint
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/wangsirco/wharf/internal/agent"
	"github.com/wangsirco/wharf/internal/sign"
	"github.com/wangsirco/wharf/internal/tlsutil"
)

func uci(key string) string {
	out, err := exec.Command("uci", "-q", "get", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// setLocalTimezone: OpenWrt keeps its zone in uci and has no /etc/localtime;
// schedules must be evaluated in the router's local time.
func setLocalTimezone() {
	if os.Getenv("TZ") != "" {
		return
	}
	if _, err := os.Stat("/etc/localtime"); err == nil {
		return
	}
	if z := uci("system.@system[0].zonename"); z != "" {
		if loc, err := time.LoadLocation(strings.ReplaceAll(z, " ", "_")); err == nil {
			time.Local = loc
		}
	}
}

func main() {
	setLocalTimezone()
	if len(os.Args) > 1 && os.Args[1] == "genkey" {
		fmt.Printf("key_id=%s\nsecret=%s\n", sign.RandomHex(4), sign.RandomHex(32))
		return
	}

	def := func(k, d string) string {
		if v := uci("owp.agent." + k); v != "" {
			return v
		}
		return d
	}
	listen := flag.String("listen", def("listen", "127.0.0.1:7071"), "listen address")
	keyID := flag.String("key-id", def("key_id", ""), "key id")
	secret := flag.String("secret", def("secret", ""), "shared secret")
	allow := flag.String("allow", def("allow_from", ""), "space separated source IPs/CIDRs allowed (empty = any)")
	useTLS := flag.Bool("tls", def("tls", "0") == "1", "serve HTTPS with a self-signed certificate")
	dataDir := flag.String("data", uci("owp.main.data_dir"), "data directory")
	flag.Parse()
	if *dataDir == "" {
		*dataDir = "/etc/owp"
	}
	certFile, keyFile := filepath.Join(*dataDir, "agent.crt"), filepath.Join(*dataDir, "agent.key")

	if flag.Arg(0) == "fingerprint" {
		c, err := tlsutil.LoadOrCreate(certFile, keyFile, "owp-agent")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(tlsutil.Fingerprint(c))
		return
	}
	if *keyID == "" || len(*secret) < 32 {
		log.Fatal("agent key not configured (key_id / secret >= 32 chars); run `owp-agent genkey`")
	}

	// config files the panel writes to must exist for uci
	for _, f := range []string{"/etc/config/owpfwd", "/etc/config/owpdev"} {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			_ = os.WriteFile(f, nil, 0o644)
		}
	}

	handler := agent.NewServer(agent.Config{Listen: *listen, KeyID: *keyID, Secret: *secret, AllowFrom: strings.Fields(*allow), DataDir: *dataDir})
	// OWP_COLLECT=0 runs an API-only instance (testing) that never touches the firewall
	if def("collect", "1") == "1" && os.Getenv("OWP_COLLECT") != "0" {
		handler.Traffic = agent.NewTraffic()
		handler.Collector = agent.NewCollector(handler.Traffic)
		handler.Collector.Net = agent.NewNetMon()
		go agent.NewPresence().Run()
		go handler.Collector.Net.Run()
		handler.Policy = agent.NewPolicy(handler.Traffic)
		handler.Collector.SetResolveHook(handler.Policy.OnResolve)
		go handler.Traffic.Run()
		go handler.Collector.Run()
		go handler.Policy.Run(handler.Collector.DNS())
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      90 * time.Second,
	}
	log.Printf("owp-agent %s listening on %s (tls=%v, firewall=%s)", agent.Version, *listen, *useTLS, agent.FirewallFlavor())
	if *useTLS {
		c, err := tlsutil.LoadOrCreate(certFile, keyFile, "owp-agent")
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("tls fingerprint %s", tlsutil.Fingerprint(c))
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12}
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}
	log.Fatal(srv.ListenAndServe())
}
