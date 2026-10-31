package agent

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// Device fingerprints, for telling what a device is when its MAC is randomised and it
// sends no hostname:
//
//   - DHCP: the parameter request list (option 55) and vendor class (option 60) differ
//     by operating system. dnsmasq logs them with log-dhcp (see DNSLog.handleDHCP).
//   - mDNS: asked directly (unicast to port 5353), Apple and many other devices answer
//     with their .local name, the services they offer and model fields in TXT records.
//   - SSDP / UPnP: TVs, consoles, speakers and printers describe themselves (friendly
//     name, maker, model) in an XML document they point to.
//
// Results are kept in <data>/fingerprints.json; the panel classifies them.

type DeviceFP struct {
	DHCPOpts   string   `json:"dhcp_opts,omitempty"`   // option 55, in order: "1,121,3,6,15,108,114,119,252"
	DHCPVendor string   `json:"dhcp_vendor,omitempty"` // option 60: "android-dhcp-14", "MSFT 5.0"
	DHCPName   string   `json:"dhcp_name,omitempty"`   // option 12
	DHCPSeen   int64    `json:"dhcp_seen,omitempty"`
	LocalName  string   `json:"local_name,omitempty"` // mDNS host name without ".local"
	Model      string   `json:"model,omitempty"`      // mDNS / UPnP model ("iPhone17,2", "Google TV Streamer")
	Friendly   string   `json:"friendly,omitempty"`   // the name the device gives itself (Cast, UPnP)
	Maker      string   `json:"maker,omitempty"`      // UPnP manufacturer
	Services   []string `json:"services,omitempty"`   // "_airplay._tcp", "_googlecast._tcp" …
	NetSeen    int64    `json:"net_seen,omitempty"`
}

var fps = struct {
	sync.Mutex
	m     map[string]*DeviceFP
	path  string
	dirty bool
}{m: map[string]*DeviceFP{}}

// SetIdentityDir loads the stored fingerprints (agent start).
func SetIdentityDir(dataDir string) {
	fps.Lock()
	defer fps.Unlock()
	fps.path = filepath.Join(dataDir, "fingerprints.json")
	if b, err := os.ReadFile(fps.path); err == nil {
		_ = json.Unmarshal(b, &fps.m)
	}
	if fps.m == nil {
		fps.m = map[string]*DeviceFP{}
	}
}

func fpUpdate(mac string, f func(*DeviceFP)) {
	fps.Lock()
	defer fps.Unlock()
	p := fps.m[mac]
	if p == nil {
		p = &DeviceFP{}
		fps.m[mac] = p
	}
	f(p)
	fps.dirty = true
}

// Fingerprints returns a copy of everything known.
func Fingerprints() map[string]DeviceFP {
	fps.Lock()
	defer fps.Unlock()
	out := make(map[string]DeviceFP, len(fps.m))
	for k, v := range fps.m {
		out[k] = *v
	}
	return out
}

func saveFingerprints() {
	fps.Lock()
	defer fps.Unlock()
	if !fps.dirty || fps.path == "" {
		return
	}
	cut := time.Now().Add(-90 * 24 * time.Hour).Unix()
	for mac, p := range fps.m {
		if max(p.DHCPSeen, p.NetSeen) < cut {
			delete(fps.m, mac)
		}
	}
	b, _ := json.Marshal(fps.m)
	if os.WriteFile(fps.path+".tmp", b, 0o600) == nil && os.Rename(fps.path+".tmp", fps.path) == nil {
		fps.dirty = false
	}
}

// ---- DHCP (dnsmasq log-dhcp) ----
//
//	dnsmasq-dhcp[1]: 1185352710 vendor class: android-dhcp-14
//	dnsmasq-dhcp[1]: 1185352710 client provides name: Pixel-8
//	dnsmasq-dhcp[1]: 1185352710 DHCPREQUEST(br-lan) 192.168.1.20 aa:8f:fe:6d:d7:e7
//	dnsmasq-dhcp[1]: 1185352710 requested options: 1:netmask, 3:router, 6:dns-server, 15:domain-name,
//	dnsmasq-dhcp[1]: 1185352710 requested options: 26:mtu, 28:broadcast, 51:lease-time, 58:T1,

type dhcpTx struct {
	mac, vendor, name string
	opts              []string
	optsDone          bool // a new "requested options" block after a DHCP verb starts over
	at                time.Time
}

// SetDHCPLogging turns dnsmasq's DHCP detail log on or off (it goes to the same file).
func SetDHCPLogging(on bool) error {
	sec := "@dnsmasq[0]"
	if all, err := uciGetConfig("dhcp"); err == nil {
		for id, s := range all {
			if s[".type"] == "dnsmasq" {
				sec = id
				break
			}
		}
	}
	want := map[bool]string{true: "1", false: ""}[on]
	if uciGetOption("dhcp", sec, "logdhcp") == want {
		return nil
	}
	ch := Change{Op: "set", Config: "dhcp", Section: sec, Values: map[string]any{"logdhcp": "1"}}
	if !on {
		ch = Change{Op: "delete", Config: "dhcp", Section: sec, Options: []string{"logdhcp"}}
	}
	_, err := Apply([]Change{ch})
	return err
}

func (d *DNSLog) handleDHCP(rest string) {
	serial, text, ok := strings.Cut(rest, " ")
	if !ok {
		return
	}
	if _, err := strconv.ParseUint(serial, 10, 64); err != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dhcp == nil {
		d.dhcp = map[string]*dhcpTx{}
	}
	tx := d.dhcp[serial]
	if tx == nil {
		tx = &dhcpTx{at: time.Now()}
		d.dhcp[serial] = tx
	}
	switch {
	case strings.HasPrefix(text, "vendor class: "):
		tx.vendor = strings.TrimSpace(strings.TrimPrefix(text, "vendor class: "))
	case strings.HasPrefix(text, "client provides name: "):
		tx.name = strings.TrimSpace(strings.TrimPrefix(text, "client provides name: "))
	case strings.HasPrefix(text, "requested options: "):
		if tx.optsDone {
			tx.opts, tx.optsDone = nil, false
		}
		for _, o := range strings.Split(strings.TrimPrefix(text, "requested options: "), ",") {
			n, _, _ := strings.Cut(strings.TrimSpace(o), ":")
			if _, err := strconv.Atoi(n); err == nil {
				tx.opts = append(tx.opts, n)
			}
		}
	case strings.HasPrefix(text, "DHCP"):
		for _, f := range strings.Fields(text)[1:] {
			if hw, err := net.ParseMAC(f); err == nil && len(hw) == 6 {
				tx.mac = hw.String()
			}
		}
		tx.optsDone = len(tx.opts) > 0
	default:
		return
	}
	if tx.mac != "" && len(tx.opts) > 0 {
		t := *tx
		fpUpdate(t.mac, func(p *DeviceFP) {
			p.DHCPOpts, p.DHCPVendor, p.DHCPSeen = strings.Join(t.opts, ","), t.vendor, time.Now().Unix()
			if t.name != "" {
				p.DHCPName = t.name
			}
		})
	}
}

func (d *DNSLog) gcDHCP() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, tx := range d.dhcp {
		if time.Since(tx.at) > time.Minute {
			delete(d.dhcp, k)
		}
	}
}

// ---- mDNS and SSDP probes ----

var probeMu sync.Mutex

// ProbeNetwork asks every online LAN device about itself (mDNS, then SSDP). It takes a
// few seconds; concurrent calls wait for the running one.
func ProbeNetwork() {
	probeMu.Lock()
	defer probeMu.Unlock()
	subnet, _, err := lanSubnet()
	if err != nil {
		return
	}
	macOf := map[string]string{}
	var ips []string
	for _, d := range GetDevices() {
		if ip := net.ParseIP(d.IP); d.Online && ip != nil && subnet.Contains(ip) {
			macOf[d.IP] = d.MAC
			ips = append(ips, d.IP)
		}
	}
	sem := make(chan struct{}, 24)
	var wg sync.WaitGroup
	var silentMu sync.Mutex
	var silent []string
	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			r := mdnsAsk(ip)
			if r == nil || r.host == "" {
				silentMu.Lock()
				silent = append(silent, ip)
				silentMu.Unlock()
			}
			if r != nil {
				fpUpdate(macOf[ip], func(p *DeviceFP) {
					p.NetSeen = time.Now().Unix()
					if r.host != "" {
						p.LocalName = r.host
					}
					if r.model != "" {
						p.Model = r.model
					}
					if r.friendly != "" {
						p.Friendly = r.friendly
					}
					if len(r.services) > 0 {
						p.Services = r.services
					}
				})
			}
		}()
	}
	wg.Wait()
	// sleeping iPhones do not answer themselves; a Bonjour sleep proxy (an Apple TV or
	// HomePod) answers multicast questions for them
	for ip, host := range mdnsReverse(silent) {
		fpUpdate(macOf[ip], func(p *DeviceFP) { p.LocalName, p.NetSeen = host, time.Now().Unix() })
	}
	for ip, u := range ssdpAsk() {
		if mac := macOf[ip]; mac != "" {
			fpUpdate(mac, func(p *DeviceFP) {
				p.NetSeen = time.Now().Unix()
				p.Maker = firstNonEmptyStr(u.Manufacturer, p.Maker)
				if u.Model != "" && p.Model == "" {
					p.Model = u.Model
				}
				if u.Friendly != "" && p.Friendly == "" {
					p.Friendly = u.Friendly
				}
			})
		}
	}
	saveFingerprints()
}

type mdnsResult struct {
	host, model, friendly string
	services              []string
}

var mdnsTypes = []string{"_services._dns-sd._udp.local.", "_device-info._tcp.local.", "_companion-link._tcp.local.",
	"_airplay._tcp.local.", "_raop._tcp.local.", "_googlecast._tcp.local.", "_ipp._tcp.local.", "_hap._tcp.local.", "_smb._tcp.local."}

// mdnsAsk sends one unicast mDNS query to ip:5353 (reverse name, service list and the
// common service types) and, when instances come back without their TXT records, asks
// for those too.
func mdnsAsk(ip string) *mdnsResult {
	conn, err := net.DialTimeout("udp4", net.JoinHostPort(ip, "5353"), time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	rev := revName(ip)
	qs := []dnsmessage.Question{{Name: dnsmessage.MustNewName(rev), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}}
	for _, t := range mdnsTypes {
		qs = append(qs, dnsmessage.Question{Name: dnsmessage.MustNewName(t), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET})
	}
	res := &mdnsResult{}
	txt := map[string]bool{}  // instance names whose TXT we have
	inst := map[string]bool{} // instance names seen
	ask := func(qs []dnsmessage.Question) bool {
		msg := dnsmessage.Message{Header: dnsmessage.Header{ID: uint16(time.Now().UnixNano())}, Questions: qs}
		b, err := msg.Pack()
		if err != nil {
			return false
		}
		if _, err := conn.Write(b); err != nil {
			return false
		}
		got := false
		buf := make([]byte, 9000)
		_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return got
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil {
				continue
			}
			got = true
			for _, rr := range append(append(m.Answers, m.Additionals...), m.Authorities...) {
				name := rr.Header.Name.String()
				switch b := rr.Body.(type) {
				case *dnsmessage.PTRResource:
					target := b.PTR.String()
					switch {
					case name == rev:
						res.host = strings.TrimSuffix(strings.TrimSuffix(target, "."), ".local")
					case name == "_services._dns-sd._udp.local.":
						if s := strings.TrimSuffix(strings.TrimSuffix(target, "."), ".local"); !slices.Contains(res.services, s) {
							res.services = append(res.services, s)
						}
					default:
						inst[target] = true
						if s := strings.TrimSuffix(strings.TrimSuffix(name, "."), ".local"); !slices.Contains(res.services, s) {
							res.services = append(res.services, s)
						}
					}
				case *dnsmessage.SRVResource:
					if res.host == "" {
						res.host = strings.TrimSuffix(strings.TrimSuffix(b.Target.String(), "."), ".local")
					}
				case *dnsmessage.TXTResource:
					txt[name] = true
					kv := map[string]string{}
					for _, t := range b.TXT {
						if k, v, ok := strings.Cut(t, "="); ok {
							kv[strings.ToLower(k)] = v
						}
					}
					// model: _device-info / AirPlay "model", Continuity "rpmd", Cast "md", RAOP "am"
					for _, k := range []string{"model", "rpmd", "md", "am", "ty"} {
						if v := strings.TrimSpace(kv[k]); v != "" && res.model == "" {
							res.model = v
						}
					}
					if v := strings.TrimSpace(kv["fn"]); v != "" { // Cast friendly name
						res.friendly = v
					}
				}
			}
		}
	}
	if !ask(qs) {
		return nil
	}
	var more []dnsmessage.Question
	for n := range inst {
		if !txt[n] && len(more) < 6 {
			if nm, err := dnsmessage.NewName(n); err == nil {
				more = append(more, dnsmessage.Question{Name: nm, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET})
			}
		}
	}
	if len(more) > 0 && res.model == "" {
		ask(more)
	}
	if res.host == "" && res.model == "" && res.friendly == "" && len(res.services) == 0 {
		return nil
	}
	slices.Sort(res.services)
	return res
}

func revName(ip string) string {
	a := net.ParseIP(ip).To4()
	return strconv.Itoa(int(a[3])) + "." + strconv.Itoa(int(a[2])) + "." + strconv.Itoa(int(a[1])) + "." + strconv.Itoa(int(a[0])) + ".in-addr.arpa."
}

// mdnsReverse asks the multicast group for the .local names of these addresses (from a
// non-5353 port, so answers come back to us by unicast) and matches answers by name.
func mdnsReverse(ips []string) map[string]string {
	out := map[string]string{}
	if len(ips) == 0 {
		return out
	}
	_, lanIP, err := lanSubnet()
	if err != nil {
		return out
	}
	c, err := net.ListenPacket("udp4", net.JoinHostPort(lanIP.String(), "0"))
	if err != nil {
		return out
	}
	defer c.Close()
	pc := ipv4.NewPacketConn(c)
	dev := uciGetOption("network", "lan", "device")
	if dev == "" {
		dev = "br-lan"
	}
	if ifc, err := net.InterfaceByName(dev); err == nil {
		_ = pc.SetMulticastInterface(ifc)
	}
	_ = pc.SetMulticastTTL(255)
	byRev := map[string]string{}
	dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	for i := 0; i < len(ips); i += 16 {
		var qs []dnsmessage.Question
		for _, ip := range ips[i:min(i+16, len(ips))] {
			r := revName(ip)
			byRev[r] = ip
			qs = append(qs, dnsmessage.Question{Name: dnsmessage.MustNewName(r), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET})
		}
		msg := dnsmessage.Message{Questions: qs}
		if b, err := msg.Pack(); err == nil {
			_, _ = c.WriteTo(b, dst)
		}
	}
	buf := make([]byte, 9000)
	_ = c.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return out
		}
		var m dnsmessage.Message
		if m.Unpack(buf[:n]) != nil {
			continue
		}
		for _, rr := range append(m.Answers, m.Additionals...) {
			if p, ok := rr.Body.(*dnsmessage.PTRResource); ok {
				if ip := byRev[rr.Header.Name.String()]; ip != "" {
					out[ip] = strings.TrimSuffix(strings.TrimSuffix(p.PTR.String(), "."), ".local")
				}
			}
		}
	}
}

type upnpInfo struct {
	Friendly     string
	Manufacturer string
	Model        string
}

// ssdpAsk multicasts one M-SEARCH on the LAN and reads each answer's description.
func ssdpAsk() map[string]upnpInfo {
	out := map[string]upnpInfo{}
	_, lanIP, err := lanSubnet()
	if err != nil {
		return out
	}
	c, err := net.ListenPacket("udp4", net.JoinHostPort(lanIP.String(), "0"))
	if err != nil {
		return out
	}
	defer c.Close()
	pc := ipv4.NewPacketConn(c)
	dev := uciGetOption("network", "lan", "device")
	if dev == "" {
		dev = "br-lan"
	}
	if ifc, err := net.InterfaceByName(dev); err == nil {
		_ = pc.SetMulticastInterface(ifc)
	}
	_ = pc.SetMulticastTTL(2)
	req := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
	dst := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	for range 2 {
		_, _ = c.WriteTo([]byte(req), dst)
	}
	locs := map[string]string{} // ip -> description URL
	buf := make([]byte, 4096)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			break
		}
		ip := from.(*net.UDPAddr).IP.String()
		if _, ok := locs[ip]; ok {
			continue
		}
		for _, line := range strings.Split(string(buf[:n]), "\r\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "location") {
				v = strings.TrimSpace(v)
				// only descriptions served by the device that answered
				if strings.HasPrefix(v, "http://"+ip+":") || strings.HasPrefix(v, "http://"+ip+"/") {
					locs[ip] = v
				}
			}
		}
	}
	cl := &http.Client{Timeout: 2 * time.Second}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for ip, u := range locs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
			resp, err := cl.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			var doc struct {
				Device struct {
					FriendlyName string `xml:"friendlyName"`
					Manufacturer string `xml:"manufacturer"`
					ModelName    string `xml:"modelName"`
				} `xml:"device"`
			}
			if xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&doc) != nil {
				return
			}
			mu.Lock()
			out[ip] = upnpInfo{Friendly: clip(doc.Device.FriendlyName), Manufacturer: clip(doc.Device.Manufacturer), Model: clip(doc.Device.ModelName)}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// RunIdentity saves DHCP fingerprints regularly (the probes run when the panel asks).
func RunIdentity() {
	for {
		time.Sleep(2 * time.Minute)
		saveFingerprints()
	}
}
