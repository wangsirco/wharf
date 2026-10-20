package panel

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Demo mode (WHARF_DEMO=1, development only — there is no UI switch): every JSON
// response is anonymised so screenshots of a real, busy panel can be published.
// Device and person names become generic ones, LAN / WAN addresses move into
// documentation ranges, MACs keep their vendor prefix but lose the rest, and
// anything listed in WHARF_DEMO_SCRUB ("secret=>replacement;…") is replaced.

type demoMapper struct {
	mu     sync.Mutex
	names  map[string]string // original (lower case) -> fake
	macs   map[string]string // fake MAC -> real, so links to device pages still work
	byMAC  map[string]string // real MAC -> fake device name
	used   map[string]bool
	scrub  []demoRule
	seeded bool
}

type demoRule struct {
	re  *regexp.Regexp
	rep string
}

var (
	demoNameKeys = map[string]bool{"name": true, "hostname": true, "alias": true, "static_name": true, "device_name": true, "device_now": true,
		"guest_name": true, "names": false}
	demoPersonKeys = map[string]bool{"display_name": true, "username": true, "owner_name": true, "by": true, "user": true}
	demoNoteKeys   = map[string]bool{"note": true}
	demoMACKeys    = map[string]bool{"mac": true, "device_mac": true}
	demoPools      = map[string][]string{
		"手机":  {"爸爸的 iPhone", "妈妈的手机", "小雨的手机", "备用手机", "奶奶的手机", "客人的手机"},
		"平板":  {"客厅 iPad", "孩子的平板", "厨房平板"},
		"电脑":  {"书房台式机", "工作笔记本", "MacBook Pro", "游戏电脑", "孩子的电脑"},
		"电视":  {"客厅电视", "卧室电视", "投影仪", "Apple TV"},
		"NAS": {"书房 NAS", "备份 NAS"},
		"虚拟机": {"web-server", "ubuntu-dev", "home-assistant", "docker-host", "jellyfin", "debian-vpn", "minecraft", "gitea", "monitoring", "test-vm"},
		"摄像头": {"门口摄像头", "车库摄像头", "宝宝监控"},
		"游戏机": {"PlayStation 5", "Switch", "Xbox"},
		"音箱":  {"小爱音箱", "HomePod", "书房音箱"},
		"家电":  {"扫地机器人", "空气净化器", "智能插座", "空调", "冰箱", "灯带", "门铃", "洗衣机"},
		"手表":  {"儿童手表", "Apple Watch"},
		"打印机": {"打印机"},
		"路由":  {"二楼 AP", "Mesh 节点", "旧路由器"},
	}
	demoGeneric = []string{"客厅设备", "书房设备", "卧室设备", "阳台设备", "车库设备", "厨房设备", "访客设备", "未命名设备 A", "未命名设备 B", "未命名设备 C"}
	demoForward = []string{"NAS 网页", "SSH 跳板", "Jellyfin", "Home Assistant", "远程桌面", "游戏服务器", "博客", "Git 服务", "监控面板", "下载器",
		"VPN", "文件同步", "照片备份", "测试服务", "邮件", "相册", "笔记", "代理", "开发环境", "数据库"}
	demoPeople = []string{"管理员", "小明", "阿杰", "家人", "朋友"}
	lanRe      = regexp.MustCompile(`\b10\.0\.2\.(\d{1,3})\b`)
	macRe      = regexp.MustCompile(`(?i)[0-9a-f]{2}(:[0-9a-f]{2}){5}`)
)

func newDemoMapper() *demoMapper {
	if os.Getenv("WHARF_DEMO") != "1" {
		return nil
	}
	d := &demoMapper{names: map[string]string{}, used: map[string]bool{}, macs: map[string]string{}, byMAC: map[string]string{}}
	for _, part := range strings.Split(os.Getenv("WHARF_DEMO_SCRUB"), ";") {
		if from, to, ok := strings.Cut(part, "=>"); ok && strings.TrimSpace(from) != "" {
			d.scrub = append(d.scrub, demoRule{regexp.MustCompile(`(?i)` + regexp.QuoteMeta(strings.TrimSpace(from))), strings.TrimSpace(to)})
		}
	}
	return d
}

func (d *demoMapper) pick(pool []string, seed string) string {
	for _, n := range pool {
		if !d.used[n] {
			d.used[n] = true
			return n
		}
	}
	for i := 2; ; i++ { // pool exhausted: number them
		n := fmt.Sprintf("%s %d", pool[int(hashByte(seed))%len(pool)], i)
		if !d.used[n] {
			d.used[n] = true
			return n
		}
	}
}

func hashByte(s string) byte { h := sha256.Sum256([]byte(s)); return h[0] }

func (d *demoMapper) poolFor(kind string) []string {
	for k, p := range demoPools {
		if strings.Contains(kind, k) {
			return p
		}
	}
	return demoGeneric
}

// name returns the fake for an original name, assigning one from the pool on first sight.
func (d *demoMapper) name(orig string, pool []string) string {
	key := strings.ToLower(strings.TrimSpace(orig))
	if key == "" {
		return orig
	}
	if f, ok := d.names[key]; ok {
		return f
	}
	f := d.pick(pool, key)
	d.names[key] = f
	return f
}

// seed maps every name a device is known by to one fake, chosen by its type.
func (a *App) demoSeed() {
	d := a.demo
	if d.seeded {
		return
	}
	d.seeded = true
	var devs []Device
	_ = a.agent.Do("GET", "/v1/devices", nil, &devs)
	metas := a.deviceMetas()
	type dev struct {
		names []string
		kind  string
	}
	byMAC := map[string]*dev{}
	get := func(mac string) *dev {
		if byMAC[mac] == nil {
			byMAC[mac] = &dev{}
		}
		return byMAC[mac]
	}
	for _, x := range devs {
		e := get(x.MAC)
		id := a.identifyDevice(x.MAC, firstNonEmpty(x.StaticName, x.Hostname), metas[x.MAC].Type)
		e.kind = id.Type
		if id.VMTag != "" {
			e.kind = "虚拟机"
		}
		e.names = append(e.names, x.Hostname, x.StaticName, id.GuestName)
	}
	for mac, m := range metas {
		e := get(mac)
		e.names = append(e.names, m.Alias)
		if e.kind == "" {
			e.kind = m.Type
		}
	}
	if rows, err := a.db.Query(`SELECT mac, name FROM devices_seen WHERE name<>''`); err == nil {
		for rows.Next() {
			var mac, n string
			if rows.Scan(&mac, &n) == nil {
				get(mac).names = append(get(mac).names, n)
			}
		}
		rows.Close()
	}
	for mac, e := range byMAC {
		fake := ""
		if fake == "" {
			fake = d.pick(d.poolFor(e.kind), mac)
		}
		d.byMAC[strings.ToLower(mac)] = fake
		for _, n := range e.names {
			if k := strings.ToLower(strings.TrimSpace(n)); len(k) > 1 && !generic(k) {
				d.names[k] = fake
			}
		}
	}
}

// names that are labels rather than identities ("未知设备", "Apple 设备") are left alone
func generic(k string) bool {
	return strings.Contains(k, "未知") || strings.Contains(k, "设备") || strings.Contains(k, "未命名") || k == "localhost"
}

func (d *demoMapper) mac(m string) string {
	p := strings.Split(strings.ToLower(m), ":")
	if len(p) != 6 {
		return m
	}
	h := sha256.Sum256([]byte("wharf-demo" + m))
	f := fmt.Sprintf("%s:%s:%s:%02x:%02x:%02x", p[0], p[1], p[2], h[0], h[1], h[2])
	d.macs[f] = strings.ToLower(m)
	return f
}

// text scrubs a free-form string: known names, LAN / WAN addresses, configured secrets.
func (d *demoMapper) text(s string) string {
	if s == "" {
		return s
	}
	s = lanRe.ReplaceAllString(s, "192.168.1.$1")
	for _, r := range d.scrub {
		s = r.re.ReplaceAllString(s, r.rep)
	}
	low := strings.ToLower(s)
	for orig, fake := range d.names {
		if len(orig) >= 4 && strings.Contains(low, orig) {
			s = regexp.MustCompile(`(?i)`+regexp.QuoteMeta(orig)).ReplaceAllString(s, fake)
			low = strings.ToLower(s)
		}
	}
	return s
}

func (d *demoMapper) walk(v any) any {
	switch x := v.(type) {
	case map[string]any:
		kind, _ := x["type"].(string)
		_, isForward := x["wan_port"]
		realMAC, _ := x["mac"].(string)
		realMAC = strings.ToLower(realMAC)
		if realMAC == "" {
			realMAC, _ = x["device_mac"].(string)
			realMAC = strings.ToLower(realMAC)
		}
		for k, val := range x {
			s, ok := val.(string)
			if !ok {
				x[k] = d.walk(val)
				continue
			}
			switch {
			case demoMACKeys[k]:
				x[k] = d.mac(s)
			case demoNameKeys[k] && isForward && k == "name":
				x[k] = d.name("fwd:"+s, demoForward)
			case demoNameKeys[k] && realMAC != "":
				if s == "" || generic(strings.ToLower(s)) {
					break
				}
				f, ok := d.byMAC[realMAC]
				if !ok {
					f = d.pick(d.poolFor(kind), realMAC)
					d.byMAC[realMAC] = f
				}
				x[k] = f
			case demoNameKeys[k] && isForward:
				x[k] = d.text(s)
			case demoPersonKeys[k]:
				if s != "" && s != "admin" {
					x[k] = d.name("person:"+s, demoPeople)
				}
			case demoNoteKeys[k]:
				x[k] = ""
			default:
				x[k] = d.text(s)
			}
		}
		return x
	case []any:
		for i := range x {
			x[i] = d.walk(x[i])
		}
		return x
	case string:
		return d.text(x)
	}
	return v
}

type demoWriter struct {
	http.ResponseWriter
	buf  bytes.Buffer
	code int
}

func (w *demoWriter) WriteHeader(c int)           { w.code = c }
func (w *demoWriter) Write(b []byte) (int, error) { return w.buf.Write(b) }

func (a *App) demoWrap(h http.Handler) http.Handler {
	if a.demo == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			h.ServeHTTP(w, r)
			return
		}
		a.demo.mu.Lock()
		r.URL.Path = macRe.ReplaceAllStringFunc(r.URL.Path, func(m string) string {
			if real, ok := a.demo.macs[strings.ToLower(m)]; ok {
				return real
			}
			return m
		})
		a.demo.mu.Unlock()
		dw := &demoWriter{ResponseWriter: w, code: 200}
		h.ServeHTTP(dw, r)
		body := dw.buf.Bytes()
		if strings.Contains(w.Header().Get("Content-Type"), "json") {
			a.demo.mu.Lock()
			a.demoSeed()
			dec := json.NewDecoder(bytes.NewReader(body))
			dec.UseNumber()
			var v any
			if dec.Decode(&v) == nil {
				if out, err := json.Marshal(a.demo.walk(v)); err == nil {
					body = out
				}
			}
			a.demo.mu.Unlock()
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(dw.code)
		_, _ = w.Write(body)
	})
}
