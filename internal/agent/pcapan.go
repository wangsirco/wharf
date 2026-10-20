package agent

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
)

// pcap analysis without external libraries: per-protocol breakdown, a timeline,
// conversations with TCP health (handshake RTT / failures, retransmissions, resets,
// zero windows), DNS transactions, TLS SNI, ICMP errors, and "expert" findings in
// plain language — the things one would otherwise dig out of Wireshark by hand.

var analysisCache sync.Map // id -> *PcapAnalysis

type PcapAnalysis struct {
	ID        string       `json:"id"`
	Packets   int64        `json:"packets"`
	Bytes     int64        `json:"bytes"`
	First     float64      `json:"first"`
	Last      float64      `json:"last"`
	Truncated bool         `json:"truncated"` // stopped after maxAnalyse packets
	SnapCut   int64        `json:"snap_cut"`  // packets cut by snaplen
	Protocols []NamedCount `json:"protocols"`
	Services  []NamedCount `json:"services"`
	Timeline  []TimePoint  `json:"timeline"`
	Bucket    float64      `json:"bucket"` // seconds per timeline point
	Hosts     []HostStat   `json:"hosts"`
	Convs     []Conv       `json:"conversations"`
	TCP       TCPSummary   `json:"tcp"`
	DNS       DNSSummary   `json:"dns"`
	TLS       []NamedCount `json:"tls_sni"`
	HTTP      []NamedCount `json:"http_hosts"`
	ICMP      []ICMPStat   `json:"icmp"`
	Findings  []Finding    `json:"findings"`
	Sizes     []NamedCount `json:"sizes"` // packet size histogram
}

type NamedCount struct {
	Name    string `json:"name"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
	Extra   string `json:"extra,omitempty"`
}

type TimePoint struct {
	T       float64 `json:"t"`
	Packets int64   `json:"packets"`
	Bytes   int64   `json:"bytes"`
	Retrans int64   `json:"retrans"`
}

type HostStat struct {
	IP      string `json:"ip"`
	Sent    int64  `json:"sent"`
	Recv    int64  `json:"recv"`
	Packets int64  `json:"packets"`
	Peers   int    `json:"peers"`
}

type Conv struct {
	Proto     string  `json:"proto"`
	A         string  `json:"a"` // initiator when known
	B         string  `json:"b"`
	Service   string  `json:"service,omitempty"`
	Packets   int64   `json:"packets"`
	BytesAB   int64   `json:"bytes_ab"`
	BytesBA   int64   `json:"bytes_ba"`
	Start     float64 `json:"start"`
	Dur       float64 `json:"dur"`
	State     string  `json:"state"` // ok | failed | reset | partial | open
	SynTries  int     `json:"syn_tries,omitempty"`
	RTT       float64 `json:"rtt_ms,omitempty"`
	Retrans   int64   `json:"retrans,omitempty"`
	DupAcks   int64   `json:"dup_acks,omitempty"`
	ZeroWin   int64   `json:"zero_win,omitempty"`
	Resets    int64   `json:"resets,omitempty"`
	MSS       int     `json:"mss,omitempty"`
	PeerMSS   int     `json:"peer_mss,omitempty"`
	SNI       string  `json:"sni,omitempty"`
	ResetBy   string  `json:"reset_by,omitempty"`
	DataBytes int64   `json:"data_bytes,omitempty"`
}

type TCPSummary struct {
	Conns       int     `json:"conns"`
	Handshakes  int     `json:"handshakes"`
	Failed      int     `json:"failed"`
	Reset       int     `json:"reset"`
	RTTAvg      float64 `json:"rtt_avg_ms"`
	RTTP50      float64 `json:"rtt_p50_ms"`
	RTTP95      float64 `json:"rtt_p95_ms"`
	DataSegs    int64   `json:"data_segments"`
	Retrans     int64   `json:"retrans"`
	RetransRate float64 `json:"retrans_rate"`
	DupAcks     int64   `json:"dup_acks"`
	ZeroWin     int64   `json:"zero_win"`
}

type DNSSummary struct {
	Queries   int          `json:"queries"`
	Answered  int          `json:"answered"`
	NoAnswer  int          `json:"no_answer"`
	Errors    []NamedCount `json:"errors"` // rcode -> count
	AvgMs     float64      `json:"avg_ms"`
	P95Ms     float64      `json:"p95_ms"`
	Names     []NamedCount `json:"names"`
	Slow      []DNSTx      `json:"slow"`
	Failures  []DNSTx      `json:"failures"`
	Resolvers []NamedCount `json:"resolvers"`
}

type DNSTx struct {
	TS     float64 `json:"ts"`
	Client string  `json:"client"`
	Server string  `json:"server"`
	Name   string  `json:"name"`
	Type   string  `json:"type"`
	Rcode  string  `json:"rcode"`
	Ms     float64 `json:"ms"`
}

type ICMPStat struct {
	Kind  string `json:"kind"`
	From  string `json:"from"`
	About string `json:"about,omitempty"`
	Count int64  `json:"count"`
}

type Finding struct {
	Level  string `json:"level"` // error | warn | info | ok
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

const maxAnalyse = 3_000_000

// ---- pcap reading ----

type pcapReader struct {
	r        *bufio.Reader
	order    binary.ByteOrder
	nano     bool
	linkType uint32
	snap     uint32
	hdr      [16]byte
	buf      []byte
}

func newPcapReader(f io.Reader) (*pcapReader, error) {
	r := bufio.NewReaderSize(f, 1<<20)
	var gh [24]byte
	if _, err := io.ReadFull(r, gh[:]); err != nil {
		return nil, errors.New("文件为空或不是 pcap")
	}
	p := &pcapReader{r: r}
	switch binary.LittleEndian.Uint32(gh[0:4]) {
	case 0xa1b2c3d4:
		p.order = binary.LittleEndian
	case 0xa1b23c4d:
		p.order, p.nano = binary.LittleEndian, true
	case 0xd4c3b2a1:
		p.order = binary.BigEndian
	case 0x4d3cb2a1:
		p.order, p.nano = binary.BigEndian, true
	default:
		return nil, errors.New("不是 pcap 文件（pcapng 暂不支持）")
	}
	p.snap = p.order.Uint32(gh[16:20])
	p.linkType = p.order.Uint32(gh[20:24])
	return p, nil
}

// next returns timestamp (s), original length and captured bytes (valid until the next call).
func (p *pcapReader) next() (float64, int, []byte, error) {
	if _, err := io.ReadFull(p.r, p.hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	sec, frac := p.order.Uint32(p.hdr[0:4]), p.order.Uint32(p.hdr[4:8])
	incl, orig := p.order.Uint32(p.hdr[8:12]), p.order.Uint32(p.hdr[12:16])
	if incl > 262144 {
		return 0, 0, nil, errors.New("损坏的数据包记录")
	}
	if cap(p.buf) < int(incl) {
		p.buf = make([]byte, incl)
	}
	b := p.buf[:incl]
	if _, err := io.ReadFull(p.r, b); err != nil {
		return 0, 0, nil, io.ErrUnexpectedEOF
	}
	div := 1e6
	if p.nano {
		div = 1e9
	}
	return float64(sec) + float64(frac)/div, int(orig), b, nil
}

// l3 strips the link layer: returns ethertype and payload.
func (p *pcapReader) l3(b []byte) (uint16, []byte) {
	switch p.linkType {
	case 1: // Ethernet
		if len(b) < 14 {
			return 0, nil
		}
		et, off := binary.BigEndian.Uint16(b[12:14]), 14
		for (et == 0x8100 || et == 0x88a8) && len(b) >= off+4 { // VLAN tags
			et, off = binary.BigEndian.Uint16(b[off+2:off+4]), off+4
		}
		return et, b[off:]
	case 113: // Linux cooked v1
		if len(b) < 16 {
			return 0, nil
		}
		return binary.BigEndian.Uint16(b[14:16]), b[16:]
	case 276: // Linux cooked v2
		if len(b) < 20 {
			return 0, nil
		}
		return binary.BigEndian.Uint16(b[0:2]), b[20:]
	case 101, 12, 14: // raw IP
		if len(b) > 0 && b[0]>>4 == 6 {
			return 0x86dd, b
		}
		return 0x0800, b
	}
	return 0, nil
}

// ---- analysis state ----

type pcFlowKey struct {
	proto uint8
	a, b  netip.AddrPort // a < b canonical
}

type dirState struct {
	maxEnd   uint32
	seenData bool
	lastAck  uint32
	lastWin  uint16
	ackRun   int
	bytes    int64
	mss      int
}

type flow struct {
	key         pcFlowKey
	cli, srv    netip.AddrPort // initiator if SYN seen, else first sender
	known       bool           // initiator known from SYN
	pkts        int64
	first       float64
	last        float64
	synTS       float64
	synSeq      uint32
	synTries    int
	synAckTS    float64
	established bool
	fin, rst    bool
	rstBy       string
	retrans     int64
	dupAcks     int64
	zeroWin     int64
	resets      int64
	dirs        [2]dirState // 0: cli→srv, 1: srv→cli
	sni         string
	httpHost    string
	dataBytes   int64
}

type pcDNSKey struct {
	cli netip.AddrPort
	id  uint16
}

type dnsPending struct {
	ts     float64
	server string
	name   string
	qtype  string
}

func AnalyseCapture(id string) (*PcapAnalysis, error) {
	if v, ok := analysisCache.Load(id); ok {
		return v.(*PcapAnalysis), nil
	}
	c := findCapture(id)
	if c == nil {
		return nil, errors.New("抓包不存在或已被清理")
	}
	if c.Running {
		return nil, errors.New("抓包还在进行中")
	}
	f, err := os.Open(capPath(id))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res, err := analysePcap(f)
	if err != nil {
		return nil, err
	}
	res.ID = id
	analysisCache.Store(id, res)
	return res, nil
}

func analysePcap(f io.Reader) (*PcapAnalysis, error) {
	pr, err := newPcapReader(f)
	if err != nil {
		return nil, err
	}
	res := &PcapAnalysis{}
	protos := map[string]*NamedCount{}
	services := map[string]*NamedCount{}
	hosts := map[netip.Addr]*HostStat{}
	peers := map[netip.Addr]map[netip.Addr]bool{}
	flows := map[pcFlowKey]*flow{}
	var order []*flow
	type tl struct{ p, b, r int64 }
	timeline := map[int64]*tl{}
	sizes := [6]int64{}
	sni := map[string]*NamedCount{}
	httpHosts := map[string]*NamedCount{}
	icmp := map[string]*ICMPStat{}
	dnsPend := map[pcDNSKey]dnsPending{}
	dns := &res.DNS
	var dnsMs []float64
	dnsNames := map[string]*NamedCount{}
	dnsErr := map[string]int64{}
	resolvers := map[string]*NamedCount{}

	add := func(m map[string]*NamedCount, name string, n int) {
		e := m[name]
		if e == nil {
			e = &NamedCount{Name: name}
			m[name] = e
		}
		e.Packets++
		e.Bytes += int64(n)
	}
	host := func(ip netip.Addr) *HostStat {
		h := hosts[ip]
		if h == nil {
			h = &HostStat{IP: ip.String()}
			hosts[ip] = h
		}
		return h
	}

	for {
		ts, olen, b, err := pr.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if res.Packets == 0 {
				return nil, err
			}
			break // a capture cut mid-record is still useful
		}
		res.Packets++
		res.Bytes += int64(olen)
		if res.First == 0 {
			res.First = ts
		}
		res.Last = ts
		if len(b) < olen {
			res.SnapCut++
		}
		switch {
		case olen <= 64:
			sizes[0]++
		case olen <= 128:
			sizes[1]++
		case olen <= 256:
			sizes[2]++
		case olen <= 512:
			sizes[3]++
		case olen <= 1024:
			sizes[4]++
		default:
			sizes[5]++
		}
		sec := int64(ts)
		t := timeline[sec]
		if t == nil {
			t = &tl{}
			timeline[sec] = t
		}
		t.p++
		t.b += int64(olen)
		if res.Packets >= maxAnalyse {
			res.Truncated = true
			break
		}

		et, l3 := pr.l3(b)
		var src, dst netip.Addr
		var proto uint8
		var l4 []byte
		switch et {
		case 0x0800:
			if len(l3) < 20 || l3[0]>>4 != 4 {
				add(protos, "IPv4（损坏）", olen)
				continue
			}
			ihl := int(l3[0]&0x0f) * 4
			if ihl < 20 || len(l3) < ihl {
				continue
			}
			src, _ = netip.AddrFromSlice(l3[12:16])
			dst, _ = netip.AddrFromSlice(l3[16:20])
			proto = l3[9]
			fragOff := binary.BigEndian.Uint16(l3[6:8]) & 0x1fff
			if fragOff != 0 {
				add(protos, "IPv4 分片", olen)
				continue
			}
			tot := int(binary.BigEndian.Uint16(l3[2:4]))
			l4 = l3[ihl:]
			if tot >= ihl && tot-ihl < len(l4) {
				l4 = l4[:tot-ihl] // drop Ethernet padding
			}
		case 0x86dd:
			if len(l3) < 40 {
				continue
			}
			src, _ = netip.AddrFromSlice(l3[8:24])
			dst, _ = netip.AddrFromSlice(l3[24:40])
			proto = l3[6]
			l4 = l3[40:]
			if pl := int(binary.BigEndian.Uint16(l3[4:6])); pl < len(l4) {
				l4 = l4[:pl]
			}
		case 0x0806:
			add(protos, "ARP", olen)
			continue
		case 0x8864, 0x8863:
			add(protos, "PPPoE", olen)
			continue
		case 0x888e:
			add(protos, "EAPOL", olen)
			continue
		default:
			add(protos, fmt.Sprintf("其他（0x%04x）", et), olen)
			continue
		}
		hs, hd := host(src), host(dst)
		hs.Sent += int64(olen)
		hs.Packets++
		hd.Recv += int64(olen)
		hd.Packets++
		if peers[src] == nil {
			peers[src] = map[netip.Addr]bool{}
		}
		peers[src][dst] = true
		if peers[dst] == nil {
			peers[dst] = map[netip.Addr]bool{}
		}
		peers[dst][src] = true

		switch proto {
		case 6:
			add(protos, "TCP", olen)
			if len(l4) < 20 {
				continue
			}
			sp, dp := binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
			seq, ack := binary.BigEndian.Uint32(l4[4:8]), binary.BigEndian.Uint32(l4[8:12])
			doff := int(l4[12]>>4) * 4
			flags := l4[13]
			win := binary.BigEndian.Uint16(l4[14:16])
			if doff < 20 || doff > len(l4) {
				continue
			}
			payload := l4[doff:]
			syn, ackf, fin, rst := flags&0x02 != 0, flags&0x10 != 0, flags&0x01 != 0, flags&0x04 != 0
			s, d := netip.AddrPortFrom(src, sp), netip.AddrPortFrom(dst, dp)
			k := canon(6, s, d)
			fl := flows[k]
			if fl != nil && syn && !ackf && fl.synTries > 0 && seq != fl.synSeq {
				fl = nil // same ports reused by a new connection (different ISN)
			}
			if fl == nil {
				fl = &flow{key: k, cli: s, srv: d, first: ts}
				if syn && ackf { // first packet seen is the reply: the other side started it
					fl.cli, fl.srv = d, s
				}
				flows[k] = fl
				order = append(order, fl)
			}
			fl.pkts++
			fl.last = ts
			dir := 0
			if s != fl.cli {
				dir = 1
			}
			ds := &fl.dirs[dir]
			ds.bytes += int64(olen)
			plen := len(payload)
			if olen > len(b) { // snaplen cut: trust the IP length
				plen = max(plen, 0)
			}
			switch {
			case syn && !ackf:
				if !fl.known {
					fl.cli, fl.srv, fl.known = s, d, true
					if dir == 1 {
						fl.dirs[0], fl.dirs[1] = fl.dirs[1], fl.dirs[0]
						dir, ds = 0, &fl.dirs[0]
					}
				}
				if fl.synTries == 0 {
					fl.synTS, fl.synSeq = ts, seq
				}
				fl.synTries++
				ds.mss = tcpMSS(l4[20:doff])
				ds.maxEnd = seq + 1
			case syn && ackf:
				if fl.synAckTS == 0 {
					fl.synAckTS = ts
				}
				ds.mss = tcpMSS(l4[20:doff])
				ds.maxEnd = seq + 1
			}
			if rst {
				fl.rst = true
				fl.resets++
				fl.rstBy = s.String()
			}
			if fin {
				fl.fin = true
			}
			if ackf && !syn && fl.synAckTS > 0 && dir == 0 {
				fl.established = true
			}
			if ackf && !syn && !rst && fl.synTS == 0 && fl.synAckTS == 0 {
				fl.established = true // started before the capture
			}
			if win == 0 && !rst && !syn && !fin {
				fl.zeroWin++
			}
			if plen > 0 && !syn {
				res.TCP.DataSegs++
				fl.dataBytes += int64(plen)
				end := seq + uint32(plen)
				if ds.seenData && seqLE(end, ds.maxEnd) && !(plen == 1 && seq+1 == ds.maxEnd) { // not a keep-alive
					fl.retrans++
					t.r++
				} else if !ds.seenData || seqGT(end, ds.maxEnd) {
					ds.maxEnd = end
				}
				ds.seenData = true
				if fl.sni == "" && len(payload) > 5 && payload[0] == 0x16 {
					if name := tlsSNI(payload); name != "" {
						fl.sni = name
						add(sni, name, 1)
					}
				}
				if fl.httpHost == "" && dir == 0 && len(payload) > 16 {
					if h := httpHost(payload); h != "" {
						fl.httpHost = h
						add(httpHosts, h, 1)
					}
				}
			} else if ackf && !syn && !fin && !rst && plen == 0 {
				if ack == ds.lastAck && win == ds.lastWin && ds.lastAck != 0 {
					ds.ackRun++
					if ds.ackRun >= 1 {
						fl.dupAcks++
					}
				} else {
					ds.ackRun = 0
				}
				ds.lastAck, ds.lastWin = ack, win
			}
			add(services, serviceName(6, sp, dp), olen)
		case 17:
			add(protos, "UDP", olen)
			if len(l4) < 8 {
				continue
			}
			sp, dp := binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
			payload := l4[8:]
			s, d := netip.AddrPortFrom(src, sp), netip.AddrPortFrom(dst, dp)
			k := canon(17, s, d)
			fl := flows[k]
			if fl == nil {
				fl = &flow{key: k, cli: s, srv: d, first: ts}
				if sp < 1024 && dp >= 1024 {
					fl.cli, fl.srv = d, s
				}
				flows[k] = fl
				order = append(order, fl)
			}
			fl.pkts++
			fl.last = ts
			dir := 0
			if s != fl.cli {
				dir = 1
			}
			fl.dirs[dir].bytes += int64(olen)
			add(services, serviceName(17, sp, dp), olen)
			if (dp == 53 || sp == 53) && len(payload) >= 12 {
				id := binary.BigEndian.Uint16(payload[0:2])
				qr := payload[2]&0x80 != 0
				name, qtype := dnsQuestion(payload)
				if !qr {
					dns.Queries++
					dnsPend[pcDNSKey{s, id}] = dnsPending{ts, d.Addr().String(), name, qtype}
					add(dnsNames, name, olen)
					add(resolvers, d.Addr().String(), olen)
				} else if q, ok := dnsPend[pcDNSKey{d, id}]; ok {
					delete(dnsPend, pcDNSKey{d, id})
					ms := (ts - q.ts) * 1000
					rcode := dnsRcode(payload[3] & 0x0f)
					ancount := binary.BigEndian.Uint16(payload[6:8])
					dnsMs = append(dnsMs, ms)
					tx := DNSTx{TS: q.ts, Client: d.Addr().String(), Server: q.server, Name: q.name, Type: q.qtype, Rcode: rcode, Ms: round1(ms)}
					if rcode != "NOERROR" {
						dnsErr[rcode]++
						if len(dns.Failures) < 50 {
							dns.Failures = append(dns.Failures, tx)
						}
					} else {
						dns.Answered++
						if ancount == 0 {
							dnsErr["空应答"]++
						}
					}
					if ms > 300 {
						dns.Slow = append(dns.Slow, tx)
					}
				}
			}
		case 1, 58:
			name := "ICMP"
			if proto == 58 {
				name = "ICMPv6"
			}
			add(protos, name, olen)
			if len(l4) < 4 {
				continue
			}
			kind := icmpKind(proto, l4[0], l4[1])
			if kind == "" {
				continue
			}
			about := ""
			if proto == 1 && len(l4) >= 8+20 && (l4[0] == 3 || l4[0] == 11) { // quoted original header
				inner := l4[8:]
				if a, ok := netip.AddrFromSlice(inner[16:20]); ok {
					about = a.String()
					if ihl := int(inner[0]&0x0f) * 4; len(inner) >= ihl+4 && (inner[9] == 6 || inner[9] == 17) {
						about += fmt.Sprintf(":%d", binary.BigEndian.Uint16(inner[ihl+2:ihl+4]))
					}
				}
			}
			key := kind + "|" + src.String() + "|" + about
			e := icmp[key]
			if e == nil {
				e = &ICMPStat{Kind: kind, From: src.String(), About: about}
				icmp[key] = e
			}
			e.Count++
		case 2:
			add(protos, "IGMP", olen)
		case 47:
			add(protos, "GRE", olen)
		case 50:
			add(protos, "ESP（IPsec）", olen)
		default:
			add(protos, fmt.Sprintf("IP 协议 %d", proto), olen)
		}
	}
	dns.NoAnswer = len(dnsPend)

	// ---- summaries ----
	res.Protocols = sortedCounts(protos, 0)
	res.Services = sortedCounts(services, 25)
	res.TLS = sortedCounts(sni, 40)
	res.HTTP = sortedCounts(httpHosts, 20)
	dns.Names = sortedCounts(dnsNames, 30)
	dns.Resolvers = sortedCounts(resolvers, 10)
	for k, v := range dnsErr {
		dns.Errors = append(dns.Errors, NamedCount{Name: k, Packets: v})
	}
	sort.Slice(dns.Errors, func(i, j int) bool { return dns.Errors[i].Packets > dns.Errors[j].Packets })
	if len(dnsMs) > 0 {
		dns.AvgMs, dns.P95Ms = round1(mean(dnsMs)), round1(percentile(dnsMs, 95))
	}
	sort.Slice(dns.Slow, func(i, j int) bool { return dns.Slow[i].Ms > dns.Slow[j].Ms })
	if len(dns.Slow) > 30 {
		dns.Slow = dns.Slow[:30]
	}
	for i, n := range []string{"≤64 B", "65–128 B", "129–256 B", "257–512 B", "513–1024 B", ">1024 B"} {
		res.Sizes = append(res.Sizes, NamedCount{Name: n, Packets: sizes[i]})
	}

	// timeline: at most ~300 points
	span := res.Last - res.First
	res.Bucket = 1
	for span/res.Bucket > 300 {
		res.Bucket *= 2
	}
	agg := map[int64]*TimePoint{}
	for s, v := range timeline {
		k := int64(float64(s-int64(res.First)) / res.Bucket)
		p := agg[k]
		if p == nil {
			p = &TimePoint{T: float64(int64(res.First)) + float64(k)*res.Bucket}
			agg[k] = p
		}
		p.Packets += v.p
		p.Bytes += v.b
		p.Retrans += v.r
	}
	for k := int64(0); k <= int64(span/res.Bucket); k++ {
		if p := agg[k]; p != nil {
			res.Timeline = append(res.Timeline, *p)
		} else {
			res.Timeline = append(res.Timeline, TimePoint{T: float64(int64(res.First)) + float64(k)*res.Bucket})
		}
	}

	for _, h := range hosts {
		h.Peers = len(peers[netip.MustParseAddr(h.IP)])
		res.Hosts = append(res.Hosts, *h)
	}
	sort.Slice(res.Hosts, func(i, j int) bool { return res.Hosts[i].Sent+res.Hosts[i].Recv > res.Hosts[j].Sent+res.Hosts[j].Recv })
	if len(res.Hosts) > 30 {
		res.Hosts = res.Hosts[:30]
	}

	// conversations + TCP health
	var rtts []float64
	var convs []Conv
	failedTargets := map[string]int{}
	resetTargets := map[string]int{}
	for _, fl := range order {
		c := Conv{Proto: "UDP", A: fl.cli.String(), B: fl.srv.String(), Packets: fl.pkts, BytesAB: fl.dirs[0].bytes, BytesBA: fl.dirs[1].bytes,
			Start: fl.first, Dur: round3(fl.last - fl.first), Service: serviceName(fl.key.proto, fl.cli.Port(), fl.srv.Port()), SNI: fl.sni}
		if c.SNI == "" {
			c.SNI = fl.httpHost
		}
		if fl.key.proto == 6 {
			c.Proto = "TCP"
			res.TCP.Conns++
			c.SynTries, c.Retrans, c.DupAcks, c.ZeroWin, c.Resets = fl.synTries, fl.retrans, fl.dupAcks, fl.zeroWin, fl.resets
			c.MSS, c.PeerMSS, c.DataBytes = fl.dirs[0].mss, fl.dirs[1].mss, fl.dataBytes
			res.TCP.Retrans += fl.retrans
			res.TCP.DupAcks += fl.dupAcks
			res.TCP.ZeroWin += fl.zeroWin
			switch {
			case fl.synTS > 0 && fl.synAckTS > 0:
				res.TCP.Handshakes++
				c.RTT = round1((fl.synAckTS - fl.synTS) * 1000)
				rtts = append(rtts, c.RTT)
				c.State = "ok"
			case fl.synTS > 0 && fl.synAckTS == 0 && !fl.rst:
				c.State = "failed"
				res.TCP.Failed++
				failedTargets[fl.srv.String()]++
			case fl.synTS > 0 && fl.synAckTS == 0 && fl.rst:
				c.State = "refused"
				res.TCP.Failed++
				failedTargets[fl.srv.String()+"（被拒绝）"]++
			default:
				c.State = "partial" // started before the capture
			}
			if fl.rst && c.State != "refused" {
				c.State = "reset"
				res.TCP.Reset++
				c.ResetBy = fl.rstBy
				resetTargets[fl.srv.String()]++
			}
		} else {
			c.State = "udp"
		}
		convs = append(convs, c)
	}
	// keep the interesting ones: problems first, then by size
	score := func(c Conv) int64 {
		s := c.BytesAB + c.BytesBA
		switch c.State {
		case "failed", "refused":
			s += 1 << 40
		case "reset":
			s += 1 << 38
		}
		if c.Retrans > 0 {
			s += c.Retrans << 30
		}
		return s
	}
	sort.SliceStable(convs, func(i, j int) bool { return score(convs[i]) > score(convs[j]) })
	if len(convs) > 200 {
		convs = convs[:200]
	}
	res.Convs = convs
	if len(rtts) > 0 {
		res.TCP.RTTAvg, res.TCP.RTTP50, res.TCP.RTTP95 = round1(mean(rtts)), round1(percentile(rtts, 50)), round1(percentile(rtts, 95))
	}
	if res.TCP.DataSegs > 0 {
		res.TCP.RetransRate = round3(float64(res.TCP.Retrans) / float64(res.TCP.DataSegs))
	}

	for _, v := range icmp {
		res.ICMP = append(res.ICMP, *v)
	}
	sort.Slice(res.ICMP, func(i, j int) bool { return res.ICMP[i].Count > res.ICMP[j].Count })
	if len(res.ICMP) > 40 {
		res.ICMP = res.ICMP[:40]
	}

	res.Findings = findings(res, failedTargets, resetTargets)
	return res, nil
}

func findings(res *PcapAnalysis, failed, resets map[string]int) []Finding {
	var out []Finding
	top := func(m map[string]int, n int) string {
		type kv struct {
			k string
			v int
		}
		var l []kv
		for k, v := range m {
			l = append(l, kv{k, v})
		}
		sort.Slice(l, func(i, j int) bool { return l[i].v > l[j].v })
		var s []string
		for i, e := range l {
			if i >= n {
				break
			}
			s = append(s, fmt.Sprintf("%s ×%d", e.k, e.v))
		}
		return strings.Join(s, "、")
	}
	t := res.TCP
	if res.Packets == 0 {
		return []Finding{{"info", "没有抓到数据包", "检查接口和过滤条件是否正确，或在抓包期间让设备产生流量。"}}
	}
	if t.Failed > 0 {
		attempts := t.Handshakes + t.Failed
		lvl := "warn"
		if float64(t.Failed)/float64(attempts) >= 0.1 {
			lvl = "error"
		}
		out = append(out, Finding{lvl, fmt.Sprintf("%d / %d 个 TCP 连接握手失败（%.0f%%）", t.Failed, attempts, 100*float64(t.Failed)/float64(attempts)),
			"发出了 SYN 却没收到 SYN-ACK：对方不可达、端口被防火墙丢弃，或线路上某条路径在丢包。主要目标：" + top(failed, 6)})
	}
	if t.DataSegs > 200 {
		switch r := t.RetransRate; {
		case r >= 0.05:
			out = append(out, Finding{"error", fmt.Sprintf("TCP 重传率 %.1f%%", r*100), "超过 5% 会明显拖慢下载、上传和视频；通常是线路丢包或拥塞。重传集中的连接见「会话」。"})
		case r >= 0.01:
			out = append(out, Finding{"warn", fmt.Sprintf("TCP 重传率 %.1f%%", r*100), "1%–5% 的重传说明线路有轻微丢包或拥塞。"})
		default:
			out = append(out, Finding{"ok", fmt.Sprintf("TCP 重传率 %.2f%%", r*100), "传输质量正常。"})
		}
	}
	if t.Reset > 0 {
		out = append(out, Finding{"warn", fmt.Sprintf("%d 个连接被 RST 重置", t.Reset), "连接被一方强制中断（服务器拒绝、中间设备干扰或应用主动关闭）。主要目标：" + top(resets, 5)})
	}
	if t.ZeroWin > 0 {
		out = append(out, Finding{"warn", fmt.Sprintf("%d 次零窗口", t.ZeroWin), "接收方缓冲区满、处理不过来（设备性能或应用卡住），不是线路问题。"})
	}
	if t.Handshakes > 0 {
		lvl := "info"
		if t.RTTP95 > 250 {
			lvl = "warn"
		}
		out = append(out, Finding{lvl, fmt.Sprintf("握手延迟 中位 %.0f ms，P95 %.0f ms", t.RTTP50, t.RTTP95), "SYN → SYN-ACK 的时间，接近到服务器的网络往返时延。"})
	}
	d := res.DNS
	if d.Queries > 0 {
		var bad, benign []string
		for _, e := range d.Errors {
			item := fmt.Sprintf("%s ×%d", e.Name, e.Packets)
			if e.Name == "NXDOMAIN" || e.Name == "空应答" { // ad / tracker blocking, or AAAA with IPv6 off
				benign = append(benign, item)
			} else {
				bad = append(bad, item)
			}
		}
		lvl := "ok"
		msg := fmt.Sprintf("平均 %.0f ms，P95 %.0f ms。", d.AvgMs, d.P95Ms)
		if len(bad) > 0 {
			lvl = "warn"
			msg += " 失败：" + strings.Join(bad, "、") + "（SERVFAIL / REFUSED 说明上游 DNS 出了问题）。"
		}
		if d.NoAnswer > 0 {
			msg += fmt.Sprintf(" %d 个查询没有应答。", d.NoAnswer)
			if d.NoAnswer >= 3 && float64(d.NoAnswer) >= 0.05*float64(d.Queries) {
				lvl = "warn"
			}
		}
		if len(benign) > 0 {
			msg += " " + strings.Join(benign, "、") + "：域名不存在 / 没有该类型记录，多为广告拦截或 IPv6 关闭，属正常。"
		}
		if d.P95Ms > 300 {
			lvl = "warn"
		}
		out = append(out, Finding{lvl, fmt.Sprintf("DNS：%d 个查询", d.Queries), msg})
	}
	var unreach, ttl int64
	for _, i := range res.ICMP {
		if strings.Contains(i.Kind, "不可达") {
			unreach += i.Count
		}
		if strings.Contains(i.Kind, "TTL") {
			ttl += i.Count
		}
	}
	if unreach > 0 {
		out = append(out, Finding{"info", fmt.Sprintf("%d 个 ICMP 不可达", unreach), "路由器或对方告知某个地址 / 端口无法到达，详见 ICMP 表。"})
	}
	if res.SnapCut > 0 && res.SnapCut == res.Packets {
		out = append(out, Finding{"info", "只抓了包头", "抓包时选了「只抓包头」：统计和健康分析完整，但看不到内容（TLS 域名可能缺失）。"})
	}
	if res.Truncated {
		out = append(out, Finding{"info", "只分析了前 300 万个包", "文件更大的部分请下载后用 Wireshark 查看。"})
	}
	return out
}

// ---- helpers ----

func canon(p uint8, x, y netip.AddrPort) pcFlowKey {
	if x.Compare(y) < 0 {
		return pcFlowKey{p, x, y}
	}
	return pcFlowKey{p, y, x}
}

func seqLE(a, b uint32) bool { return int32(a-b) <= 0 }
func seqGT(a, b uint32) bool { return int32(a-b) > 0 }

func tcpMSS(opts []byte) int {
	for i := 0; i < len(opts); {
		switch opts[i] {
		case 0:
			return 0
		case 1:
			i++
			continue
		}
		if i+1 >= len(opts) || opts[i+1] < 2 {
			return 0
		}
		if opts[i] == 2 && opts[i+1] == 4 && i+4 <= len(opts) {
			return int(binary.BigEndian.Uint16(opts[i+2 : i+4]))
		}
		i += int(opts[i+1])
	}
	return 0
}

// tlsSNI pulls server_name out of a ClientHello in the first data segment.
func tlsSNI(b []byte) string {
	if len(b) < 43 || b[0] != 0x16 || b[5] != 0x01 {
		return ""
	}
	p := 9 + 2 + 32 // record hdr 5 + handshake hdr 4, version 2, random 32
	if p >= len(b) {
		return ""
	}
	p += 1 + int(b[p]) // session id
	if p+2 > len(b) {
		return ""
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:])) // cipher suites
	if p >= len(b) {
		return ""
	}
	p += 1 + int(b[p]) // compression
	if p+2 > len(b) {
		return ""
	}
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	for p+4 <= len(b) && p+4 <= end {
		typ, l := binary.BigEndian.Uint16(b[p:]), int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if typ == 0 && p+5 <= len(b) {
			n := int(binary.BigEndian.Uint16(b[p+3:]))
			if p+5+n <= len(b) && b[p+2] == 0 {
				return strings.ToLower(string(b[p+5 : p+5+n]))
			}
			return ""
		}
		p += l
	}
	return ""
}

func httpHost(b []byte) string {
	s := string(b[:min(len(b), 2048)])
	if !(strings.HasPrefix(s, "GET ") || strings.HasPrefix(s, "POST ") || strings.HasPrefix(s, "HEAD ") || strings.HasPrefix(s, "PUT ") || strings.HasPrefix(s, "OPTIONS ")) {
		return ""
	}
	for _, line := range strings.Split(s, "\r\n")[1:] {
		if len(line) > 5 && strings.EqualFold(line[:5], "host:") {
			return strings.ToLower(strings.TrimSpace(line[5:]))
		}
	}
	return ""
}

func dnsQuestion(b []byte) (string, string) {
	if binary.BigEndian.Uint16(b[4:6]) == 0 {
		return "", ""
	}
	p := 12
	var labels []string
	for p < len(b) {
		l := int(b[p])
		if l == 0 {
			p++
			break
		}
		if l&0xc0 != 0 || p+1+l > len(b) {
			return strings.Join(labels, "."), ""
		}
		labels = append(labels, string(b[p+1:p+1+l]))
		p += 1 + l
	}
	name := strings.ToLower(strings.Join(labels, "."))
	if p+2 > len(b) {
		return name, ""
	}
	return name, dnsTypeName(binary.BigEndian.Uint16(b[p:]))
}

func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS"
	case 64:
		return "SVCB"
	case 2:
		return "NS"
	case 6:
		return "SOA"
	}
	return fmt.Sprintf("TYPE%d", t)
}

func dnsRcode(c byte) string {
	switch c {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE%d", c)
}

func icmpKind(proto, typ, code uint8) string {
	if proto == 1 {
		switch typ {
		case 0:
			return "回显应答（ping 回复）"
		case 8:
			return "回显请求（ping）"
		case 11:
			return "TTL 超时"
		case 3:
			switch code {
			case 0:
				return "不可达：网络"
			case 1:
				return "不可达：主机"
			case 3:
				return "不可达：端口"
			case 4:
				return "不可达：需要分片（MTU）"
			case 13:
				return "不可达：被管理禁止"
			}
			return fmt.Sprintf("不可达（代码 %d）", code)
		case 5:
			return "重定向"
		}
		return fmt.Sprintf("ICMP 类型 %d", typ)
	}
	switch typ {
	case 1:
		return "不可达（ICMPv6）"
	case 2:
		return "不可达：包过大（ICMPv6 MTU）"
	case 3:
		return "TTL 超时（ICMPv6）"
	case 128, 129:
		return "ping（ICMPv6）"
	case 133, 134, 135, 136:
		return "" // neighbour discovery noise
	}
	return fmt.Sprintf("ICMPv6 类型 %d", typ)
}

var wellKnown = map[uint16]string{
	20: "FTP 数据", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
	123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "SMB", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
	500: "IPsec IKE", 514: "Syslog", 548: "AFP", 554: "RTSP", 587: "SMTP", 853: "DoT", 993: "IMAPS", 995: "POP3S", 1194: "OpenVPN",
	1883: "MQTT", 1900: "SSDP", 3074: "Xbox Live", 3389: "远程桌面", 3478: "STUN", 3479: "STUN", 4500: "IPsec NAT-T", 5222: "XMPP / Telegram",
	5223: "Apple 推送", 5228: "Google 推送", 5353: "mDNS", 5355: "LLMNR", 5900: "VNC", 6881: "BitTorrent", 7080: "Wharf 面板",
	8006: "PVE", 8080: "HTTP 代理 / Web", 8443: "HTTPS 备用", 8883: "MQTT TLS", 9000: "Web", 19302: "Google STUN",
	27015: "Steam", 32400: "Plex", 51820: "WireGuard",
}

func serviceName(proto uint8, sp, dp uint16) string {
	p := "TCP"
	if proto == 17 {
		p = "UDP"
	}
	pick := func(port uint16) (string, bool) {
		if proto == 17 && port == 443 {
			return "QUIC / HTTP3", true
		}
		n, ok := wellKnown[port]
		return n, ok
	}
	lo, hi := min(sp, dp), max(sp, dp)
	if n, ok := pick(lo); ok {
		return n
	}
	if n, ok := pick(hi); ok {
		return n
	}
	return fmt.Sprintf("%s %d", p, lo)
}

func sortedCounts(m map[string]*NamedCount, limit int) []NamedCount {
	out := make([]NamedCount, 0, len(m))
	for _, v := range m {
		if v.Name == "" {
			continue
		}
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Packets > out[j].Packets
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func mean(v []float64) float64 {
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func percentile(v []float64, p float64) float64 {
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	i := int(float64(len(c)-1) * p / 100)
	return c[i]
}

func round3(v float64) float64 { return float64(int64(v*1000+0.5)) / 1000 }
