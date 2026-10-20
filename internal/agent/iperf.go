package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// iperf3: the router can test against a device running `iperf3 -s`, or itself act as a
// server for a limited time (each run is `iperf3 -s -1 -J`, restarted until the deadline)
// so phones and computers can test against it; finished runs are kept for the panel.

type IperfResult struct {
	TS        int64   `json:"ts"`
	Peer      string  `json:"peer"`
	Proto     string  `json:"proto"`     // TCP | UDP
	Direction string  `json:"direction"` // "up" = device → router, "down" = router → device (server view); client view: "send" / "recv"
	Secs      float64 `json:"secs"`
	BPS       float64 `json:"bps"` // received rate (what actually arrived)
	SentBPS   float64 `json:"sent_bps"`
	Retrans   int     `json:"retransmits"`
	Jitter    float64 `json:"jitter_ms,omitempty"`
	Lost      float64 `json:"lost_percent,omitempty"`
	Streams   int     `json:"streams"`
	Error     string  `json:"error,omitempty"`
}

type iperfJSON struct {
	Start struct {
		Connected []struct {
			RemoteHost string `json:"remote_host"`
		} `json:"connected"`
		TestStart struct {
			Protocol   string `json:"protocol"`
			NumStreams int    `json:"num_streams"`
			Reverse    int    `json:"reverse"`
			Duration   int    `json:"duration"`
		} `json:"test_start"`
	} `json:"start"`
	End struct {
		SumSent struct {
			Secs    float64 `json:"seconds"`
			BPS     float64 `json:"bits_per_second"`
			Retrans int     `json:"retransmits"`
		} `json:"sum_sent"`
		SumReceived struct {
			Secs float64 `json:"seconds"`
			BPS  float64 `json:"bits_per_second"`
		} `json:"sum_received"`
		Sum struct { // UDP
			Secs   float64 `json:"seconds"`
			BPS    float64 `json:"bits_per_second"`
			Jitter float64 `json:"jitter_ms"`
			Lost   float64 `json:"lost_percent"`
		} `json:"sum"`
	} `json:"end"`
	Error string `json:"error"`
}

func (j *iperfJSON) result() IperfResult {
	r := IperfResult{TS: time.Now().Unix(), Proto: strings.ToUpper(j.Start.TestStart.Protocol), Streams: j.Start.TestStart.NumStreams, Error: j.Error}
	if len(j.Start.Connected) > 0 {
		r.Peer = strings.TrimPrefix(j.Start.Connected[0].RemoteHost, "::ffff:")
	}
	if r.Proto == "UDP" {
		// the server side reports the rate in sum_received and only jitter / loss in sum
		r.Secs, r.Jitter, r.Lost = j.End.Sum.Secs, j.End.Sum.Jitter, j.End.Sum.Lost
		r.BPS = max(j.End.Sum.BPS, j.End.SumReceived.BPS)
		r.SentBPS = max(j.End.SumSent.BPS, r.BPS)
	} else {
		r.Secs, r.BPS, r.SentBPS, r.Retrans = j.End.SumReceived.Secs, j.End.SumReceived.BPS, j.End.SumSent.BPS, j.End.SumSent.Retrans
	}
	if r.Error != "" {
		r.Error = iperfError(r.Error)
	}
	return r
}

func iperfError(e string) string {
	switch {
	case strings.Contains(e, "Connection refused"):
		return "对方没有运行 iperf3 服务端（iperf3 -s），或端口不对"
	case strings.Contains(e, "No route to host"), strings.Contains(e, "timed out"), strings.Contains(e, "Connection timed out"):
		return "连不上对方：设备离线或防火墙拦截了 iperf3 端口"
	case strings.Contains(e, "server is busy"):
		return "对方 iperf3 正忙（另一个测试正在进行）"
	case strings.Contains(e, "Address in use"), strings.Contains(e, "address already in use"):
		return "端口已被占用"
	}
	return e
}

func IperfClient(req DiagReq) (*IperfResult, error) {
	host, err := validHost(req.Target)
	if err != nil {
		return nil, err
	}
	secs := clamp(req.Secs, 3, 30, 8)
	args := []string{"-c", host, "-J", "-t", strconv.Itoa(secs), "-p", strconv.Itoa(clamp(req.Port, 1, 65535, 5201)),
		"-P", strconv.Itoa(clamp(req.Streams, 1, 8, 1)), "--connect-timeout", "3000"}
	if req.Reverse {
		args = append(args, "-R")
	}
	if req.Mode == "udp" {
		rate := strings.ToUpper(strings.TrimSpace(req.Rate))
		if rate == "" {
			rate = "100M"
		}
		if _, err := strconv.ParseFloat(strings.TrimRight(rate, "KMG"), 64); err != nil {
			return nil, errors.New("UDP 带宽格式如 100M、1G")
		}
		args = append(args, "-u", "-b", rate)
	}
	out, _ := run(time.Duration(secs+15)*time.Second, "iperf3", args...)
	var j iperfJSON
	if err := json.Unmarshal(out, &j); err != nil {
		return nil, errors.New("iperf3 没有返回结果（路由器上未安装 iperf3？）")
	}
	r := j.result()
	r.Direction = "send" // router → device
	if req.Reverse {
		r.Direction = "recv"
	}
	if r.Peer == "" {
		r.Peer = host
	}
	return &r, nil
}

// ---- temporary server ----

type IperfServer struct {
	Running bool          `json:"running"`
	Port    int           `json:"port"`
	Until   int64         `json:"until"`
	Results []IperfResult `json:"results"`
	Error   string        `json:"error,omitempty"`
}

var iperfSrv struct {
	sync.Mutex
	state  IperfServer
	cancel context.CancelFunc
}

func IperfServerStatus() IperfServer {
	iperfSrv.Lock()
	defer iperfSrv.Unlock()
	s := iperfSrv.state
	s.Results = append([]IperfResult{}, s.Results...)
	return s
}

func IperfServerStart(port, minutes int) (IperfServer, error) {
	port = clamp(port, 1024, 65535, 5201)
	iperfSrv.Lock()
	if iperfSrv.state.Running {
		// extend instead of starting a second one
		iperfSrv.state.Until = time.Now().Add(time.Duration(minutes) * time.Minute).Unix()
		iperfSrv.Unlock()
		return IperfServerStatus(), nil
	}
	if _, err := exec.LookPath("iperf3"); err != nil {
		iperfSrv.Unlock()
		return IperfServer{}, errors.New("路由器上没有 iperf3（opkg install iperf3）")
	}
	ctx, cancel := context.WithCancel(context.Background())
	iperfSrv.cancel = cancel
	iperfSrv.state = IperfServer{Running: true, Port: port, Until: time.Now().Add(time.Duration(minutes) * time.Minute).Unix(), Results: iperfSrv.state.Results}
	iperfSrv.Unlock()
	go iperfServe(ctx, port)
	return IperfServerStatus(), nil
}

func IperfServerStop() {
	iperfSrv.Lock()
	defer iperfSrv.Unlock()
	if iperfSrv.cancel != nil {
		iperfSrv.cancel()
	}
}

func iperfServe(ctx context.Context, port int) {
	ctx, stop := context.WithCancel(ctx)
	defer func() {
		stop()
		iperfSrv.Lock()
		iperfSrv.state.Running = false
		iperfSrv.cancel = nil
		iperfSrv.Unlock()
	}()
	go func() { // the deadline can be extended while running
		for ctx.Err() == nil {
			iperfSrv.Lock()
			until := iperfSrv.state.Until
			iperfSrv.Unlock()
			if time.Now().Unix() >= until {
				stop()
				return
			}
			time.Sleep(time.Second)
		}
	}()
	// one long-running server; with -J it prints one JSON document per finished test
	cmd := exec.CommandContext(ctx, "iperf3", "-s", "-J", "-p", strconv.Itoa(port))
	out, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		iperfSrv.Lock()
		iperfSrv.state.Error = err.Error()
		iperfSrv.Unlock()
		return
	}
	defer func() { _ = cmd.Wait() }()
	dec := json.NewDecoder(out)
	for {
		var j iperfJSON
		if err := dec.Decode(&j); err != nil {
			return // process ended (deadline, stop, or it could not bind)
		}
		if len(j.Start.Connected) == 0 {
			if j.Error != "" && ctx.Err() == nil && !strings.Contains(j.Error, "interrupt") {
				iperfSrv.Lock()
				iperfSrv.state.Error = iperfError(j.Error)
				iperfSrv.Unlock()
			}
			continue
		}
		r := j.result()
		r.Direction = "up" // device sends, router receives
		if j.Start.TestStart.Reverse == 1 {
			r.Direction = "down"
			r.BPS = max(r.BPS, j.End.SumSent.BPS) // the server may only know what it sent
		}
		iperfSrv.Lock()
		iperfSrv.state.Error = ""
		iperfSrv.state.Results = append([]IperfResult{r}, iperfSrv.state.Results...)
		if len(iperfSrv.state.Results) > 20 {
			iperfSrv.state.Results = iperfSrv.state.Results[:20]
		}
		iperfSrv.Unlock()
	}
}
