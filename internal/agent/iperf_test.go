package agent

import (
	"encoding/json"
	"testing"
)

func TestIperfResultUDPServer(t *testing.T) {
	// trimmed iperf3 3.16 server-side UDP output: the rate lives in sum_received
	raw := `{"start":{"connected":[{"remote_host":"::ffff:192.168.1.185"}],"test_start":{"protocol":"UDP","num_streams":1,"reverse":0}},
	"end":{"sum":{"seconds":2,"bits_per_second":0,"jitter_ms":0.06,"lost_percent":0.26},
	"sum_sent":{"bits_per_second":0},"sum_received":{"seconds":2,"bits_per_second":299000000}}}`
	var j iperfJSON
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		t.Fatal(err)
	}
	r := j.result()
	if r.Peer != "192.168.1.185" || r.BPS != 299000000 || r.Lost != 0.26 || r.Proto != "UDP" {
		t.Fatalf("%+v", r)
	}
}
