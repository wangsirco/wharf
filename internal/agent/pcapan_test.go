package agent

import (
	"encoding/json"
	"os"
	"testing"
)

// The capture from the 2026-10 Telegram Singapore incident: 100 SYNs, 39 SYN-ACKs.
func TestAnalyseIncidentCapture(t *testing.T) {
	f, err := os.Open("../../docs/incidents/2026-10-telegram-sg/raw/dc5.pcap")
	if err != nil {
		t.Skip("incident capture not present")
	}
	defer f.Close()
	res, err := analysePcap(f)
	if err != nil {
		t.Fatal(err)
	}
	if res.TCP.Handshakes == 0 || res.TCP.Failed == 0 {
		t.Fatalf("handshakes %d failed %d", res.TCP.Handshakes, res.TCP.Failed)
	}
	if res.Findings[0].Level != "error" {
		t.Fatalf("first finding %+v", res.Findings[0])
	}
	if testing.Verbose() {
		b, _ := json.MarshalIndent(map[string]any{"packets": res.Packets, "tcp": res.TCP, "findings": res.Findings, "protocols": res.Protocols, "first_convs": res.Convs[:3]}, "", " ")
		t.Log(string(b))
	}
}
