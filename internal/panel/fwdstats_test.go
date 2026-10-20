package panel

import "testing"

func TestConnClass(t *testing.T) {
	cases := []struct {
		up, down, secs int64
		want           string
	}{
		{60, 60, 0, "probe"},           // SYN / RST
		{300, 40, 1, "probe"},          // server banner, client sent nothing
		{3200, 2600, 4, "short"},       // a failed SSH password try
		{40000, 9000, 1200, "long"},    // interactive session
		{20 << 20, 300000, 90, "bulk"}, // file download
		{90000, 30000, 20, "session"},  // web page
	}
	for _, c := range cases {
		if got := connClass(c.up, c.down, c.secs); got != c.want {
			t.Errorf("%v: got %s want %s", c, got, c.want)
		}
	}
	if !scannerOrg("Censys, Inc.") || !scannerOrg("The Shadowserver Foundation") || scannerOrg("Spark New Zealand") {
		t.Error("scannerOrg")
	}
	if !isPrivateIP("192.168.1.5") || !isPrivateIP("172.20.1.1") || isPrivateIP("172.32.1.1") || isPrivateIP("8.8.8.8") {
		t.Error("isPrivateIP")
	}
}
