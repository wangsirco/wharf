package panel

import "testing"

func TestIdentifyDevice(t *testing.T) {
	a := &App{}
	a.hints.m = map[string]map[string]int64{}
	cases := []struct{ mac, host, typ, os string }{
		{"38:9c:b2:a9:73:e6", "iWShengiPhone15", "手机", "iOS"},
		{"58:66:6d:5f:3b:f3", "iWSheng16ProMax", "手机", ""}, // Apple OUI but not random: hostname has no keyword
		{"46:cb:d5:8a:d1:36", "iWSheng-s-Galaxy-S24-Ultra", "手机", "Android"},
		{"b4:6b:fc:8e:cc:e5", "DESKTOP-DHC8F6G", "电脑", "Windows"},
		{"18:7f:88:96:57:c8", "RingFloodlightCam-c8", "摄像头", ""},
		{"e0:a2:5a:11:1a:6b", "mxiang-camera-mwc10_miap1A6B", "摄像头", ""},
		{"d8:e3:5e:67:6b:9c", "LGwebOSTV", "电视/投屏", ""},
		{"34:fc:99:a4:7e:bd", "Samsung-Refrigerator", "智能家电", ""},
		{"bc:24:11:d6:b8:5e", "", "虚拟机", "Linux"},
		{"1e:4d:73:93:36:16", "", "手机", ""}, // randomised MAC
		{"bc:24:11:80:b5:13", "iWSheng-Nas", "NAS/服务器", "Linux"},
		{"ac:3f:a4:00:00:01", "ABR-AL60", "手机", "Android"},
		{"00:0e:6d:00:00:01", "", "未知", ""}, // Murata: "Manufacturing" must not match "ring"
	}
	for _, c := range cases {
		id := a.identifyDevice(c.mac, c.host, "")
		if id.Type != c.typ || (c.os != "" && id.OS != c.os) {
			t.Errorf("%s %s: got %s/%s (%s, vendor %q)", c.mac, c.host, id.Type, id.OS, id.By, id.Vendor)
		}
	}
	if id := a.identifyDevice("bc:24:11:d6:b8:5e", "", "打印机"); id.Type != "打印机" || id.By != "manual" {
		t.Errorf("manual override: %+v", id)
	}
}

func TestVMNaming(t *testing.T) {
	a := &App{}
	id := a.identifyDevice("bc:24:11:14:71:e6", "", "")
	if id.VMTag != "PVE 虚拟机" || displayName("", "", "", id) != "未命名虚拟机" {
		t.Fatalf("unnamed pve guest: %+v", id)
	}
	id = a.identifyDevice("bc:24:11:80:b5:13", "iWSheng-Nas", "")
	if id.VMTag != "PVE 虚拟机" || displayName("", "", "iWSheng-Nas", id) != "iWSheng-Nas" {
		t.Fatalf("named pve guest: %+v", id)
	}
	a.pve.byMAC = map[string]pveGuest{"bc:24:11:14:71:e6": {VMID: 105, Name: "ubuntu-dev", Kind: "qemu"}}
	id = a.identifyDevice("bc:24:11:14:71:e6", "", "")
	if id.VMTag != "PVE 虚拟机 #105" || displayName("", "", "", id) != "ubuntu-dev" {
		t.Fatalf("pve api guest: %+v", id)
	}
	if !pveTokenRe.MatchString("owp@pve!panel=8b5c1f7e-2d4a-4e31-9a0b-6f1c2d3e4f50") {
		t.Fatal("token regex")
	}
}
