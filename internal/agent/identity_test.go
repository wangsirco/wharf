package agent

import "testing"

func TestDHCPFingerprint(t *testing.T) {
	fps.m = map[string]*DeviceFP{}
	d := NewDNSLog("", nil)
	for _, l := range []string{
		"Oct 31 10:00:00 dnsmasq-dhcp[1]: 1185352710 available DHCP range: 192.168.1.100 -- 192.168.1.249",
		"Oct 31 10:00:00 dnsmasq-dhcp[1]: 1185352710 vendor class: android-dhcp-14",
		"Oct 31 10:00:00 dnsmasq-dhcp[1]: 1185352710 client provides name: Pixel-8",
		"Oct 31 10:00:00 dnsmasq-dhcp[1]: 1185352710 DHCPREQUEST(br-lan) 192.168.1.20 AA:8F:FE:6D:D7:E7",
		"Oct 31 10:00:00 dnsmasq-dhcp[1]: 1185352710 tags: lan, br-lan",
		"Oct 31 10:00:00 dnsmasq-dhcp[1]: 1185352710 DHCPACK(br-lan) 192.168.1.20 aa:8f:fe:6d:d7:e7 Pixel-8",
		"Oct 31 10:00:00 dnsmasq-dhcp[1]: 1185352710 requested options: 1:netmask, 3:router, 6:dns-server, 15:domain-name, ",
		"Oct 31 10:00:00 dnsmasq-dhcp[1]: 1185352710 requested options: 26:mtu, 28:broadcast, 51:lease-time, 58:T1, ",
		"Oct 31 10:00:00 dnsmasq-dhcp[1]: 1185352710 requested options: 59:T2, 43:vendor-encap, 114, 108",
		"Oct 31 10:00:00 dnsmasq-dhcp[1]: 1185352710 next server: 192.168.1.1",
		"Oct 31 10:00:01 dnsmasq[1]: 1592 192.168.1.20/53321 query[A] www.youtube.com from 192.168.1.20",
	} {
		d.handle(l)
	}
	p := Fingerprints()["aa:8f:fe:6d:d7:e7"]
	if p.DHCPOpts != "1,3,6,15,26,28,51,58,59,43,114,108" || p.DHCPVendor != "android-dhcp-14" || p.DHCPName != "Pixel-8" {
		t.Fatalf("%+v", p)
	}
}
