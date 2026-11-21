package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConvert(t *testing.T) {
	dir := t.TempDir()
	sweep := filepath.Join(dir, "sweep.xml")
	tcp := filepath.Join(dir, "tcp.xml")
	os.WriteFile(sweep, []byte(`<nmaprun>
<host endtime="100"><status state="up" reason="arp-response"/><address addr="10.0.0.2" addrtype="ipv4"/></host>
<host><status state="down" reason="no-response"/><address addr="10.0.0.3" addrtype="ipv4"/></host>
</nmaprun>`), 0o644)
	os.WriteFile(tcp, []byte(`<nmaprun>
<host endtime="200"><status state="up" reason="arp-response"/><address addr="10.0.0.2" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="10.3" method="probed" conf="10"/></port></ports></host>
</nmaprun>`), 0o644)

	hosts, err := convert([]string{sweep, tcp}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].IP != "10.0.0.2" || len(hosts[0].Services) != 1 || hosts[0].Services[0].Version != "10.3" {
		t.Fatalf("hosts: %+v", hosts)
	}
	// The time of the first scan that saw the host stays.
	if hosts[0].ObservedAt.Unix() != 100 {
		t.Fatalf("observed at %v", hosts[0].ObservedAt)
	}
	all, err := convert([]string{sweep, tcp}, false)
	if err != nil || len(all) != 2 {
		t.Fatalf("with down hosts: %d, %v", len(all), err)
	}
	if _, err := convert([]string{filepath.Join(dir, "missing.xml")}, true); err == nil {
		t.Fatal("a missing file must fail")
	}
}
