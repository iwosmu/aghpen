package model

import "testing"

func TestVendorForMAC(t *testing.T) {
	for mac, want := range map[string]string{
		"5A:B7:8C:5E:04:F9": "", "02:42:0A:42:00:1E": "", "AE:00:00:00:00:01": "", "f6:00:00:00:00:01": "",
		"00:1B:21:AA:BB:CC": "Intel", "": "Intel",
	} {
		if got := VendorForMAC(mac, "Intel"); got != want {
			t.Errorf("%q: %q, want %q", mac, got, want)
		}
	}
}
