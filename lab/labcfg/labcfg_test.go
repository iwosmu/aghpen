package labcfg

import (
	"testing"
	"time"
)

func TestMurmur3KnownVectors(t *testing.T) {
	// Reference values of MurmurHash3_x86_32.
	cases := []struct {
		in   string
		seed uint32
		want uint32
	}{
		{"", 0, 0},
		{"", 1, 0x514e28b7},
		{"hello", 0, 0x248bfa47},
		{"hello, world", 0, 0x149bbb7f},
		{"The quick brown fox jumps over the lazy dog", 0, 0x2e4ff723},
	}
	for _, c := range cases {
		if got := Murmur3([]byte(c.in), c.seed); got != c.want {
			t.Errorf("Murmur3(%q, %d) = %#x, want %#x", c.in, c.seed, got, c.want)
		}
	}
}

func TestFaviconIsStableAndDistinct(t *testing.T) {
	a, b, c := Favicon("hikvision"), Favicon("hikvision"), Favicon("mikrotik")
	if string(a) != string(b) {
		t.Fatal("same seed gave different icons")
	}
	if string(a) == string(c) {
		t.Fatal("different seeds gave the same icon")
	}
	if len(a) != 6+16+40+16*16*4+64 {
		t.Fatalf("unexpected icon size %d", len(a))
	}
	if a[0] != 0 || a[2] != 1 || a[4] != 1 {
		t.Fatal("not an ICO header")
	}
	if FaviconMMH3(a) == FaviconMMH3(c) {
		t.Fatal("hash collision between seeds")
	}
}

func TestScheduleAvail(t *testing.T) {
	a := &Avail{Kind: "schedule", PeriodSec: 360, UpFromSec: 0, UpToSec: 180}
	base := time.Unix(360*1000, 0)
	if !a.UpAt(base) || !a.UpAt(base.Add(179*time.Second)) {
		t.Fatal("expected up in the first half")
	}
	if a.UpAt(base.Add(180*time.Second)) || a.UpAt(base.Add(359*time.Second)) {
		t.Fatal("expected down in the second half")
	}
	at, ok := a.NextChange(base.Add(10*time.Second), 10*time.Minute)
	if !ok || !at.Equal(base.Add(180*time.Second)) {
		t.Fatalf("NextChange = %v %v", at, ok)
	}
}

func TestFlapAvailIsAboutHalfAndSlotStable(t *testing.T) {
	a := &Avail{Kind: "flap", Seed: "flapper-1", SlotSec: 60}
	up := 0
	const slots = 2000
	for i := 0; i < slots; i++ {
		t0 := time.Unix(int64(1_700_000_040+i*60), 0)
		v := a.UpAt(t0)
		if a.UpAt(t0.Add(59*time.Second)) != v && t0.Unix()%60 == 0 {
			t.Fatalf("state changed inside slot %d", i)
		}
		if v {
			up++
		}
	}
	if share := float64(up) / slots; share < 0.45 || share > 0.55 {
		t.Fatalf("flapper up share %.3f, want about 0.5", share)
	}
	var nilAvail *Avail
	if !nilAvail.UpAt(time.Now()) {
		t.Fatal("nil availability must mean always up")
	}
}
