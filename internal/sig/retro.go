package sig

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Hunter is a streaming retro-hunt: it checks one signature text against
// stored observations one at a time, so the caller never holds them all in
// memory. It sends no packet; it reads only what was stored.
//
//	h, val := sig.NewHunter(yaml)
//	if !val.OK { ... }
//	for each stored observation { h.Add(&obs, ip) }
//	res := h.Result()
type Hunter struct {
	st      *set
	res     model.RetroHuntResult
	missing map[string]int
	start   time.Time
	// MaxHits bounds the hit list (0: no limit). TotalHits still counts all.
	MaxHits int
}

// NewHunter validates and compiles the signature text. With an invalid or
// unsafe signature it returns a nil Hunter and the validation result.
func NewHunter(sigYAML string) (*Hunter, model.SignatureValidation) {
	sigs, val := Parse(sigYAML)
	if !val.OK {
		return nil, val
	}
	for _, s := range sigs {
		s.Enabled = true
	}
	return &Hunter{
		st:      buildSet(sigs),
		res:     model.RetroHuntResult{Hits: []model.RetroHit{}, MissingPaths: []string{}, Notes: []string{}},
		missing: map[string]int{},
		start:   time.Now(),
	}, val
}

// Add checks one stored observation. ip is the address of the service when
// the caller knows it; otherwise the IP is taken from the stored URL when its
// host is an address (retro-hunt never resolves names).
func (h *Hunter) Add(obs *model.ServiceObservation, ip string) {
	h.res.Scanned++
	v := newView(&obs.Result, h.st, nil)
	if v.http != nil {
		incomplete := false
		for _, path := range h.st.paths {
			if _, ok := v.paths[path]; !ok {
				h.missing[path]++
				incomplete = true
			}
		}
		if incomplete {
			h.res.Incomplete++
		}
	}
	for _, s := range h.st.enabled {
		m, ok := v.evalSig(s)
		if !ok {
			continue
		}
		h.res.TotalHits++
		if h.MaxHits > 0 && len(h.res.Hits) >= h.MaxHits {
			h.res.Truncated = true
			continue
		}
		hit := model.RetroHit{ServiceID: obs.ServiceID, IP: ip, Port: obs.Result.Port, RunID: obs.RunID, At: obs.At, Match: m}
		if v.http != nil {
			hit.URL = v.http.URL
			if hit.IP == "" {
				if u, err := url.Parse(v.http.URL); err == nil && net.ParseIP(u.Hostname()) != nil {
					hit.IP = u.Hostname()
				}
			}
		}
		h.res.Hits = append(h.res.Hits, hit)
	}
}

// Result returns the result so far, with the notes in Polish.
func (h *Hunter) Result() model.RetroHuntResult {
	res := h.res
	res.Notes = []string{}
	res.MissingPaths = sortedKeys(h.missing)
	sort.Strings(res.MissingPaths)
	for _, path := range res.MissingPaths {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"Sygnatura potrzebuje ścieżki %s, której nie pobrano w %d z %d obserwacji. Reguły path nie mogły tam zadziałać; wynik dla tych usług opiera się tylko na pozostałych regułach. Pełny wynik da nowy skan z włączonymi ścieżkami sygnatur.",
			path, h.missing[path], res.Scanned))
	}
	if len(h.st.paths) > 0 && len(res.MissingPaths) == 0 && res.Scanned > 0 {
		res.Notes = append(res.Notes, "Wszystkie ścieżki sygnatury ("+strings.Join(h.st.paths, ", ")+") były pobrane w zapisanych obserwacjach.")
	}
	if res.Truncated {
		res.Notes = append(res.Notes, fmt.Sprintf("Lista pokazuje pierwsze %d z %d trafień.", len(res.Hits), res.TotalHits))
	}
	res.TookMs = time.Since(h.start).Milliseconds()
	res.PacketsSent = 0
	return res
}

// RetroHunt checks a signature text against stored observations. It sends no
// packet. When the signature needs an extra path that an observation never
// fetched, the result says so in MissingPaths and Notes.
func RetroHunt(sigYAML string, observations []model.ServiceObservation) model.RetroHuntResult {
	start := time.Now()
	h, val := NewHunter(sigYAML)
	if h == nil {
		res := model.RetroHuntResult{Hits: []model.RetroHit{}, MissingPaths: []string{}, Notes: []string{}}
		for _, is := range val.Issues {
			if is.Level == "error" {
				res.Notes = append(res.Notes, fmt.Sprintf("Sygnatura odrzucona: %s: %s", is.Path, is.Message))
			}
		}
		res.TookMs = time.Since(start).Milliseconds()
		return res
	}
	for i := range observations {
		h.Add(&observations[i], "")
	}
	return h.Result()
}
