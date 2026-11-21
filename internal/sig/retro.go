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

// RetroHunt runs the signatures of one YAML text against stored observations.
// It reads stored data only and sends no packet. Path rules use the paths
// that were fetched when the observation was made; when a signature needs a
// path that an observation does not have, the result says so in
// MissingPaths, Incomplete and Notes, because such an observation cannot
// match on that rule.
func RetroHunt(sigYAML string, observations []model.ServiceObservation) model.RetroHuntResult {
	start := time.Now()
	res := model.RetroHuntResult{Hits: []model.RetroHit{}, MissingPaths: []string{}, Notes: []string{}}
	sigs, val := Parse(sigYAML)
	if !val.OK {
		for _, is := range val.Issues {
			if is.Level == "error" {
				res.Notes = append(res.Notes, fmt.Sprintf("Sygnatura odrzucona: %s: %s", is.Path, is.Message))
			}
		}
		res.TookMs = time.Since(start).Milliseconds()
		return res
	}
	for _, s := range sigs {
		s.Enabled = true
	}
	st := buildSet(sigs)

	missing := map[string]int{}
	for i := range observations {
		obs := &observations[i]
		res.Scanned++
		v := newView(&obs.Result, st, nil)
		incomplete := false
		if v.http != nil {
			for _, path := range st.paths {
				if _, ok := v.paths[path]; !ok {
					missing[path]++
					incomplete = true
				}
			}
		}
		if incomplete {
			res.Incomplete++
		}
		for _, s := range st.enabled {
			m, ok := v.evalSig(s)
			if !ok {
				continue
			}
			hit := model.RetroHit{ServiceID: obs.ServiceID, Port: obs.Result.Port, RunID: obs.RunID, At: obs.At, Match: m}
			if v.http != nil {
				hit.URL = v.http.URL
				if u, err := url.Parse(v.http.URL); err == nil && net.ParseIP(u.Hostname()) != nil {
					hit.IP = u.Hostname()
				}
			}
			res.Hits = append(res.Hits, hit)
		}
	}
	res.MissingPaths = sortedKeys(missing)
	sort.Strings(res.MissingPaths)
	for _, path := range res.MissingPaths {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"Sygnatura potrzebuje ścieżki %s, której nie pobrano w %d z %d obserwacji. Reguły path nie mogły tam zadziałać; wynik dla tych usług opiera się tylko na pozostałych regułach. Pełny wynik da nowy skan z włączonymi ścieżkami sygnatur.",
			path, missing[path], res.Scanned))
	}
	if len(st.paths) > 0 && len(res.MissingPaths) == 0 && res.Scanned > 0 {
		res.Notes = append(res.Notes, "Wszystkie ścieżki sygnatury ("+strings.Join(st.paths, ", ")+") były pobrane w zapisanych obserwacjach.")
	}
	res.TookMs = time.Since(start).Milliseconds()
	res.PacketsSent = 0
	return res
}
