package sigsuggest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/sig"
	"github.com/iwosmu/aghpen/internal/store"
)

// ErrNotFound means the service has no stored observation.
var ErrNotFound = errors.New("not found")

// Tuning of the selection.
const (
	MaxRules      = 6    // rules in one suggested signature
	MaxBodyRules  = 3    // body rules among them
	MaxShare      = 0.05 // a feature seen in more than 5 % of the other services is common
	MinConfidence = 0.6  // min_confidence of the suggested signature
	HistoryDepth  = 5    // observations of the example compared for stability
	MaxHitsShown  = 50
)

// RuleExplain is one rule of the suggestion with the reason it was chosen.
type RuleExplain struct {
	Kind        string  `json:"kind"`
	Feature     string  `json:"feature"`
	Rule        string  `json:"rule"`
	Weight      float64 `json:"weight"`
	DF          int     `json:"df"`     // other services that have this feature
	Others      int     `json:"others"` // other services it was compared with
	Explanation string  `json:"explanation"`
}

// Suggestion is the answer of POST /signatures/suggest.
type Suggestion struct {
	OK            bool                      `json:"ok"`
	Message       string                    `json:"message"`
	ServiceID     int64                     `json:"service_id"`
	Target        string                    `json:"target"`
	Slug          string                    `json:"slug"`
	Name          string                    `json:"name"`
	YAML          string                    `json:"yaml"`
	Rules         []RuleExplain             `json:"rules"`
	Rejected      []Rejected                `json:"rejected"`
	Validation    model.SignatureValidation `json:"validation"`
	RetroHunt     *model.RetroHuntResult    `json:"retro_hunt"`
	MatchesTarget bool                      `json:"matches_target"`
	OtherMatches  int                       `json:"other_matches"`
	Candidates    int                       `json:"candidates"`
	OthersHTTP    int                       `json:"others_http"`
	OthersTLS     int                       `json:"others_tls"`
	// LookAlikes counts other services that share at least half of the
	// candidate features of the example: instances of the same product. They
	// are what the signature is for, so they do not count against rarity.
	LookAlikes int   `json:"look_alikes"`
	History    int   `json:"history"` // observations of the example compared for stability
	TookMs     int64 `json:"took_ms"`
}

// Suggester proposes signatures from stored observations.
type Suggester struct {
	st  *store.Store
	log *slog.Logger
}

// New returns a Suggester.
func New(st *store.Store, logger *slog.Logger) *Suggester {
	if logger == nil {
		logger = slog.Default()
	}
	return &Suggester{st: st, log: logger}
}

type scored struct {
	f      Feature
	df     int
	others int
	look   int
	weight float64
}

// Suggest proposes a signature for "things like" the given service.
func (s *Suggester) Suggest(ctx context.Context, serviceID int64) (Suggestion, error) {
	start := time.Now()
	out := Suggestion{ServiceID: serviceID, Rules: []RuleExplain{}, Rejected: []Rejected{}}

	// 1. The example: its newest observations, newest first.
	var history []store.ObservationRow
	if err := s.st.EachObservation(ctx, store.ObsFilter{ServiceID: serviceID}, func(o *store.ObservationRow) error {
		if len(history) < HistoryDepth {
			history = append(history, *o)
		}
		return nil
	}); err != nil {
		return out, fmt.Errorf("sigsuggest: read the example: %w", err)
	}
	if len(history) == 0 {
		return out, ErrNotFound
	}
	target := history[0]
	if target.Result.Port == 0 {
		target.Result.Port = target.Port
	}
	out.Target = fmt.Sprintf("%s:%d", target.IP, target.Port)
	cands, rej := Extract(&target.Result)
	out.Rejected = append(out.Rejected, rej...)
	out.Candidates = len(cands)

	// 2. Stability: a feature must be present in every earlier observation
	// of the example that has the same kind of data.
	stable := map[string]bool{}
	for _, f := range cands {
		stable[f.Key] = true
	}
	for _, o := range history[1:] {
		if (o.Result.HTTP == nil || o.Result.HTTP.Status == 0) && o.Result.TLS == nil {
			continue
		}
		out.History++
		fs, _ := Extract(&o.Result)
		have := map[string]bool{}
		for _, f := range fs {
			have[f.Key] = true
		}
		for _, f := range cands {
			if f.TLS && o.Result.TLS == nil || !f.TLS && (o.Result.HTTP == nil || o.Result.HTTP.Status == 0) {
				continue
			}
			if !have[f.Key] {
				stable[f.Key] = false
			}
		}
	}

	// 3. Document frequency over the newest observation of every other
	// service, one observation in memory at a time.
	want := map[string]int{}
	structural := map[string]bool{}
	for _, f := range cands {
		want[f.Key] = 0
		if isStructural(f) {
			structural[f.Key] = true
		}
	}
	err := s.st.EachObservation(ctx, store.ObsFilter{LatestOnly: true}, func(o *store.ObservationRow) error {
		if o.ServiceID == serviceID {
			return nil
		}
		fs, _ := Extract(&o.Result)
		var shared []string
		sharedStruct := 0
		for _, f := range fs {
			if _, ok := want[f.Key]; ok {
				shared = append(shared, f.Key)
				if structural[f.Key] {
					sharedStruct++
				}
			}
		}
		if len(structural) >= 2 && sharedStruct >= 2 && 2*sharedStruct >= len(structural) {
			out.LookAlikes++
			return ctx.Err()
		}
		if o.Result.HTTP != nil && o.Result.HTTP.Status != 0 {
			out.OthersHTTP++
		}
		if o.Result.TLS != nil {
			out.OthersTLS++
		}
		for _, k := range shared {
			want[k]++
		}
		return ctx.Err()
	})
	if err != nil {
		return out, fmt.Errorf("sigsuggest: read the inventory: %w", err)
	}

	// 4. Score and select.
	var pool []scored
	for _, f := range cands {
		others := out.OthersHTTP
		if f.TLS {
			others = out.OthersTLS
		}
		df := want[f.Key]
		switch {
		case !stable[f.Key]:
			out.Rejected = append(out.Rejected, Rejected{Kind: f.Kind, Value: f.Value, Reason: "zmienia się między obserwacjami tej usługi"})
			continue
		case others > 0 && df > 1 && float64(df)/float64(others) > MaxShare:
			out.Rejected = append(out.Rejected, Rejected{Kind: f.Kind, Value: f.Value,
				Reason: fmt.Sprintf("pospolite: występuje w %d z %d innych usług (%.0f%%)", df, others, 100*float64(df)/float64(others))})
			continue
		case f.Strength < 0.35 && df > 0:
			out.Rejected = append(out.Rejected, Rejected{Kind: f.Kind, Value: f.Value, Reason: "ogólna nazwa, używana przez wiele aplikacji"})
			continue
		}
		w := f.Strength
		if df > 0 {
			w = f.Strength * 0.6
		}
		pool = append(pool, scored{f: f, df: df, others: others, look: out.LookAlikes, weight: math.Round(w*20) / 20})
	}
	sort.SliceStable(pool, func(i, j int) bool {
		if pool[i].df != pool[j].df {
			return pool[i].df < pool[j].df
		}
		return pool[i].f.Strength > pool[j].f.Strength
	})
	var chosen []scored
	body, titles := 0, 0
	for _, c := range pool {
		if len(chosen) >= MaxRules {
			break
		}
		isBody := c.f.Kind == KindAsset || c.f.Kind == KindCSS || c.f.Kind == KindComment || c.f.Kind == KindVersionText
		if isBody && body >= MaxBodyRules || c.f.Kind == KindTitle && titles >= 1 {
			continue
		}
		if isBody {
			body++
		}
		if c.f.Kind == KindTitle {
			titles++
		}
		chosen = append(chosen, c)
	}
	conf, unique, rare := 0.0, 0, 0
	miss := 1.0
	for _, c := range chosen {
		miss *= 1 - c.weight
		if c.df == 0 && c.f.Strength >= 0.5 {
			unique++
		}
		if c.df <= max(1, c.others/100) {
			rare++
		}
	}
	conf = 1 - miss
	if len(chosen) == 0 || conf < MinConfidence || (unique == 0 && rare < 2) {
		out.Message = fmt.Sprintf("Ta usługa nie ma cech wyróżniających: z %d kandydatów żaden nie jest jednocześnie rzadki i stały (porównano z %d innymi usługami HTTP). Słaba sygnatura dawałaby fałszywe trafienia, więc jej nie proponuję.",
			out.Candidates, out.OthersHTTP)
		out.TookMs = time.Since(start).Milliseconds()
		return out, nil
	}

	// 5. Emit the signature.
	name := productName(chosen, &target.Result)
	slug, err := s.freeSlug(ctx, slugify(name))
	if err != nil {
		return out, err
	}
	out.Slug, out.Name = slug, name
	var b strings.Builder
	fmt.Fprintf(&b, "id: %s\nname: %s\ncategory: %s\n", slug, q(name), category(&target.Result))
	fmt.Fprintf(&b, "description: %s\n", q(fmt.Sprintf("Sygnatura zaproponowana z przykładu %s (%s). %d z %d cech nie występuje w żadnej usłudze spoza grupy podobnych instancji.",
		out.Target, nonEmpty(titleOf(&target.Result), "bez tytułu"), unique, len(chosen))))
	b.WriteString("tags: [sugerowana]\ninterest: 20\n")
	if cl := classesOf(&target.Result); len(cl) > 0 {
		fmt.Fprintf(&b, "classes: [%s]\n", strings.Join(cl, ", "))
	}
	fmt.Fprintf(&b, "match:\n  condition: any\n  min_confidence: %.2g\n  rules:\n", MinConfidence)
	versions := []string{}
	for _, c := range chosen {
		fmt.Fprintf(&b, "    - %s, weight: %.2g}\n", strings.TrimSuffix(c.f.Rule, "}"), c.weight)
		if c.f.Version != "" && len(versions) < 2 && !contains(versions, c.f.Version) {
			versions = append(versions, c.f.Version)
		}
		out.Rules = append(out.Rules, RuleExplain{Kind: c.f.Kind, Feature: c.f.Value, Rule: c.f.Rule, Weight: c.weight, DF: c.df, Others: c.others,
			Explanation: explain(c)})
	}
	for _, f := range cands { // a version can come from a feature that was not chosen as a rule
		if f.Version != "" && len(versions) < 2 && !contains(versions, f.Version) && stable[f.Key] {
			versions = append(versions, f.Version)
		}
	}
	if len(versions) > 0 {
		b.WriteString("version:\n")
		for _, v := range versions {
			fmt.Fprintf(&b, "  - %s\n", v)
		}
	}
	out.YAML = b.String()

	// 6. Safe-mode validator and retro-hunt over the stored data.
	out.Validation = sig.Validate(out.YAML)
	if !out.Validation.OK {
		out.Message = "Zaproponowana sygnatura nie przeszła walidatora; to błąd generatora. Szczegóły w polu validation."
		out.TookMs = time.Since(start).Milliseconds()
		return out, nil
	}
	h, _ := sig.NewHunter(out.YAML)
	h.MaxHits = MaxHitsShown
	if err := s.st.EachObservation(ctx, store.ObsFilter{LatestOnly: true}, func(o *store.ObservationRow) error {
		if o.Result.Port == 0 {
			o.Result.Port = o.Port
		}
		h.Add(&o.ServiceObservation, o.IP)
		return ctx.Err()
	}); err != nil {
		return out, fmt.Errorf("sigsuggest: retro-hunt: %w", err)
	}
	res := h.Result()
	out.RetroHunt = &res
	for _, hit := range res.Hits {
		if hit.ServiceID == serviceID {
			out.MatchesTarget = true
		}
	}
	out.OtherMatches = res.TotalHits
	if out.MatchesTarget {
		out.OtherMatches--
	}
	out.OK = out.MatchesTarget
	switch {
	case !out.MatchesTarget:
		out.Message = "Sygnatura nie pasuje do przykładu w retro-huncie (np. cecha leży poza zapisanym fragmentem treści). Nie zapisuj jej bez poprawki."
	case out.OtherMatches == 0 && out.LookAlikes > 0:
		out.Message = fmt.Sprintf("Sygnatura „%s” pasuje do przykładu i do żadnej innej z %d zapisanych usług, choć %d usług jest podobnych: sprawdź, czy reguły nie są zbyt wąskie.", name, res.Scanned-1, out.LookAlikes)
	case out.OtherMatches == 0:
		out.Message = fmt.Sprintf("Sygnatura „%s” pasuje do przykładu i do żadnej innej z %d zapisanych usług.", name, res.Scanned-1)
	default:
		out.Message = fmt.Sprintf("Sygnatura „%s” pasuje do przykładu i do %d innych z %d zapisanych usług (podobne instancje).", name, out.OtherMatches, res.Scanned-1)
	}
	out.TookMs = time.Since(start).Milliseconds()
	s.log.Info("signature suggested", "service", serviceID, "slug", slug, "rules", len(chosen), "other_matches", out.OtherMatches, "took_ms", out.TookMs)
	return out, nil
}

// isStructural says whether a feature describes how the application is
// built (favicon, custom headers, cookies, assets, markup) rather than a
// value that many unrelated applications share (a web server name, a title).
// Only structural features decide whether another service is a look-alike.
func isStructural(f Feature) bool {
	switch f.Kind {
	case KindHeaderValue, KindTitle:
		return false
	case KindCookie:
		return f.Strength >= 0.5
	}
	return true
}

func explain(c scored) string {
	switch {
	case c.others == 0:
		return c.f.Label + ": brak innych usług do porównania, rzadkości nie da się zmierzyć"
	case c.df == 0 && c.look > 0:
		return fmt.Sprintf("%s występuje tylko w tej usłudze i w %d podobnych instancjach (0 z %d pozostałych usług)", c.f.Label, c.look, c.others)
	case c.df == 0:
		return fmt.Sprintf("%s występuje tylko w tej usłudze (0 z %d innych usług)", c.f.Label, c.others)
	default:
		return fmt.Sprintf("%s występuje też w %d z %d innych usług; waga obniżona", c.f.Label, c.df, c.others)
	}
}

func productName(chosen []scored, r *model.ServiceResult) string {
	for _, kind := range []string{KindMeta, KindVersionText, KindHeaderValue} {
		for _, c := range chosen {
			if c.f.Kind == kind && c.f.Product != "" {
				return c.f.Product
			}
		}
	}
	if r.HTTP != nil {
		if p := titlePrefix(strings.TrimSpace(r.HTTP.Title)); p != "" {
			return p
		}
	}
	if r.Product != "" {
		return r.Product
	}
	for _, c := range chosen {
		if c.f.Kind == KindHeaderName {
			return c.f.Value
		}
	}
	return fmt.Sprintf("Usługa na porcie %d", r.Port)
}

func category(r *model.ServiceResult) string {
	for _, c := range r.Classes {
		switch c {
		case model.ClassAdminPanel:
			return model.CatPanel
		case model.ClassIoT:
			return model.CatIoT
		}
	}
	return model.CatOther
}

var keepClasses = map[string]bool{model.ClassAdminPanel: true, model.ClassLogin: true, model.ClassIoT: true, model.ClassStaging: true,
	model.ClassDevTool: true, model.ClassAPI: true}

func classesOf(r *model.ServiceResult) []string {
	var out []string
	for _, c := range r.Classes {
		if keepClasses[c] && !contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

func titleOf(r *model.ServiceResult) string {
	if r.HTTP != nil {
		return r.HTTP.Title
	}
	return ""
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func slugify(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			if r2, ok := plFold[r]; ok {
				b.WriteRune(r2)
				dash = false
			} else if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 60 {
		out = strings.Trim(out[:60], "-")
	}
	if out == "" {
		out = "sugerowana"
	}
	return out
}

var plFold = map[rune]rune{'ą': 'a', 'ć': 'c', 'ę': 'e', 'ł': 'l', 'ń': 'n', 'ó': 'o', 'ś': 's', 'ź': 'z', 'ż': 'z'}

// freeSlug returns base, or base-2, base-3 ... when a stored or built-in signature has it.
func (s *Suggester) freeSlug(ctx context.Context, base string) (string, error) {
	taken := map[string]bool{}
	if lib, err := sig.Builtin(); err == nil {
		for _, g := range lib {
			taken[g.Slug] = true
		}
	}
	rows, err := s.st.Pool().Query(ctx, `SELECT slug FROM signatures WHERE slug = $1 OR slug LIKE $2`, base, base+"-%")
	if err != nil {
		return "", fmt.Errorf("sigsuggest: read signature ids: %w", err)
	}
	for rows.Next() {
		var sl string
		if err := rows.Scan(&sl); err == nil {
			taken[sl] = true
		}
	}
	rows.Close()
	if !taken[base] {
		return base, nil
	}
	for i := 2; ; i++ {
		if c := fmt.Sprintf("%s-%d", base, i); !taken[c] {
			return c, nil
		}
	}
}
