package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// SimhashBucketBits is the number of top simhash bits used in GroupKey.
// 8 bits make 256 coarse buckets: pages that look alike mostly share a bucket.
const SimhashBucketBits = 8

// GroupSimhashDistance is the largest Hamming distance at which AssignGroupKeys
// puts two pages with the same base key in one group.
const GroupSimhashDistance = 6

var (
	reIPv4     = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	reHexToken = regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`)
	reDigits   = regexp.MustCompile(`\d+`)
)

// TitleTemplate removes the parts of a title that differ between copies of
// the same application: addresses, host names, ids and numbers.
func TitleTemplate(title string, hostnames ...string) string {
	t := strings.ToLower(squash(title))
	for _, h := range hostnames {
		if h != "" {
			t = strings.ReplaceAll(t, strings.ToLower(h), "<host>")
		}
	}
	t = reIPv4.ReplaceAllString(t, "<ip>")
	t = reHexToken.ReplaceAllString(t, "#")
	t = reDigits.ReplaceAllString(t, "#")
	return t
}

// groupBase is the part of the key that does not depend on the body simhash.
func groupBase(s *model.ServiceResult, hostnames []string) string {
	if s.HTTP == nil || s.HTTP.Error != "" {
		// Non-web service: same protocol, product and version look alike.
		return "svc|" + strings.ToLower(s.Name) + "|" + strings.ToLower(s.Product) + "|" + s.Version
	}
	h := s.HTTP
	fav := h.FaviconSHA256
	if h.FaviconMMH3 != nil {
		fav = strconv.Itoa(int(*h.FaviconMMH3))
	}
	techs := make([]string, 0, len(s.Technologies))
	for _, t := range s.Technologies {
		if t.Name != "" && !(t.Confidence > 0 && t.Confidence < MinTechConfidence) {
			techs = append(techs, strings.ToLower(t.Name))
		}
	}
	sort.Strings(techs)
	hosts := append([]string{h.Host}, hostnames...)
	return strings.Join([]string{
		"web",
		"fav=" + fav,
		"title=" + TitleTemplate(h.Title, hosts...),
		"status=" + strconv.Itoa(h.Status/100),
		"tech=" + strings.Join(dedupSorted(techs), ","),
		"hdr=" + strings.ToLower(strings.Join(headerNames(h.Headers), ",")),
	}, "|")
}

func hashKey(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:8])
}

// GroupKey returns the grouping key of one service (§4.6): a hash of the
// favicon hash, the title template, the sorted technology names, the header
// name set and the simhash bucket. Services with the same key look alike.
//
// The simhash bucket is the top SimhashBucketBits bits. Two near-identical
// pages can still fall on two sides of a bucket border; AssignGroupKeys
// fixes that when the whole set of services is at hand.
func GroupKey(s model.ServiceResult, hostnames ...string) string {
	base := groupBase(&s, hostnames)
	bucket := ""
	if s.HTTP != nil {
		if v, ok := parseSimhash(s.HTTP.BodySimhash); ok {
			bucket = fmt.Sprintf("%02x", v>>(64-SimhashBucketBits))
		}
	}
	return hashKey(base, "sim="+bucket)
}

// GroupItem is one service for AssignGroupKeys.
type GroupItem struct {
	Service   model.ServiceResult
	Hostnames []string
}

// AssignGroupKeys returns one key per item. Items with the same base key
// (favicon, title template, technologies, header names) whose body simhashes
// are within GroupSimhashDistance of each other share a key, also across a
// bucket border. The key of a cluster is derived from its smallest simhash,
// so it is stable for a stable set of pages.
func AssignGroupKeys(items []GroupItem) []string {
	keys := make([]string, len(items))
	type member struct {
		idx  int
		hash uint64
		ok   bool
	}
	byBase := map[string][]member{}
	bases := make([]string, len(items))
	for i := range items {
		b := groupBase(&items[i].Service, items[i].Hostnames)
		bases[i] = b
		m := member{idx: i}
		if h := items[i].Service.HTTP; h != nil {
			m.hash, m.ok = parseSimhash(h.BodySimhash)
		}
		byBase[b] = append(byBase[b], m)
	}
	for base, ms := range byBase {
		// Union-find over the members that have a simhash.
		parent := make([]int, len(ms))
		for i := range parent {
			parent[i] = i
		}
		var find func(int) int
		find = func(x int) int {
			for parent[x] != x {
				parent[x] = parent[parent[x]]
				x = parent[x]
			}
			return x
		}
		for i := 0; i < len(ms); i++ {
			if !ms[i].ok {
				continue
			}
			for j := i + 1; j < len(ms); j++ {
				if ms[j].ok && popcount(ms[i].hash^ms[j].hash) <= GroupSimhashDistance {
					parent[find(i)] = find(j)
				}
			}
		}
		minHash := map[int]uint64{}
		for i, m := range ms {
			if !m.ok {
				continue
			}
			r := find(i)
			if cur, seen := minHash[r]; !seen || m.hash < cur {
				minHash[r] = m.hash
			}
		}
		for i, m := range ms {
			if !m.ok {
				keys[m.idx] = hashKey(base, "sim=")
				continue
			}
			keys[m.idx] = hashKey(base, fmt.Sprintf("simc=%016x", minHash[find(i)]))
		}
	}
	return keys
}

func popcount(x uint64) int {
	n := 0
	for x != 0 {
		x &= x - 1
		n++
	}
	return n
}

// GroupLabel is a short human name for the group of a service.
func GroupLabel(s model.ServiceResult) string {
	if s.HTTP != nil && s.HTTP.Error == "" {
		var names []string
		for _, t := range s.Technologies {
			if t.Name != "" && len(names) < 3 {
				names = append(names, t.Name)
			}
		}
		title := squash(s.HTTP.Title)
		switch {
		case title != "" && len(names) > 0:
			return clip(title, 60) + " · " + strings.Join(names, ", ")
		case title != "":
			return clip(title, 80)
		case len(names) > 0:
			return strings.Join(names, ", ")
		}
		return fmt.Sprintf("HTTP %d bez tytułu", s.HTTP.Status)
	}
	if v := productVersion(&s); v != "" {
		return v
	}
	return fmt.Sprintf("port %d/%s", s.Port, firstNonEmpty(s.Proto, "tcp"))
}
