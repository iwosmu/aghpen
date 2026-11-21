package scan

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/targets"
)

// Planning model.
//
// The address space is cut into /24-aligned blocks. Blocks are packed into
// units; a unit is one model.Chunk and is what the sink sees. Units are
// fixed once they are announced through OnPlan: their Seq, Spec and Size
// never change, so a paused run resumes from exactly the chunks the store
// holds. Blocks with hinted live hosts come first (density-first).
//
// The adaptive part is the work group: a worker takes as many consecutive
// pending units as the current target size allows and scans them with one
// nmap process per stage. The target size follows the measured speed:
//
//	ideal = size * target_seconds / measured_seconds
//	next  = clamp(EWMA(ideal), min_size, max_size)

const (
	blockSize       = 256
	maxPlannedUnits = 16384
	maxBlocks       = 1 << 20 // 2^28 addresses per run
)

// Chunking defaults used when the profile leaves a value at zero.
const (
	defaultInitialSize   = 256
	defaultMinSize       = 256
	defaultMaxSize       = 4096
	defaultTargetSeconds = 30
)

// normalizeChunking fills defaults and repairs impossible values.
func normalizeChunking(c model.ChunkingOpts) model.ChunkingOpts {
	if c.InitialSize <= 0 && c.MinSize <= 0 && c.MaxSize <= 0 && c.TargetSeconds <= 0 {
		c.Adaptive = true // an empty block means "use the adaptive defaults"
	}
	if c.InitialSize <= 0 {
		c.InitialSize = defaultInitialSize
	}
	if c.MinSize <= 0 {
		c.MinSize = min(defaultMinSize, c.InitialSize)
	}
	if c.MaxSize <= 0 {
		c.MaxSize = max(defaultMaxSize, c.InitialSize)
	}
	if c.MaxSize > 65536 {
		c.MaxSize = 65536
	}
	if c.MinSize > c.MaxSize {
		c.MinSize = c.MaxSize
	}
	if c.InitialSize < c.MinSize {
		c.InitialSize = c.MinSize
	}
	if c.InitialSize > c.MaxSize {
		c.InitialSize = c.MaxSize
	}
	if c.TargetSeconds <= 0 {
		c.TargetSeconds = defaultTargetSeconds
	}
	return c
}

// unitSizeFor returns the size of one planned unit: the smallest group the
// planner can form. It is min_size rounded up to whole /24 blocks, and it
// grows for very large scopes so that a plan never has more than
// maxPlannedUnits chunks.
func unitSizeFor(c model.ChunkingOpts, total int64) int {
	u := c.MinSize
	if !c.Adaptive {
		u = c.InitialSize
	}
	u = (u + blockSize - 1) / blockSize * blockSize
	if u < blockSize {
		u = blockSize
	}
	for total/int64(u) > maxPlannedUnits {
		u *= 2
	}
	return u
}

// unit is one planned chunk with its address ranges in machine form.
type unit struct {
	c      model.Chunk
	ranges []targets.Range
	v6     []string
	hostUp int // set while its group runs
}

func (u *unit) isV6() bool { return len(u.v6) > 0 }

func (u *unit) contains(ip string) bool {
	if u.isV6() {
		for _, a := range u.v6 {
			if a == ip {
				return true
			}
		}
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Unmap().Is4() {
		return false
	}
	n := targets.U32(a)
	for _, r := range u.ranges {
		if n >= r.Lo && n <= r.Hi {
			return true
		}
	}
	return false
}

// countIn returns how many of the sorted addresses fall into the range.
func countIn(sorted []uint32, r targets.Range) int {
	lo := sort.Search(len(sorted), func(i int) bool { return sorted[i] >= r.Lo })
	hi := sort.Search(len(sorted), func(i int) bool { return sorted[i] > r.Hi })
	return hi - lo
}

// buildUnits cuts the scope into units. hintIPs must be sorted.
func buildUnits(runID int64, set targets.Set, v6 []netip.Addr, hintIPs []uint32, unitSize int) ([]*unit, error) {
	if set.BlockCount() > maxBlocks {
		return nil, fmt.Errorf("scope is too large: %d addresses (limit %d per run)", set.Count(), int64(maxBlocks)*blockSize)
	}
	type block struct {
		r     targets.Range
		hints int
	}
	blocks := make([]block, 0, set.BlockCount())
	set.Blocks(func(r targets.Range) bool {
		blocks = append(blocks, block{r, countIn(hintIPs, r)})
		return true
	})
	// density-first: blocks with known live hosts first, most hosts first;
	// the rest keeps address order
	sort.SliceStable(blocks, func(i, j int) bool { return blocks[i].hints > blocks[j].hints })

	var units []*unit
	var cur []targets.Range
	curSize, curHints := 0, 0
	flush := func() {
		if len(cur) == 0 {
			return
		}
		merged := targets.NewSet(cur...).Ranges()
		units = append(units, &unit{
			c: model.Chunk{
				RunID: runID, Seq: len(units) + 1, Spec: targets.Spec(merged), Size: curSize,
				Priority: curHints, Status: model.ChunkPending,
			},
			ranges: merged,
		})
		cur, curSize, curHints = nil, 0, 0
	}
	for _, b := range blocks {
		n := int(b.r.Size())
		// keep hinted and unhinted blocks in separate units
		if curSize > 0 && (curSize+n > unitSize || (curHints > 0) != (b.hints > 0)) {
			flush()
		}
		cur = append(cur, b.r)
		curSize += n
		curHints += b.hints
	}
	flush()
	for i := 0; i < len(v6); i += blockSize {
		end := min(i+blockSize, len(v6))
		u := &unit{c: model.Chunk{RunID: runID, Seq: len(units) + 1, Size: end - i, Status: model.ChunkPending}}
		for _, a := range v6[i:end] {
			u.v6 = append(u.v6, a.String())
		}
		u.c.Spec = append([]string{}, u.v6...)
		units = append(units, u)
	}
	return units, nil
}

// unitsFromChunks rebuilds units from stored chunks when a paused run
// resumes. Done chunks are skipped. The current exclusions (with the
// addresses outside the allowed networks) are applied again, and v6Allowed
// filters IPv6 addresses (nil: all): the policy may have changed while the
// run was paused.
func unitsFromChunks(chunks []model.Chunk, exclusions targets.Set, v6Allowed func(netip.Addr) bool) ([]*unit, error) {
	var units []*unit
	for _, c := range chunks {
		if c.Status == model.ChunkDone {
			continue
		}
		st := targets.Build(c.Spec)
		if len(st.Invalid) > 0 {
			return nil, fmt.Errorf("chunk %d has an invalid spec %q: %s", c.Seq, st.Invalid[0].Value, st.Invalid[0].Reason)
		}
		u := &unit{c: c, ranges: st.V4.Subtract(exclusions).Ranges()}
		for _, a := range st.V6 {
			if v6Allowed == nil || v6Allowed(a) {
				u.v6 = append(u.v6, a.String())
			}
		}
		u.c.Status = model.ChunkPending
		u.c.Error = ""
		units = append(units, u)
	}
	sort.SliceStable(units, func(i, j int) bool {
		if units[i].c.Priority != units[j].c.Priority {
			return units[i].c.Priority > units[j].c.Priority
		}
		return units[i].c.Seq < units[j].c.Seq
	})
	return units, nil
}

// sizer holds the adaptive group size.
type sizer struct {
	mu         sync.Mutex
	cur        float64 // target addresses per group
	min, max   float64
	target     float64 // wanted seconds per group
	alpha      float64
	adaptive   bool
	secPerAddr float64 // EWMA of measured seconds per address; 0 = nothing measured yet
	history    []int   // group sizes in start order (for reports)
}

func newSizer(c model.ChunkingOpts, unitSize int) *sizer {
	c = normalizeChunking(c)
	s := &sizer{
		cur: float64(c.InitialSize), min: float64(max(c.MinSize, unitSize)), max: float64(max(c.MaxSize, unitSize)),
		target: float64(c.TargetSeconds), alpha: 0.5, adaptive: c.Adaptive,
	}
	s.cur = clampF(s.cur, s.min, s.max)
	return s
}

func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Next returns the wanted size of the next group in addresses.
func (s *sizer) Next() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int(s.cur + 0.5)
}

// Observe feeds one finished group into the model.
func (s *sizer) Observe(size int, d time.Duration) {
	if size <= 0 {
		return
	}
	sec := d.Seconds()
	if sec < 0.05 {
		sec = 0.05
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	per := sec / float64(size)
	if s.secPerAddr == 0 {
		s.secPerAddr = per
	} else {
		s.secPerAddr = s.alpha*per + (1-s.alpha)*s.secPerAddr
	}
	if !s.adaptive {
		return
	}
	ideal := clampF(float64(size)*s.target/sec, s.min, s.max)
	s.cur = clampF(s.alpha*ideal+(1-s.alpha)*s.cur, s.min, s.max)
}

// Estimate predicts the wall time of a group of the given size. ok is false
// when nothing was measured yet.
func (s *sizer) Estimate(size int) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secPerAddr == 0 {
		return 0, false
	}
	return time.Duration(s.secPerAddr * float64(size) * float64(time.Second)), true
}

func (s *sizer) record(size int) {
	s.mu.Lock()
	s.history = append(s.history, size)
	s.mu.Unlock()
}

// History returns the sizes of the groups started so far.
func (s *sizer) History() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int{}, s.history...)
}

// group is one unit of work: consecutive units scanned by one nmap process per stage.
type group struct {
	id    int
	units []*unit
	size  int
	v6    bool
}

func (g *group) specs() []string {
	var out []string
	for _, u := range g.units {
		out = append(out, u.c.Spec...)
	}
	return out
}

func (g *group) ranges() []targets.Range {
	var out []targets.Range
	for _, u := range g.units {
		out = append(out, u.ranges...)
	}
	return out
}

func (g *group) unitOf(ip string) *unit {
	for _, u := range g.units {
		if u.contains(ip) {
			return u
		}
	}
	return nil
}

func (g *group) label() string {
	seqs := make([]string, 0, 2)
	seqs = append(seqs, fmt.Sprint(g.units[0].c.Seq))
	if len(g.units) > 1 {
		seqs = append(seqs, fmt.Sprint(g.units[len(g.units)-1].c.Seq))
	}
	return strings.Join(seqs, "-")
}

// takeGroup removes the next group from the pending list: units in order
// until the wanted size is reached. It always takes at least one unit and
// never mixes IPv4 and IPv6 units.
func takeGroup(pending []*unit, want int) (g *group, rest []*unit) {
	if len(pending) == 0 {
		return nil, pending
	}
	g = &group{v6: pending[0].isV6()}
	n := 0
	for _, u := range pending {
		if n > 0 && (u.isV6() != g.v6 || g.size+u.c.Size > want) {
			break
		}
		g.units = append(g.units, u)
		g.size += u.c.Size
		n++
	}
	return g, pending[n:]
}
