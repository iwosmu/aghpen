package sig

// ac is an Aho-Corasick automaton over bytes. The engine builds one from
// every literal that body rules need, so one pass over a response body tells
// which literals occur. Rules then test a bit instead of scanning the body.
type ac struct {
	next   []int32   // dense transitions: state*256 + byte
	out    [][]int32 // literal ids that end in a state (fail links merged)
	hasOut []bool
	n      int // number of literals
}

// buildAC makes the automaton. Literal i gets id i. Empty literals never match.
func buildAC(lits []string) *ac {
	a := &ac{n: len(lits)}
	type node struct {
		child map[byte]int32
		fail  int32
		out   []int32
	}
	nodes := []node{{child: map[byte]int32{}}}
	for id, lit := range lits {
		if lit == "" {
			continue
		}
		cur := int32(0)
		for i := 0; i < len(lit); i++ {
			c := lit[i]
			nx, ok := nodes[cur].child[c]
			if !ok {
				nx = int32(len(nodes))
				nodes = append(nodes, node{child: map[byte]int32{}})
				nodes[cur].child[c] = nx
			}
			cur = nx
		}
		nodes[cur].out = append(nodes[cur].out, int32(id))
	}
	a.next = make([]int32, len(nodes)*256)
	a.out = make([][]int32, len(nodes))
	a.hasOut = make([]bool, len(nodes))

	queue := make([]int32, 0, len(nodes))
	for c, nx := range nodes[0].child {
		a.next[int(c)] = nx
		queue = append(queue, nx)
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		f := nodes[s].fail
		nodes[s].out = append(nodes[s].out, nodes[f].out...)
		for c := 0; c < 256; c++ {
			nx, ok := nodes[s].child[byte(c)]
			if ok {
				nodes[nx].fail = a.next[int(f)*256+c]
				a.next[int(s)*256+c] = nx
				queue = append(queue, nx)
			} else {
				a.next[int(s)*256+c] = a.next[int(f)*256+c]
			}
		}
	}
	for i := range nodes {
		a.out[i] = nodes[i].out
		a.hasOut[i] = len(nodes[i].out) > 0
	}
	return a
}

// scan sets the bit of every literal that occurs in text.
func (a *ac) scan(text string, hits []uint64) {
	s := int32(0)
	next, hasOut := a.next, a.hasOut
	for i := 0; i < len(text); i++ {
		s = next[int(s)<<8|int(text[i])]
		if hasOut[s] {
			for _, id := range a.out[s] {
				hits[id>>6] |= 1 << uint(id&63)
			}
		}
	}
}

func (a *ac) words() int { return (a.n + 63) / 64 }

// anyBit reports whether at least one of the literals was found.
func anyBit(hits []uint64, ids []int32) bool {
	for _, id := range ids {
		if bit(hits, id) {
			return true
		}
	}
	return false
}

func bit(hits []uint64, id int32) bool { return hits[id>>6]&(1<<uint(id&63)) != 0 }
