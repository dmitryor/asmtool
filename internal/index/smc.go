package index

import (
	"sort"
	"strconv"
	"strings"
)

// SmcSlot describes the location and shape of a self-modifying-code slot:
// a Var_NNNN EQU resolves to a typed pointer at an offset into the byte
// stream of an instruction labelled by SmcAnchor_NNNN. Knowing all three
// pieces (anchor, offset, slot size) lets a caller see exactly which bytes
// of which instruction get rewritten at run time.
type SmcSlot struct {
	Anchor string // anchor symbol name (e.g. SmcAnchor_a71f)
	Size   string // "byte" | "word" | "dword"
	Offset int    // byte offset into the anchor instruction
}

// ParseSmcEqu parses a JWasm Text-EQU body of the form
//
//	"byte ptr SmcAnchor_xxxx + N"   (offset >= 0)
//	"byte ptr SmcAnchor_xxxx"       (offset == 0)
//	"word ptr SmcAnchor_xxxx + 1"
//	"dword ptr SmcAnchor_xxxx + 2"
//
// and returns the SMC slot it points at. Returns ok=false for any other
// shape so callers can distinguish SMC-style EQUates from plain numeric or
// expression equates.
func ParseSmcEqu(text string) (slot SmcSlot, ok bool) {
	parts := strings.Fields(text)
	if len(parts) < 3 {
		return SmcSlot{}, false
	}
	size := strings.ToLower(parts[0])
	switch size {
	case "byte", "word", "dword":
	default:
		return SmcSlot{}, false
	}
	if strings.ToLower(parts[1]) != "ptr" {
		return SmcSlot{}, false
	}
	anchor := parts[2]
	offset := 0
	if len(parts) >= 5 && parts[3] == "+" {
		v, err := strconv.Atoi(parts[4])
		if err != nil {
			return SmcSlot{}, false
		}
		offset = v
	} else if len(parts) >= 4 {
		// Unrecognised trailer (e.g. arithmetic we don't model).
		return SmcSlot{}, false
	}
	return SmcSlot{Anchor: anchor, Size: size, Offset: offset}, true
}

// FindEquAliasesOf returns EQU symbols whose Text-form right-hand side
// references `name` as the anchor of an SMC slot. The motivating case:
// `find_data_refs(SmcAnchor_a71f)` returns no refs because no instruction
// names the anchor directly -- the writes go through the EQU'd `Var_a720`.
// Surfacing the alias list lets the agent immediately re-query against
// the right name.
func (idx *Index) FindEquAliasesOf(name string) []*SymbolEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	var out []*SymbolEntry
	for _, decls := range idx.Symbols {
		for _, s := range decls {
			if s.Text == "" {
				continue
			}
			slot, ok := ParseSmcEqu(s.Text)
			if !ok || slot.Anchor != name {
				continue
			}
			out = append(out, s)
		}
	}
	return out
}

// HostInstruction returns the instruction text at the SMC anchor's source
// site, with any leading label stripped. If the anchor sits on its own
// line (`SmcAnchor_xxx::` followed by the instruction on the next line),
// the next non-blank line is returned. Returns "" if the source isn't
// loaded or the line is unreachable.
func (idx *Index) HostInstruction(anchor *SymbolEntry) string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	f := idx.Files[anchor.File]
	if f == nil || anchor.Line < 1 || anchor.Line > len(f.Lines) {
		return ""
	}
	line := stripInlineComment(f.Lines[anchor.Line-1])
	if instr := afterLabel(line, anchor.Name); instr != "" {
		return strings.TrimSpace(instr)
	}
	for i := anchor.Line; i < len(f.Lines); i++ {
		next := strings.TrimSpace(stripInlineComment(f.Lines[i]))
		if next == "" {
			continue
		}
		return next
	}
	return ""
}

func stripInlineComment(line string) string {
	if i := strings.IndexByte(line, ';'); i >= 0 {
		return strings.TrimRight(line[:i], " \t")
	}
	return strings.TrimRight(line, " \t")
}

// afterLabel returns the substring of `line` following a leading
// `<name>:` or `<name>::` declaration. Returns "" if no instruction
// follows the label on the same line.
func afterLabel(line, name string) string {
	s := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(s, name) {
		return strings.TrimSpace(s)
	}
	rest := s[len(name):]
	if !strings.HasPrefix(rest, ":") {
		return strings.TrimSpace(s)
	}
	rest = strings.TrimPrefix(rest, ":")
	rest = strings.TrimPrefix(rest, ":")
	return strings.TrimSpace(rest)
}

// SmcSite is the joined view of an SMC anchor and one of its var-aliased
// slots. Returned by SmcSiteAt when a queried address either lands on an
// anchor's first byte or on a slot inside the patched instruction.
type SmcSite struct {
	Anchor          *SymbolEntry
	Var             *SymbolEntry // var alias whose slot the address hits (nil if the addr is the anchor itself)
	Slot            SmcSlot      // populated when Var != nil
	HostInstruction string       // source line of the patched instruction
	SlotAddrOffset  int          // byte offset of the queried addr relative to the anchor
}

// SmcSiteAt returns the SMC site that covers the given byte address, if
// any. Resolution rules:
//
//   - addr matches an anchor's address exactly: return the anchor (Var is nil)
//   - addr matches `anchor.Addr + slot.Offset` for some EQU'd Var: return both
//
// Returns nil when no SMC site covers addr. The motivating use case:
// `addr_to_location(0xa720)` should not just say "PROC X at offset 0xZ" but
// also reveal that 0xa720 is the immediate slot of `mov bx, 0` at SmcAnchor_a71f
// patched through Var_a720 -- saving the caller a manual line-read.
func (idx *Index) SmcSiteAt(addr uint32) *SmcSite {
	idx.mu.RLock()
	// Walk all EQU symbols once: cheap (a few hundred at most) and avoids
	// maintaining a parallel slot-addr map that would need to track index
	// rebuilds.
	var bestVar *SymbolEntry
	var bestAnchor *SymbolEntry
	var bestSlot SmcSlot
	var bestOffset int
	for _, decls := range idx.Symbols {
		for _, s := range decls {
			if s.Kind != "EQU" || s.Text == "" {
				continue
			}
			slot, ok := ParseSmcEqu(s.Text)
			if !ok {
				continue
			}
			anchorDecls := idx.Symbols[slot.Anchor]
			if len(anchorDecls) == 0 {
				continue
			}
			anchor := anchorDecls[0]
			if !anchor.HasAddr {
				continue
			}
			if anchor.Addr+uint32(slot.Offset) != addr {
				continue
			}
			bestVar = s
			bestAnchor = anchor
			bestSlot = slot
			bestOffset = slot.Offset
			break
		}
		if bestVar != nil {
			break
		}
	}
	// If the addr didn't match a slot, see if it lands directly on an anchor.
	if bestVar == nil {
		for _, decls := range idx.Symbols {
			for _, s := range decls {
				if !s.HasAddr || s.Addr != addr {
					continue
				}
				if !strings.HasPrefix(s.Name, "SmcAnchor_") {
					continue
				}
				bestAnchor = s
				break
			}
			if bestAnchor != nil {
				break
			}
		}
	}
	idx.mu.RUnlock()
	if bestAnchor == nil {
		return nil
	}
	site := &SmcSite{
		Anchor:         bestAnchor,
		Var:            bestVar,
		Slot:           bestSlot,
		SlotAddrOffset: bestOffset,
	}
	site.HostInstruction = idx.HostInstruction(bestAnchor)
	return site
}

// SmcAnchorRef is one anchor's worth of identifying info inside a cluster.
type SmcAnchorRef struct {
	Anchor    *SymbolEntry
	Var       *SymbolEntry // nil if no Var_* alias was found for this anchor
	Slot      SmcSlot      // valid only when Var != nil
	HostInstr string
}

// SmcCluster is a contiguous run of SMC anchors that sit close enough to
// each other in CSEG to be treated as a single SMC pattern -- typically a
// triple of consecutive immediates patched together by one writer PROC.
type SmcCluster struct {
	File       string         // source file the anchors live in
	Anchors    []SmcAnchorRef // sorted by anchor address ascending
	StartAddr  uint32
	EndAddr    uint32 // address of the last anchor (not the byte after)
	Procs      []string       // distinct PROCs that write to any var in the cluster
}

// SmcClusters groups SMC anchors by spatial proximity. Two consecutive
// anchors (sorted by address) are placed in the same cluster when they
// live in the same source file AND their addresses are within `maxGap`
// bytes of each other. Clusters smaller than `minSize` are dropped.
//
// The motivating observation: a writer PROC that performs three patches in
// a row (e.g. FlightModelUpdate writing Var_a81b/a81e/a824) leaves three
// anchors at consecutive instruction addresses. Surfacing those clusters
// turns "194 individual vars" into a much smaller set of patterns the
// agent can name and annotate together.
//
// `fileFilter`, when non-empty, restricts the scan to one file (compared
// against the absolute path stored in the index).
func (idx *Index) SmcClusters(fileFilter string, maxGap uint32, minSize int) []*SmcCluster {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	// Collect every SmcAnchor_* with a known address.
	type anchorRow struct {
		entry *SymbolEntry
	}
	var anchors []anchorRow
	for name, decls := range idx.Symbols {
		if !strings.HasPrefix(name, "SmcAnchor_") {
			continue
		}
		for _, s := range decls {
			if !s.HasAddr {
				continue
			}
			if fileFilter != "" && s.File != fileFilter {
				continue
			}
			anchors = append(anchors, anchorRow{entry: s})
		}
	}
	sort.Slice(anchors, func(i, j int) bool {
		return anchors[i].entry.Addr < anchors[j].entry.Addr
	})

	// Build a reverse map anchor name -> var alias (first one wins; usually
	// there is exactly one Var_NNNN per anchor).
	varOf := map[string]*SymbolEntry{}
	slotOf := map[string]SmcSlot{}
	for _, decls := range idx.Symbols {
		for _, s := range decls {
			if s.Kind != "EQU" || s.Text == "" {
				continue
			}
			slot, ok := ParseSmcEqu(s.Text)
			if !ok {
				continue
			}
			if _, seen := varOf[slot.Anchor]; seen {
				continue
			}
			varOf[slot.Anchor] = s
			slotOf[slot.Anchor] = slot
		}
	}

	// Walk anchors, splitting into clusters at file boundaries or when the
	// gap to the previous anchor exceeds maxGap.
	var clusters []*SmcCluster
	var cur *SmcCluster
	procSeen := map[string]bool{}
	for i, a := range anchors {
		startNew := cur == nil ||
			cur.File != a.entry.File ||
			a.entry.Addr-cur.EndAddr > maxGap
		if startNew {
			if cur != nil && len(cur.Anchors) >= minSize {
				clusters = append(clusters, cur)
			}
			cur = &SmcCluster{
				File:      a.entry.File,
				StartAddr: a.entry.Addr,
			}
			procSeen = map[string]bool{}
		}
		ref := SmcAnchorRef{
			Anchor:    a.entry,
			HostInstr: idx.hostInstructionLocked(a.entry),
		}
		if v, ok := varOf[a.entry.Name]; ok {
			ref.Var = v
			ref.Slot = slotOf[a.entry.Name]
			// Record writer PROCs for cluster summary.
			for _, r := range idx.Refs[v.Name] {
				if r.Kind != "mem" {
					continue
				}
				access := classifyAccessLocked(r)
				if access != "write" && access != "rw" {
					continue
				}
				if r.EnclosingProc == "" || procSeen[r.EnclosingProc] {
					continue
				}
				procSeen[r.EnclosingProc] = true
				cur.Procs = append(cur.Procs, r.EnclosingProc)
			}
		}
		cur.Anchors = append(cur.Anchors, ref)
		cur.EndAddr = a.entry.Addr
		_ = i
	}
	if cur != nil && len(cur.Anchors) >= minSize {
		clusters = append(clusters, cur)
	}
	for _, c := range clusters {
		sort.Strings(c.Procs)
	}
	return clusters
}

// SmcProcCluster groups SMC vars by a shared writer or reader PROC. This
// is the analytic counterpart to SmcCluster: rather than asking "which
// anchors sit next to each other in CSEG?" it asks "which anchors are
// touched by the same PROC?" -- the key the math-batch case turns on
// (8 matrix vars span ~150 source lines but a single reader PROC loads
// them all back-to-back).
type SmcProcCluster struct {
	Proc    string         // the shared writer or reader PROC
	Role    string         // "writer" | "reader"
	Vars    []SmcAnchorRef // one entry per var the PROC touches; sorted by anchor address
}

// SmcClustersByProc returns clusters keyed by shared writer or reader
// PROC. `kind` selects the access ("write" includes rw; "read" picks
// up cmp/mov-from). `procFilter`, when non-empty, restricts output to a
// single PROC. Clusters smaller than `minSize` are dropped.
func (idx *Index) SmcClustersByProc(kind, procFilter string, minSize int) []*SmcProcCluster {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if minSize < 1 {
		minSize = 2
	}

	// Map var name -> SmcAnchorRef (anchor + slot + host instr).
	varRefs := map[string]SmcAnchorRef{}
	for name, decls := range idx.Symbols {
		if !strings.HasPrefix(name, "Var_") {
			continue
		}
		for _, s := range decls {
			if s.Kind != "EQU" || s.Text == "" {
				continue
			}
			slot, ok := ParseSmcEqu(s.Text)
			if !ok {
				continue
			}
			anchorDecls := idx.Symbols[slot.Anchor]
			if len(anchorDecls) == 0 {
				continue
			}
			anchor := anchorDecls[0]
			varRefs[name] = SmcAnchorRef{
				Anchor:    anchor,
				Var:       s,
				Slot:      slot,
				HostInstr: idx.hostInstructionLocked(anchor),
			}
		}
	}

	// proc -> []var name (ordered by addr later)
	procVars := map[string]map[string]bool{}
	for varName := range varRefs {
		for _, r := range idx.Refs[varName] {
			if r.Kind != "mem" || r.EnclosingProc == "" {
				continue
			}
			access := ClassifyAccess(r)
			match := false
			switch kind {
			case "writer", "writer_proc", "write":
				match = access == "write" || access == "rw"
			case "reader", "reader_proc", "read":
				match = access == "read" || access == "rw"
			}
			if !match {
				continue
			}
			if procFilter != "" && r.EnclosingProc != procFilter {
				continue
			}
			if procVars[r.EnclosingProc] == nil {
				procVars[r.EnclosingProc] = map[string]bool{}
			}
			procVars[r.EnclosingProc][varName] = true
		}
	}

	role := "writer"
	if kind == "reader" || kind == "reader_proc" || kind == "read" {
		role = "reader"
	}

	clusters := make([]*SmcProcCluster, 0, len(procVars))
	for proc, varSet := range procVars {
		if len(varSet) < minSize {
			continue
		}
		c := &SmcProcCluster{Proc: proc, Role: role}
		for v := range varSet {
			ref, ok := varRefs[v]
			if !ok {
				continue
			}
			c.Vars = append(c.Vars, ref)
		}
		sort.Slice(c.Vars, func(i, j int) bool {
			return c.Vars[i].Anchor.Addr < c.Vars[j].Anchor.Addr
		})
		clusters = append(clusters, c)
	}
	// Sort: largest cluster first; tiebreak by proc name.
	sort.Slice(clusters, func(i, j int) bool {
		if len(clusters[i].Vars) != len(clusters[j].Vars) {
			return len(clusters[i].Vars) > len(clusters[j].Vars)
		}
		return clusters[i].Proc < clusters[j].Proc
	})
	return clusters
}

// hostInstructionLocked is HostInstruction without taking the lock again
// (caller already holds idx.mu).
func (idx *Index) hostInstructionLocked(anchor *SymbolEntry) string {
	f := idx.Files[anchor.File]
	if f == nil || anchor.Line < 1 || anchor.Line > len(f.Lines) {
		return ""
	}
	line := stripInlineComment(f.Lines[anchor.Line-1])
	if instr := afterLabel(line, anchor.Name); instr != "" {
		return strings.TrimSpace(instr)
	}
	for i := anchor.Line; i < len(f.Lines); i++ {
		next := strings.TrimSpace(stripInlineComment(f.Lines[i]))
		if next == "" {
			continue
		}
		return next
	}
	return ""
}

// classifyAccessLocked mirrors ClassifyAccess but is callable from code
// already holding idx.mu (ClassifyAccess takes no lock currently, but if it
// later does we want a stable lock-free version for cluster scans).
func classifyAccessLocked(r *RefEntry) string {
	return ClassifyAccess(r)
}
