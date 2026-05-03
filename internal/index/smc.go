package index

import (
	"sort"
	"strconv"
	"strings"

	"github.com/orlovsky/jwasm-mcp/internal/jwasm"
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

// SiblingSlotRelation describes how two Var_* slots aliasing the same
// SmcAnchor overlap each other in the patched instruction's byte range.
// The motivating case: SmcAnchor_ae67 has Var_ae68 (word at +1, bytes
// 1..2) and Var_ae69 (byte at +2, byte 2). Var_ae69 is the high byte
// of Var_ae68.
type SiblingSlotRelation struct {
	// Kind is one of:
	//   byte_slice_of       -- this var sits fully inside the sibling
	//   contains_byte_slice -- this var fully contains the sibling
	//   co_located          -- exact same byte range (different typing)
	//   overlaps            -- partial overlap (fallback; rare)
	Kind        string
	Sibling     string
	SiblingSlot SmcSlot
}

// CarryChainPair finds an adjacent SMC-slot pair forming a 32-bit
// arithmetic operation: a sub/add at addr A whose immediate is a slot,
// followed by a sbb/adc at addr (A+sizeOfPrev) whose immediate is also
// a slot. Returns the kind ("carry_chain_lo" if the queried slot is
// the leading sub/add, "carry_chain_hi" if it's the trailing sbb/adc)
// and the sibling Var_* name. Returns "", "" when no chain is detected.
//
// Used by smc_var_info to surface the round-7 cull-transform pattern
// (sub_ax_imm16_long X immediately followed by sbb reg, Y; both
// immediates patched).
func (idx *Index) CarryChainPair(slotAnchor *SymbolEntry) (kind, sibling string) {
	if slotAnchor == nil || !slotAnchor.HasAddr {
		return "", ""
	}
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	thisInstr := idx.instructionAtLocked(slotAnchor.Addr)
	if thisInstr == nil {
		return "", ""
	}
	thisMnem := firstToken(thisInstr.Text)
	thisIsLow := isLowMnemonic(thisMnem)
	thisIsHigh := isHighMnemonic(thisMnem)
	if !thisIsLow && !thisIsHigh {
		return "", ""
	}

	var probeAddr uint32
	wantHigh := thisIsLow
	if thisIsLow {
		probeAddr = thisInstr.Addr + thisInstr.Size
	} else {
		// Find the instruction immediately preceding ours.
		prev := idx.instructionBeforeLocked(thisInstr.Addr)
		if prev == nil {
			return "", ""
		}
		probeAddr = prev.Addr
	}
	other := idx.instructionAtLocked(probeAddr)
	if other == nil {
		return "", ""
	}
	otherMnem := firstToken(other.Text)
	if wantHigh && !isHighMnemonic(otherMnem) {
		return "", ""
	}
	if !wantHigh && !isLowMnemonic(otherMnem) {
		return "", ""
	}
	// The sibling instruction must itself host an SMC slot. Look for any
	// Var_* whose anchor.addr falls inside the sibling instruction's
	// range (covering both the start-of-instruction case and slots at
	// non-zero offsets within).
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
			slotAddr := anchor.Addr + uint32(slot.Offset)
			if slotAddr < other.Addr || slotAddr >= other.Addr+other.Size {
				continue
			}
			if wantHigh {
				return "carry_chain_lo", s.Name
			}
			return "carry_chain_hi", s.Name
		}
	}
	return "", ""
}

func (idx *Index) instructionAtLocked(addr uint32) *jwasm.Instruction {
	if len(idx.instructions) == 0 {
		return nil
	}
	i := sort.Search(len(idx.instructions), func(i int) bool {
		return idx.instructions[i].Addr > addr
	})
	if i == 0 {
		return nil
	}
	c := &idx.instructions[i-1]
	if addr < c.Addr || addr >= c.Addr+c.Size {
		return nil
	}
	return c
}

func (idx *Index) instructionBeforeLocked(addr uint32) *jwasm.Instruction {
	if len(idx.instructions) == 0 {
		return nil
	}
	i := sort.Search(len(idx.instructions), func(i int) bool {
		return idx.instructions[i].Addr >= addr
	})
	if i == 0 {
		return nil
	}
	return &idx.instructions[i-1]
}

func firstToken(text string) string {
	s := strings.TrimSpace(text)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		first := s[:i]
		if strings.HasSuffix(first, ":") {
			s = strings.TrimSpace(s[i:])
		}
	}
	i := 0
	for i < len(s) && s[i] != ' ' && s[i] != '\t' {
		i++
	}
	tok := strings.ToLower(s[:i])
	// Encoding-macro fallback (matches role.go's behaviour).
	if u := strings.IndexByte(tok, '_'); u > 0 {
		prefix := tok[:u]
		if isLowMnemonic(prefix) || isHighMnemonic(prefix) {
			return prefix
		}
	}
	return tok
}

func isLowMnemonic(m string) bool {
	switch m {
	case "sub", "add":
		return true
	}
	return false
}

func isHighMnemonic(m string) bool {
	switch m {
	case "sbb", "adc":
		return true
	}
	return false
}

// SelfStoringWrites tags the "self-storing list head" pattern: the
// host instruction at the anchor is a `mov reg, imm` (role
// value_load_imm or stack_anchor) and one or more writers against the
// same var write the SAME register's value back into the slot. Each
// such write replaces the immediate in-place, so the next time the
// anchor instruction executes, `reg` is loaded with the freshly
// written value -- a one-instruction "linked list head" / "stash slot"
// implementation. Used in WalkListAndCullAaBb (cull-fail / cull-pass
// list heads, the round-7 naming-log finding).
//
// Returns the destination register of the host instruction and the
// matching writer refs. Empty register means the host isn't a
// reg-load or no writer matches; callers can treat that as "not self-storing".
func (idx *Index) SelfStoringWrites(varName string, anchor *SymbolEntry) (register string, writes []*RefEntry) {
	if anchor == nil {
		return "", nil
	}
	host := idx.HostInstruction(anchor)
	if host == "" {
		return "", nil
	}
	role := ClassifyHostRole(host)
	if role != "value_load_imm" && role != "stack_anchor" {
		return "", nil
	}
	_, dst, _ := splitOperands(host)
	dst = strings.ToLower(strings.TrimSpace(dst))
	// Reject memory destinations -- those aren't a register being
	// loaded with the slot's immediate.
	if dst == "" || strings.HasPrefix(dst, "[") || strings.Contains(dst, "ptr ") || strings.Contains(dst, ":[") {
		return "", nil
	}
	idx.mu.RLock()
	refs := idx.Refs[varName]
	idx.mu.RUnlock()
	for _, r := range refs {
		if r.Kind != "mem" {
			continue
		}
		access := ClassifyAccess(r)
		if access != "write" && access != "rw" {
			continue
		}
		_, _, src := splitOperands(r.Text)
		src = strings.ToLower(strings.TrimSpace(src))
		if src == dst {
			writes = append(writes, r)
		}
	}
	if len(writes) == 0 {
		return "", nil
	}
	return dst, writes
}

// SiblingSlotRelations returns the overlap relationships between the
// queried var's slot and every other Var_* aliasing the same anchor.
// Returns nil when no other var aliases the anchor or when the slot
// size is unknown.
func (idx *Index) SiblingSlotRelations(name, anchorName string, slot SmcSlot) []SiblingSlotRelation {
	mySize := slotSizeBytes(slot.Size)
	if mySize == 0 {
		return nil
	}
	myStart := slot.Offset
	myEnd := myStart + mySize
	var out []SiblingSlotRelation
	for _, sib := range idx.FindEquAliasesOf(anchorName) {
		if sib.Name == name {
			continue
		}
		sl, ok := ParseSmcEqu(sib.Text)
		if !ok {
			continue
		}
		sibSize := slotSizeBytes(sl.Size)
		if sibSize == 0 {
			continue
		}
		sibStart := sl.Offset
		sibEnd := sibStart + sibSize
		if sibEnd <= myStart || sibStart >= myEnd {
			continue
		}
		kind := "overlaps"
		switch {
		case sibStart == myStart && sibEnd == myEnd:
			kind = "co_located"
		case sibStart <= myStart && sibEnd >= myEnd:
			kind = "byte_slice_of"
		case myStart <= sibStart && myEnd >= sibEnd:
			kind = "contains_byte_slice"
		}
		out = append(out, SiblingSlotRelation{
			Kind:        kind,
			Sibling:     sib.Name,
			SiblingSlot: sl,
		})
	}
	return out
}

// slotSizeBytes maps a slot size token to the byte count it covers.
// Returns 0 for unknown sizes so callers can skip them.
func slotSizeBytes(s string) int {
	switch s {
	case "byte":
		return 1
	case "word":
		return 2
	case "dword":
		return 4
	}
	return 0
}

// MirrorWriteGroup represents a run of consecutive memory-write refs
// inside one writer PROC whose source operand text is identical -- the
// signature of one computed value being broadcast to N SMC slots
// back-to-back. ComputeViewMatrix produces 9 such groups, each one
// matrix element stored to its 3 mirror locations.
type MirrorWriteGroup struct {
	// Source is the operand text right of the comma (e.g. "ax", "cx",
	// "word ptr [bp+4]"). Whitespace-normalised, lowercased.
	Source    string
	LineStart int
	LineEnd   int
	Writes    []MirrorWrite
}

// MirrorWrite is one mem-write ref inside a MirrorWriteGroup.
type MirrorWrite struct {
	Target string // the destination symbol (the patched SMC slot's var name)
	File   string
	Line   int
	Text   string
}

// FindMirrorWrites returns groups of consecutive memory-write refs
// inside `proc` whose source operand is identical and whose source
// lines sit within `maxLineGap` of each other. Groups smaller than
// `minSize` are filtered out.
//
// `proc` accepts both real PROC names and the synthetic
// `<basename>:module-scope` key produced by SmcClustersByProc.
func (idx *Index) FindMirrorWrites(proc string, maxLineGap, minSize int) []MirrorWriteGroup {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if minSize < 2 {
		minSize = 2
	}
	if maxLineGap < 0 {
		maxLineGap = 0
	}
	type writeRow struct {
		ref    *RefEntry
		source string
	}
	var rows []writeRow
	for _, refs := range idx.Refs {
		for _, r := range refs {
			if r.Kind != "mem" {
				continue
			}
			if access := ClassifyAccess(r); access != "write" && access != "rw" {
				continue
			}
			procKey := r.EnclosingProc
			if procKey == "" {
				procKey = ModuleScopeProcKey(r.File)
			}
			if procKey != proc {
				continue
			}
			rows = append(rows, writeRow{ref: r, source: extractWriteSource(r.Text)})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ref.File != rows[j].ref.File {
			return rows[i].ref.File < rows[j].ref.File
		}
		return rows[i].ref.Line < rows[j].ref.Line
	})

	var groups []MirrorWriteGroup
	cur := MirrorWriteGroup{}
	for _, w := range rows {
		if w.source == "" {
			// flush current
			if len(cur.Writes) >= minSize {
				groups = append(groups, cur)
			}
			cur = MirrorWriteGroup{}
			continue
		}
		startNew := len(cur.Writes) == 0 ||
			cur.Source != w.source ||
			(w.ref.Line-cur.LineEnd) > maxLineGap
		if startNew {
			if len(cur.Writes) >= minSize {
				groups = append(groups, cur)
			}
			cur = MirrorWriteGroup{Source: w.source, LineStart: w.ref.Line, LineEnd: w.ref.Line}
		}
		cur.Writes = append(cur.Writes, MirrorWrite{
			Target: w.ref.Target,
			File:   w.ref.File,
			Line:   w.ref.Line,
			Text:   w.ref.Text,
		})
		cur.LineEnd = w.ref.Line
	}
	if len(cur.Writes) >= minSize {
		groups = append(groups, cur)
	}
	return groups
}

// extractWriteSource pulls the source operand from a memory-write
// instruction's text (the part after the first top-level comma).
// Returns "" when the line doesn't fit the dst, src shape or when the
// source operand is itself a memory operand (not a register/imm value
// being broadcast).
func extractWriteSource(text string) string {
	s := strings.TrimSpace(text)
	// Strip leading label.
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		first := s[:i]
		if strings.HasSuffix(first, ":") {
			s = strings.TrimSpace(s[i:])
		}
	}
	// Skip mnemonic.
	i := 0
	for i < len(s) && s[i] != ' ' && s[i] != '\t' {
		i++
	}
	rest := strings.TrimSpace(s[i:])
	c := indexTopComma(rest)
	if c < 0 {
		return ""
	}
	src := strings.TrimSpace(rest[c+1:])
	// Strip trailing inline comment if any survived.
	if idx := strings.IndexByte(src, ';'); idx >= 0 {
		src = strings.TrimSpace(src[:idx])
	}
	return strings.ToLower(src)
}

// SmcProcCluster groups SMC vars by a shared writer or reader PROC. This
// is the analytic counterpart to SmcCluster: rather than asking "which
// anchors sit next to each other in CSEG?" it asks "which anchors are
// touched by the same PROC?" -- the key the math-batch case turns on
// (8 matrix vars span ~150 source lines but a single reader PROC loads
// them all back-to-back).
type SmcProcCluster struct {
	Proc        string          // the shared writer or reader PROC
	Role        string          // "writer" | "reader"
	Vars        []SmcAnchorRef  // one entry per var the PROC touches; sorted by anchor address
	SubClusters []SmcSubCluster // adjacency-grouped sub-clusters; nil when no split applies
}

// SmcSubCluster is a writer/reader-line-adjacent sub-grouping inside a
// larger SmcProcCluster. The motivating case: perframe.inc writes 30 SMC
// slots in one file, but those 30 fall into 4 tight sub-clusters
// (motion-delta broadcast, SP-anchor pair, LOD-scale group, timer pair)
// scattered across the file body. Grouping vars whose writer lines sit
// within a few dozen lines of each other surfaces these sub-patterns
// without the agent having to spot them visually.
type SmcSubCluster struct {
	LineStart int            // first writer/reader line in this sub-group
	LineEnd   int            // last writer/reader line in this sub-group
	Vars      []SmcAnchorRef // sorted by anchor address ascending
}

// ModuleScopeProcKey synthesizes a stable proc-name substitute for
// references that have no enclosing PROC. Format: "<basename>:module-scope".
// The colon prevents collision with real PROC names (assembly identifiers
// don't allow colons mid-token) so the key is visually distinguishable in
// any output that lists PROC names.
func ModuleScopeProcKey(absPath string) string {
	base := absPath
	if i := strings.LastIndexAny(absPath, "/\\"); i >= 0 {
		base = absPath[i+1:]
	}
	return base + ":module-scope"
}

// SmcClustersByFile returns clusters keyed by the source file of a var's
// writer or reader refs. Coarser than by-PROC: catches setup-block
// patterns where a whole module's worth of SMC writes happen at module
// scope (polydraw.inc's 18 vars) without splitting them across the
// synthetic per-file pseudo-PROCs by-PROC mode would emit.
//
// Returns SmcProcCluster instances with the file basename in `Proc` and
// `Role` set to "writer" or "reader". When `subMaxLineGap` > 0 each
// cluster's `SubClusters` is populated from writer-line adjacency:
// vars whose writer/reader source lines sit within `subMaxLineGap` of
// each other share a sub-cluster. Use this to surface the 4-sub-cluster
// shape of perframe.inc (motion-delta broadcast, SP-anchor pair,
// LOD-scale group, timer pair) without visual scanning.
func (idx *Index) SmcClustersByFile(kind, fileFilter string, minSize, subMaxLineGap int) []*SmcProcCluster {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if minSize < 1 {
		minSize = 2
	}

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

	fileVars := map[string]map[string]bool{}
	// Per-file, per-var: lowest matching ref line. Used to seed the
	// adjacency-based sub-cluster pass after primary grouping.
	firstLine := map[string]map[string]int{}
	for varName := range varRefs {
		for _, r := range idx.Refs[varName] {
			if r.Kind != "mem" {
				continue
			}
			access := ClassifyAccess(r)
			match := false
			switch kind {
			case "writer", "writer_file", "write":
				match = access == "write" || access == "rw"
			case "reader", "reader_file", "read":
				match = access == "read" || access == "rw"
			}
			if !match {
				continue
			}
			base := r.File
			if i := strings.LastIndexAny(r.File, "/\\"); i >= 0 {
				base = r.File[i+1:]
			}
			if fileFilter != "" && base != fileFilter && r.File != fileFilter {
				continue
			}
			if fileVars[base] == nil {
				fileVars[base] = map[string]bool{}
				firstLine[base] = map[string]int{}
			}
			fileVars[base][varName] = true
			if cur := firstLine[base][varName]; cur == 0 || r.Line < cur {
				firstLine[base][varName] = r.Line
			}
		}
	}

	role := "writer"
	if kind == "reader" || kind == "reader_file" || kind == "read" {
		role = "reader"
	}
	clusters := make([]*SmcProcCluster, 0, len(fileVars))
	for file, varSet := range fileVars {
		if len(varSet) < minSize {
			continue
		}
		c := &SmcProcCluster{Proc: file, Role: role}
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
		if subMaxLineGap > 0 && len(c.Vars) >= 3 {
			c.SubClusters = subClusterByLine(c.Vars, firstLine[file], subMaxLineGap)
		}
		clusters = append(clusters, c)
	}
	sort.Slice(clusters, func(i, j int) bool {
		if len(clusters[i].Vars) != len(clusters[j].Vars) {
			return len(clusters[i].Vars) > len(clusters[j].Vars)
		}
		return clusters[i].Proc < clusters[j].Proc
	})
	return clusters
}

// SmcClustersByProc returns clusters keyed by shared writer or reader
// PROC. `kind` selects the access ("write" includes rw; "read" picks
// up cmp/mov-from). `procFilter`, when non-empty, restricts output to a
// single PROC. Clusters smaller than `minSize` are dropped. When
// `subMaxLineGap` > 0, each cluster's `SubClusters` is populated from
// writer/reader-line adjacency (same logic as SmcClustersByFile).
func (idx *Index) SmcClustersByProc(kind, procFilter string, minSize, subMaxLineGap int) []*SmcProcCluster {
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
	procVarFirstLine := map[string]map[string]int{}
	for varName := range varRefs {
		for _, r := range idx.Refs[varName] {
			if r.Kind != "mem" {
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
			// Module-scope refs (no enclosing PROC) get a synthetic key
			// so polydraw-style setup blocks still cluster. Marker is
			// distinguishable from real PROC names by the colon.
			procKey := r.EnclosingProc
			if procKey == "" {
				procKey = ModuleScopeProcKey(r.File)
			}
			if procFilter != "" && procKey != procFilter {
				continue
			}
			if procVars[procKey] == nil {
				procVars[procKey] = map[string]bool{}
				procVarFirstLine[procKey] = map[string]int{}
			}
			procVars[procKey][varName] = true
			if cur := procVarFirstLine[procKey][varName]; cur == 0 || r.Line < cur {
				procVarFirstLine[procKey][varName] = r.Line
			}
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
		if subMaxLineGap > 0 && len(c.Vars) >= 3 {
			c.SubClusters = subClusterByLine(c.Vars, procVarFirstLine[proc], subMaxLineGap)
		}
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

// subClusterByLine partitions a cluster's vars into sub-clusters by
// adjacency on their writer/reader source line. Vars are sorted by their
// recorded `firstLine` value; a gap > maxGap starts a new sub-cluster.
// Returns nil when fewer than 2 sub-clusters would result -- callers
// don't want a single sub-cluster echoing the parent.
func subClusterByLine(vars []SmcAnchorRef, firstLine map[string]int, maxGap int) []SmcSubCluster {
	if len(vars) == 0 {
		return nil
	}
	type rec struct {
		line int
		ref  SmcAnchorRef
	}
	rows := make([]rec, 0, len(vars))
	for _, v := range vars {
		ln := 0
		if v.Var != nil {
			ln = firstLine[v.Var.Name]
		}
		rows = append(rows, rec{line: ln, ref: v})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].line < rows[j].line
	})
	var groups []SmcSubCluster
	cur := SmcSubCluster{}
	prevLine := -1
	for _, r := range rows {
		if r.line == 0 {
			// Skip vars with no scope-matching ref line (shouldn't happen
			// in practice -- the cluster builder already required a match).
			continue
		}
		startNew := len(cur.Vars) == 0 || (r.line-prevLine) > maxGap
		if startNew {
			if len(cur.Vars) > 0 {
				groups = append(groups, cur)
			}
			cur = SmcSubCluster{LineStart: r.line, LineEnd: r.line}
		}
		cur.Vars = append(cur.Vars, r.ref)
		cur.LineEnd = r.line
		prevLine = r.line
	}
	if len(cur.Vars) > 0 {
		groups = append(groups, cur)
	}
	if len(groups) < 2 {
		// One sub-cluster equal to the parent isn't useful structure.
		return nil
	}
	// Sort vars inside each sub-cluster by anchor addr for stable display.
	for i := range groups {
		sort.Slice(groups[i].Vars, func(a, b int) bool {
			return groups[i].Vars[a].Anchor.Addr < groups[i].Vars[b].Anchor.Addr
		})
	}
	return groups
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
