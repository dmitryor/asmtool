package index

import (
	"testing"

	"github.com/dmitryor/asmtool/internal/jwasm"
	"github.com/dmitryor/asmtool/internal/source"
)

// fixtureWithInstructions augments buildSmcFixture with a synthetic
// instruction stream so tests can exercise InstructionAt /
// InstructionsCovering. The layout mirrors the Var_d2a7 case: a 5-byte
// `sub dx, ...` at d2a0 followed by a 4-byte `cmp dx, 80h` at d2a5,
// with the +7 word slot landing at d2a7..d2a8 inside the cmp.
func fixtureWithInstructions() *Index {
	idx := buildSmcFixture()
	// Add an extra anchor with a multi-instruction patched region.
	multiFile := "detect.inc"
	idx.Files[multiFile] = &source.File{
		Path: multiFile,
		Lines: []string{
			"SmcAnchor_d2a0:: sub dx, cs:[Var_d3f6]",
			"             cmp dx, 80h",
		},
	}
	idx.Symbols["SmcAnchor_d2a0"] = []*SymbolEntry{{
		Name: "SmcAnchor_d2a0", Kind: "export", File: multiFile, Line: 1,
		Addr: 0xd2a0, HasAddr: true, Segment: "CSEG",
	}}
	idx.Symbols["Var_d2a7"] = []*SymbolEntry{{
		Name: "Var_d2a7", Kind: "EQU", File: "globals.inc", Line: 200,
		Text: "word ptr SmcAnchor_d2a0 + 7",
	}}
	idx.instructions = []jwasm.Instruction{
		{Addr: 0xd2a0, Size: 5, Bytes: "2B16f6d3", Text: "sub dx, cs:[Var_d3f6]"},
		{Addr: 0xd2a5, Size: 4, Bytes: "81FA8000", Text: "cmp dx, 80h"},
	}
	return idx
}

func TestInstructionAt(t *testing.T) {
	idx := fixtureWithInstructions()
	cases := []struct {
		addr     uint32
		wantNil  bool
		wantAddr uint32
	}{
		{0xd2a0, false, 0xd2a0},
		{0xd2a4, false, 0xd2a0},
		{0xd2a5, false, 0xd2a5},
		{0xd2a7, false, 0xd2a5}, // slot byte lives inside cmp, not sub
		{0xd2a8, false, 0xd2a5},
		{0xd2a9, true, 0},
	}
	for _, c := range cases {
		ins := idx.InstructionAt(c.addr)
		if c.wantNil {
			if ins != nil {
				t.Errorf("addr=0x%x: expected nil, got %+v", c.addr, ins)
			}
			continue
		}
		if ins == nil || ins.Addr != c.wantAddr {
			t.Errorf("addr=0x%x: got %+v, want addr=0x%x", c.addr, ins, c.wantAddr)
		}
	}
}

func TestInstructionsCovering(t *testing.T) {
	idx := fixtureWithInstructions()
	// Anchor at d2a0, slot at d2a7..d2a8 (word). Walk should return both
	// the sub (anchor's first instr) and the cmp (slot-containing).
	got := idx.InstructionsCovering(0xd2a0, 0xd2a9)
	if len(got) != 2 {
		t.Fatalf("got %d instructions, want 2: %+v", len(got), got)
	}
	if got[0].Addr != 0xd2a0 || got[1].Addr != 0xd2a5 {
		t.Errorf("addrs: %x, %x", got[0].Addr, got[1].Addr)
	}
}

func TestSymbolsCoveringRange(t *testing.T) {
	idx := buildSmcFixture()
	// Add a same-address overlap: word `VideoDetectResult` at the same
	// addr as byte EQU `Var_d5c8`.
	idx.Symbols["VideoDetectResult"] = []*SymbolEntry{{
		Name: "VideoDetectResult", Kind: "data", File: "globals.inc", Line: 300,
		Addr: 0xd5c8, HasAddr: true, Segment: "CSEG",
	}}
	idx.Symbols["Var_d5c8"] = []*SymbolEntry{{
		Name: "Var_d5c8", Kind: "EQU", File: "globals.inc", Line: 301,
		Addr: 0xd5c8, HasAddr: true, Segment: "CSEG",
	}}
	syms := idx.SymbolsCoveringRange(0xd5c8, 0xd5c9)
	if len(syms) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(syms), syms)
	}
	// Both should be in the result; order is by addr then name.
	names := []string{syms[0].Name, syms[1].Name}
	if names[0] != "Var_d5c8" || names[1] != "VideoDetectResult" {
		t.Errorf("names: %v", names)
	}
}

func TestSiblingSlotRelations(t *testing.T) {
	idx := buildSmcFixture()
	// Add the round-4 sibling pair: Var_ae68 word@+1 (bytes 1..2) and
	// Var_ae69 byte@+2 (byte 2). Var_ae69 is the high byte of Var_ae68.
	idx.Symbols["SmcAnchor_ae67"] = []*SymbolEntry{{
		Name: "SmcAnchor_ae67", Kind: "export", File: "render3d.inc", Line: 5,
		Addr: 0xae67, HasAddr: true, Segment: "CSEG",
	}}
	idx.Symbols["Var_ae68"] = []*SymbolEntry{{
		Name: "Var_ae68", Kind: "EQU", File: "globals.inc", Line: 400,
		Text: "word ptr SmcAnchor_ae67 + 1",
	}}
	idx.Symbols["Var_ae69"] = []*SymbolEntry{{
		Name: "Var_ae69", Kind: "EQU", File: "globals.inc", Line: 401,
		Text: "byte ptr SmcAnchor_ae67 + 2",
	}}

	// Var_ae69 is the high byte of Var_ae68 → byte_slice_of.
	rels := idx.SiblingSlotRelations("Var_ae69", "SmcAnchor_ae67",
		SmcSlot{Anchor: "SmcAnchor_ae67", Size: "byte", Offset: 2})
	if len(rels) != 1 {
		t.Fatalf("Var_ae69 relations: %d, want 1", len(rels))
	}
	if rels[0].Kind != "byte_slice_of" || rels[0].Sibling != "Var_ae68" {
		t.Errorf("Var_ae69: %+v", rels[0])
	}

	// And the inverse: Var_ae68 contains Var_ae69 → contains_byte_slice.
	rels = idx.SiblingSlotRelations("Var_ae68", "SmcAnchor_ae67",
		SmcSlot{Anchor: "SmcAnchor_ae67", Size: "word", Offset: 1})
	if len(rels) != 1 {
		t.Fatalf("Var_ae68 relations: %d, want 1", len(rels))
	}
	if rels[0].Kind != "contains_byte_slice" || rels[0].Sibling != "Var_ae69" {
		t.Errorf("Var_ae68: %+v", rels[0])
	}

	// A solitary slot (Var_a720, the only var aliasing SmcAnchor_a71f
	// in the fixture) has no relations.
	rels = idx.SiblingSlotRelations("Var_a720", "SmcAnchor_a71f",
		SmcSlot{Anchor: "SmcAnchor_a71f", Size: "word", Offset: 1})
	if len(rels) != 0 {
		t.Errorf("Var_a720 should have no relations; got %+v", rels)
	}
}

func TestVarD2a7MultiInstructionWalk(t *testing.T) {
	// End-to-end check on the round-2 wart: the +7 word slot of
	// SmcAnchor_d2a0 lands inside the cmp at d2a5 (instruction 2),
	// not the sub at d2a0 (instruction 1). The instruction stream
	// produces both, with contains_slot=true on the cmp.
	idx := fixtureWithInstructions()
	slot := SmcSlot{Anchor: "SmcAnchor_d2a0", Size: "word", Offset: 7}
	slotAddr := uint32(0xd2a0) + uint32(slot.Offset)
	end := slotAddr + 2
	got := idx.InstructionsCovering(0xd2a0, end)
	if len(got) != 2 {
		t.Fatalf("got %d instrs, want 2", len(got))
	}
	if got[0].Addr != 0xd2a0 || got[1].Addr != 0xd2a5 {
		t.Errorf("addrs: %x, %x", got[0].Addr, got[1].Addr)
	}
	// Slot byte must lie inside the second instruction, not the first.
	containsIdx := -1
	for i, ins := range got {
		if slotAddr >= ins.Addr && slotAddr < ins.Addr+ins.Size {
			containsIdx = i
		}
	}
	if containsIdx != 1 {
		t.Errorf("slot containment index: got %d, want 1 (the cmp)", containsIdx)
	}
}

func TestFindMirrorWrites(t *testing.T) {
	// Synthesise a writer PROC that broadcasts AX to three slots,
	// then a different value (BX) to two slots -- exactly the
	// ComputeViewMatrix shape on a smaller scale.
	idx := buildSmcFixture()
	procName := "ComputeViewMatrix"
	mkVar := func(name string, line int, text string) {
		idx.Refs[name] = []*RefEntry{{
			Target: name, Kind: "mem",
			File: "math.inc", Line: line,
			EnclosingProc: procName,
			Text:          text,
		}}
	}
	// AX broadcast: 3 stores at lines 100, 102, 104
	mkVar("Var_M00_a", 100, "mov [Var_M00_a], ax")
	mkVar("Var_M00_b", 102, "mov [Var_M00_b], ax")
	mkVar("Var_M00_c", 104, "mov [Var_M00_c], ax")
	// Gap then a CX broadcast: 2 stores at lines 200, 201
	mkVar("Var_M01_a", 200, "mov [Var_M01_a], cx")
	mkVar("Var_M01_b", 201, "mov [Var_M01_b], cx")

	groups := idx.FindMirrorWrites(procName, 5, 2)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2: %+v", len(groups), groups)
	}
	if groups[0].Source != "ax" || len(groups[0].Writes) != 3 {
		t.Errorf("group[0] (ax broadcast): %+v", groups[0])
	}
	if groups[1].Source != "cx" || len(groups[1].Writes) != 2 {
		t.Errorf("group[1] (cx broadcast): %+v", groups[1])
	}
	if groups[0].LineStart != 100 || groups[0].LineEnd != 104 {
		t.Errorf("group[0] line range: %d..%d", groups[0].LineStart, groups[0].LineEnd)
	}

	// With a tighter gap=1, the AX broadcast should split (gap is 2
	// between consecutive lines). Result: each store its own group, all
	// dropped by minSize=2.
	groups = idx.FindMirrorWrites(procName, 0, 2)
	if len(groups) != 0 {
		t.Errorf("with max_line_gap=0, expected 0 surviving groups; got %d", len(groups))
	}

	// proc filter mismatch: empty result.
	groups = idx.FindMirrorWrites("OtherProc", 5, 2)
	if len(groups) != 0 {
		t.Errorf("OtherProc filter: %d groups", len(groups))
	}
}

func TestCarryChainPair(t *testing.T) {
	// Layout: sub at 0xc000 (3 bytes, slot at +1) followed by
	// sbb at 0xc003 (3 bytes, slot at +1). Both slots are SMC-aliased.
	idx := buildSmcFixture()
	idx.instructions = append(idx.instructions,
		jwasm.Instruction{Addr: 0xc000, Size: 3, Bytes: "2D0000", Text: "sub ax, 0"},
		jwasm.Instruction{Addr: 0xc003, Size: 3, Bytes: "1D0000", Text: "sbb dx, 0"},
	)
	// Re-sort instructions
	for i := 0; i < len(idx.instructions)-1; i++ {
		for j := i + 1; j < len(idx.instructions); j++ {
			if idx.instructions[i].Addr > idx.instructions[j].Addr {
				idx.instructions[i], idx.instructions[j] = idx.instructions[j], idx.instructions[i]
			}
		}
	}
	idx.Symbols["SmcAnchor_c000"] = []*SymbolEntry{{
		Name: "SmcAnchor_c000", Kind: "export", File: "x.inc", Line: 1,
		Addr: 0xc000, HasAddr: true, Segment: "CSEG",
	}}
	idx.Symbols["SmcAnchor_c003"] = []*SymbolEntry{{
		Name: "SmcAnchor_c003", Kind: "export", File: "x.inc", Line: 2,
		Addr: 0xc003, HasAddr: true, Segment: "CSEG",
	}}
	idx.Symbols["Var_c001"] = []*SymbolEntry{{
		Name: "Var_c001", Kind: "EQU", File: "g.inc", Line: 1,
		Text: "word ptr SmcAnchor_c000 + 1",
	}}
	idx.Symbols["Var_c004"] = []*SymbolEntry{{
		Name: "Var_c004", Kind: "EQU", File: "g.inc", Line: 2,
		Text: "word ptr SmcAnchor_c003 + 1",
	}}

	// Querying the lo (sub) anchor: the chain partner is the sbb's slot.
	kind, sib := idx.CarryChainPair(idx.Symbols["SmcAnchor_c000"][0])
	if kind != "carry_chain_lo" || sib != "Var_c004" {
		t.Errorf("from lo anchor: got (%q, %q), want (carry_chain_lo, Var_c004)", kind, sib)
	}
	// Querying the hi (sbb) anchor: partner is the sub's slot.
	kind, sib = idx.CarryChainPair(idx.Symbols["SmcAnchor_c003"][0])
	if kind != "carry_chain_hi" || sib != "Var_c001" {
		t.Errorf("from hi anchor: got (%q, %q), want (carry_chain_hi, Var_c001)", kind, sib)
	}
	// Solitary anchor (FlightModelUpdate's are mov-style, not sub/sbb)
	// has no chain.
	kind, _ = idx.CarryChainPair(idx.Symbols["SmcAnchor_a71f"][0])
	if kind != "" {
		t.Errorf("solitary anchor should not chain; got kind=%q", kind)
	}
}

func TestSelfStoringWrites(t *testing.T) {
	// Anchor: `mov bp, 0` at addr 0xd000 (3 bytes).
	// Writer: `mov [Var_d001], bp` -- BP is the host's destination AND
	// the writer's source, signalling the self-storing list-head pattern.
	idx := buildSmcFixture()
	idx.Files["x.inc"] = &source.File{
		Path:  "x.inc",
		Lines: []string{"SmcAnchor_d000:: mov bp, 0"},
	}
	idx.Symbols["SmcAnchor_d000"] = []*SymbolEntry{{
		Name: "SmcAnchor_d000", Kind: "export", File: "x.inc", Line: 1,
		Addr: 0xd000, HasAddr: true, Segment: "CSEG",
	}}
	idx.Symbols["Var_d001"] = []*SymbolEntry{{
		Name: "Var_d001", Kind: "EQU", File: "g.inc", Line: 10,
		Text: "word ptr SmcAnchor_d000 + 1",
	}}
	idx.Refs["Var_d001"] = []*RefEntry{{
		Target: "Var_d001", Kind: "mem",
		File: "y.inc", Line: 100,
		EnclosingProc: "AppendNode",
		Text:          "mov [Var_d001], bp",
	}}

	reg, writes := idx.SelfStoringWrites("Var_d001", idx.Symbols["SmcAnchor_d000"][0])
	if reg != "bp" {
		t.Errorf("register: %q, want bp", reg)
	}
	if len(writes) != 1 {
		t.Fatalf("writes: %d, want 1", len(writes))
	}
	if writes[0].EnclosingProc != "AppendNode" {
		t.Errorf("writer proc: %q", writes[0].EnclosingProc)
	}

	// Negative case: writer source is AX, not BP -- not self-storing.
	idx.Refs["Var_d001"] = []*RefEntry{{
		Target: "Var_d001", Kind: "mem",
		File: "y.inc", Line: 100,
		EnclosingProc: "AppendNode",
		Text:          "mov [Var_d001], ax",
	}}
	reg, writes = idx.SelfStoringWrites("Var_d001", idx.Symbols["SmcAnchor_d000"][0])
	if reg != "" || len(writes) != 0 {
		t.Errorf("non-matching source: got reg=%q writes=%d", reg, len(writes))
	}
}

func TestSmcClustersByProc(t *testing.T) {
	idx := buildSmcFixture()
	// buildSmcFixture has FlightModelUpdate writing Var_a81b and Var_a81e.
	// Both should land in one writer cluster of size 2.
	clusters := idx.SmcClustersByProc("writer_proc", "", 2, 0)
	if len(clusters) != 1 {
		t.Fatalf("got %d clusters, want 1: %+v", len(clusters), clusters)
	}
	if clusters[0].Proc != "FlightModelUpdate" {
		t.Errorf("proc: %q", clusters[0].Proc)
	}
	if len(clusters[0].Vars) != 2 {
		t.Errorf("vars: %d", len(clusters[0].Vars))
	}
	if clusters[0].Role != "writer" {
		t.Errorf("role: %q", clusters[0].Role)
	}
	// Reader query yields nothing here -- the fixture has no reader refs.
	if r := idx.SmcClustersByProc("reader_proc", "", 2, 0); len(r) != 0 {
		t.Errorf("reader clusters: %d", len(r))
	}
	// proc filter narrows correctly.
	if r := idx.SmcClustersByProc("writer_proc", "OtherProc", 2, 0); len(r) != 0 {
		t.Errorf("filter narrowed to OtherProc but got %d", len(r))
	}
}

// fixtureWithModuleScopeWrites adds two SMC vars whose writers have
// no enclosing PROC (mirroring the polydraw.inc setup-block case).
func fixtureWithModuleScopeWrites() *Index {
	idx := buildSmcFixture()
	// Two new vars under a new file.
	pdFile := "polydraw.inc"
	idx.Files[pdFile] = &source.File{Path: pdFile, Lines: []string{"; setup"}}
	idx.Symbols["SmcAnchor_bfdd"] = []*SymbolEntry{{
		Name: "SmcAnchor_bfdd", Kind: "export", File: pdFile, Line: 7,
		Addr: 0xbfdd, HasAddr: true, Segment: "CSEG",
	}}
	idx.Symbols["Var_bfdf"] = []*SymbolEntry{{
		Name: "Var_bfdf", Kind: "EQU", File: "globals.inc", Line: 500,
		Text: "word ptr SmcAnchor_bfdd + 2",
	}}
	idx.Symbols["SmcAnchor_bfe1"] = []*SymbolEntry{{
		Name: "SmcAnchor_bfe1", Kind: "export", File: pdFile, Line: 9,
		Addr: 0xbfe1, HasAddr: true, Segment: "CSEG",
	}}
	idx.Symbols["Var_bfe3"] = []*SymbolEntry{{
		Name: "Var_bfe3", Kind: "EQU", File: "globals.inc", Line: 501,
		Text: "word ptr SmcAnchor_bfe1 + 2",
	}}
	// Module-scope writes (no EnclosingProc).
	idx.Refs["Var_bfdf"] = []*RefEntry{{
		Target: "Var_bfdf", Kind: "mem",
		File: pdFile, Line: 7,
		EnclosingProc: "", // module scope
		Text:          "mov [Var_bfdf], ax",
	}}
	idx.Refs["Var_bfe3"] = []*RefEntry{{
		Target: "Var_bfe3", Kind: "mem",
		File: pdFile, Line: 9,
		EnclosingProc: "",
		Text:          "mov [Var_bfe3], cx",
	}}
	return idx
}

func TestSmcClustersByProc_ModuleScopeSyntheticKey(t *testing.T) {
	idx := fixtureWithModuleScopeWrites()
	clusters := idx.SmcClustersByProc("writer_proc", "", 2, 0)
	// Should include the FlightModelUpdate cluster AND a synthetic
	// polydraw.inc:module-scope cluster of size 2.
	wantKey := ModuleScopeProcKey("polydraw.inc")
	found := false
	for _, c := range clusters {
		if c.Proc == wantKey {
			found = true
			if len(c.Vars) != 2 {
				t.Errorf("module-scope cluster size: %d, want 2", len(c.Vars))
			}
		}
	}
	if !found {
		got := make([]string, 0, len(clusters))
		for _, c := range clusters {
			got = append(got, c.Proc)
		}
		t.Errorf("synthetic module-scope key %q not found; clusters: %v", wantKey, got)
	}
	// The proc filter accepts the synthetic name.
	filtered := idx.SmcClustersByProc("writer_proc", wantKey, 2, 0)
	if len(filtered) != 1 || filtered[0].Proc != wantKey {
		t.Errorf("filter on synthetic key returned: %+v", filtered)
	}
}

func TestSmcClustersByFile_SubClusters(t *testing.T) {
	// Build a fixture where four vars in one file have writers split
	// across two source-line bands: 100/102 (motion-delta-style pair)
	// and 500/505 (timer-style pair).
	idx := buildSmcFixture()
	pdFile := "perframe.inc"
	idx.Files[pdFile] = &source.File{Path: pdFile, Lines: []string{"; perframe"}}
	addPair := func(anchorName, varName string, addr uint32, slotOff int, writerLine int) {
		idx.Symbols[anchorName] = []*SymbolEntry{{
			Name: anchorName, Kind: "export", File: pdFile, Line: writerLine,
			Addr: addr, HasAddr: true, Segment: "CSEG",
		}}
		idx.Symbols[varName] = []*SymbolEntry{{
			Name: varName, Kind: "EQU", File: "globals.inc", Line: 100,
			Text: "word ptr " + anchorName + " + " + itoa(slotOff),
		}}
		idx.Refs[varName] = []*RefEntry{{
			Target: varName, Kind: "mem",
			File: pdFile, Line: writerLine,
			EnclosingProc: "PerFrameUpdate",
			Text:          "mov [" + varName + "], ax",
		}}
	}
	addPair("SmcAnchor_3000", "Var_3001", 0x3000, 1, 100)
	addPair("SmcAnchor_3010", "Var_3011", 0x3010, 1, 102)
	addPair("SmcAnchor_4000", "Var_4001", 0x4000, 1, 500)
	addPair("SmcAnchor_4010", "Var_4011", 0x4010, 1, 505)

	clusters := idx.SmcClustersByFile("writer_file", "perframe.inc", 2, 25)
	if len(clusters) != 1 {
		t.Fatalf("got %d clusters, want 1", len(clusters))
	}
	c := clusters[0]
	if len(c.Vars) != 4 {
		t.Errorf("cluster size: %d, want 4", len(c.Vars))
	}
	if len(c.SubClusters) != 2 {
		t.Fatalf("got %d sub-clusters, want 2: %+v", len(c.SubClusters), c.SubClusters)
	}
	// First sub-cluster: lines 100..102.
	if c.SubClusters[0].LineStart != 100 || c.SubClusters[0].LineEnd != 102 {
		t.Errorf("sub[0] lines: %d..%d", c.SubClusters[0].LineStart, c.SubClusters[0].LineEnd)
	}
	if len(c.SubClusters[0].Vars) != 2 {
		t.Errorf("sub[0] var count: %d", len(c.SubClusters[0].Vars))
	}
	// Second sub-cluster: lines 500..505.
	if c.SubClusters[1].LineStart != 500 || c.SubClusters[1].LineEnd != 505 {
		t.Errorf("sub[1] lines: %d..%d", c.SubClusters[1].LineStart, c.SubClusters[1].LineEnd)
	}

	// With a wider gap (1000 lines), all 4 collapse into one sub-cluster --
	// which is the "no useful split" case → SubClusters should be nil.
	clusters = idx.SmcClustersByFile("writer_file", "perframe.inc", 2, 1000)
	if len(clusters) != 1 {
		t.Fatalf("wide-gap cluster count: %d", len(clusters))
	}
	if clusters[0].SubClusters != nil {
		t.Errorf("expected nil SubClusters when only one would emerge; got %+v", clusters[0].SubClusters)
	}

	// With sub_max_line_gap=0 (disabled), no sub-clusters should be computed.
	clusters = idx.SmcClustersByFile("writer_file", "perframe.inc", 2, 0)
	if clusters[0].SubClusters != nil {
		t.Errorf("expected nil SubClusters when disabled; got %+v", clusters[0].SubClusters)
	}
}

func TestSmcClustersByFile(t *testing.T) {
	idx := fixtureWithModuleScopeWrites()
	clusters := idx.SmcClustersByFile("writer_file", "", 2, 0)
	// Two writer-file clusters: main.inc (FlightModelUpdate's vars) and
	// polydraw.inc (module-scope vars).
	got := map[string]int{}
	for _, c := range clusters {
		got[c.Proc] = len(c.Vars)
	}
	if got["polydraw.inc"] != 2 {
		t.Errorf("polydraw.inc cluster size: %d, want 2 (got: %v)", got["polydraw.inc"], got)
	}
	if got["main.inc"] != 2 {
		t.Errorf("main.inc cluster size: %d, want 2 (got: %v)", got["main.inc"], got)
	}
	// fileFilter narrows.
	filtered := idx.SmcClustersByFile("writer_file", "polydraw.inc", 2, 0)
	if len(filtered) != 1 || filtered[0].Proc != "polydraw.inc" {
		t.Errorf("filter on polydraw.inc returned: %+v", filtered)
	}
}

// buildSmcFixture returns a tiny index pre-populated with three anchors and
// their var aliases, mimicking the FlightModelUpdate triple
// (Var_a81b/a81e/a824 → SmcAnchor_a81a/a81d/a822). The fixture deliberately
// places SmcAnchor_a71f a few hundred bytes earlier so cluster boundaries
// can be exercised.
func buildSmcFixture() *Index {
	file := "render3d.inc"
	srcFile := &source.File{Path: file, Lines: []string{
		// 1
		"SmcAnchor_a71f:: mov bx, 0",
		// 2
		"SmcAnchor_a81a:: mov ax, 0",
		// 3
		"SmcAnchor_a81d:: mov cx, 0",
		// 4
		"SmcAnchor_a822:: mov dx, 0",
	}}
	idx := &Index{
		Files:   map[string]*source.File{file: srcFile},
		Symbols: map[string][]*SymbolEntry{},
		Procs:   map[string]*ProcEntry{},
		Refs:    map[string][]*RefEntry{},
	}
	addAnchor := func(name string, addr uint32, line int) {
		idx.Symbols[name] = []*SymbolEntry{{
			Name: name, Kind: "export", File: file, Line: line,
			Addr: addr, HasAddr: true, Segment: "CSEG",
		}}
	}
	addVar := func(name, anchor string, size string, off int) {
		text := size + " ptr " + anchor
		if off > 0 {
			text += " + " + itoa(off)
		}
		idx.Symbols[name] = []*SymbolEntry{{
			Name: name, Kind: "EQU", File: "globals.inc", Line: 100, Text: text,
		}}
	}
	addAnchor("SmcAnchor_a71f", 0xa71f, 1)
	addAnchor("SmcAnchor_a81a", 0xa81a, 2)
	addAnchor("SmcAnchor_a81d", 0xa81d, 3)
	addAnchor("SmcAnchor_a822", 0xa822, 4)
	addVar("Var_a720", "SmcAnchor_a71f", "word", 1)
	addVar("Var_a81b", "SmcAnchor_a81a", "word", 1)
	addVar("Var_a81e", "SmcAnchor_a81d", "word", 1)
	addVar("Var_a824", "SmcAnchor_a822", "word", 2)
	// Writer ref: FlightModelUpdate writes Var_a81b.
	idx.Refs["Var_a81b"] = []*RefEntry{{
		Target: "Var_a81b", Kind: "mem",
		File: "main.inc", Line: 50,
		EnclosingProc: "FlightModelUpdate",
		Text:          "mov [Var_a81b], ax",
	}}
	idx.Refs["Var_a81e"] = []*RefEntry{{
		Target: "Var_a81e", Kind: "mem",
		File: "main.inc", Line: 51,
		EnclosingProc: "FlightModelUpdate",
		Text:          "mov [Var_a81e], cx",
	}}
	return idx
}

// itoa is a local int-to-string for the test fixture (avoids a strconv import).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestSmcSiteAt(t *testing.T) {
	idx := buildSmcFixture()

	// Hit on a slot address: 0xa71f + 1 = 0xa720.
	if site := idx.SmcSiteAt(0xa720); site == nil {
		t.Fatal("expected SmcSite for 0xa720")
	} else {
		if site.Anchor.Name != "SmcAnchor_a71f" {
			t.Errorf("anchor: %q", site.Anchor.Name)
		}
		if site.Var == nil || site.Var.Name != "Var_a720" {
			t.Errorf("var: %+v", site.Var)
		}
		if site.Slot.Offset != 1 || site.Slot.Size != "word" {
			t.Errorf("slot: %+v", site.Slot)
		}
		if site.HostInstruction != "mov bx, 0" {
			t.Errorf("host instr: %q", site.HostInstruction)
		}
	}

	// Hit on the anchor itself.
	if site := idx.SmcSiteAt(0xa71f); site == nil {
		t.Fatal("expected SmcSite for anchor 0xa71f")
	} else if site.Var != nil {
		t.Errorf("expected anchor-only hit, got var %q", site.Var.Name)
	}

	// Miss: address that's neither anchor nor slot.
	if site := idx.SmcSiteAt(0xb000); site != nil {
		t.Errorf("expected nil for 0xb000, got %+v", site)
	}
}

func TestSmcClusters(t *testing.T) {
	idx := buildSmcFixture()

	// Default gap (16 bytes) should keep a81a/a81d/a822 together (gaps 3, 5)
	// but split a71f into its own (which then drops as singleton with min=2).
	clusters := idx.SmcClusters("", 16, 2)
	if len(clusters) != 1 {
		t.Fatalf("got %d clusters, want 1; clusters=%+v", len(clusters), clusters)
	}
	c := clusters[0]
	if len(c.Anchors) != 3 {
		t.Errorf("cluster anchors: %d, want 3", len(c.Anchors))
	}
	if c.StartAddr != 0xa81a || c.EndAddr != 0xa822 {
		t.Errorf("cluster span: 0x%x..0x%x", c.StartAddr, c.EndAddr)
	}
	// Writer PROC propagation: only Var_a81b and Var_a81e have writers; both
	// are FlightModelUpdate, so it should appear once.
	if len(c.Procs) != 1 || c.Procs[0] != "FlightModelUpdate" {
		t.Errorf("writer procs: %v", c.Procs)
	}

	// Tighter gap (2 bytes) should split a81a/a81d (gap 3) into separate
	// clusters.
	clusters = idx.SmcClusters("", 2, 1)
	if len(clusters) < 3 {
		t.Errorf("with max_gap=2, expected >=3 clusters; got %d", len(clusters))
	}

	// min_size=1 should also surface the lone a71f cluster.
	clusters = idx.SmcClusters("", 16, 1)
	if len(clusters) != 2 {
		t.Errorf("with min_size=1, expected 2 clusters; got %d", len(clusters))
	}
}

func TestParseSmcEqu(t *testing.T) {
	cases := []struct {
		text       string
		wantOK     bool
		wantSize   string
		wantAnchor string
		wantOffset int
	}{
		{"byte ptr SmcAnchor_a71f + 1", true, "byte", "SmcAnchor_a71f", 1},
		{"word ptr SmcAnchor_edc4 + 2", true, "word", "SmcAnchor_edc4", 2},
		{"dword ptr SmcAnchor_xxxx", true, "dword", "SmcAnchor_xxxx", 0},
		{"byte ptr Foo + 0", true, "byte", "Foo", 0},
		// Negatives
		{"0FFh", false, "", "", 0},
		{"byte SmcAnchor_x", false, "", "", 0},      // missing 'ptr'
		{"qword ptr SmcAnchor_x", false, "", "", 0}, // unsupported size
		{"byte ptr Foo - 1", false, "", "", 0},      // we don't model subtraction
		{"byte ptr Foo + bar", false, "", "", 0},    // non-numeric offset
	}
	for _, c := range cases {
		slot, ok := ParseSmcEqu(c.text)
		if ok != c.wantOK {
			t.Errorf("%q: ok=%v, want %v", c.text, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if slot.Size != c.wantSize || slot.Anchor != c.wantAnchor || slot.Offset != c.wantOffset {
			t.Errorf("%q: got (%q, %q, %d), want (%q, %q, %d)",
				c.text, slot.Size, slot.Anchor, slot.Offset,
				c.wantSize, c.wantAnchor, c.wantOffset)
		}
	}
}

func TestAfterLabel(t *testing.T) {
	cases := []struct {
		line, name, want string
	}{
		{"SmcAnchor_a71f:: mov bx, 0", "SmcAnchor_a71f", "mov bx, 0"},
		{"SmcAnchor_a71f: mov bx, 0", "SmcAnchor_a71f", "mov bx, 0"},
		{"        SmcAnchor_a71f::    mov bx, 0", "SmcAnchor_a71f", "mov bx, 0"},
		{"mov bx, 0", "SmcAnchor_a71f", "mov bx, 0"},
		// label-only line
		{"SmcAnchor_a71f::", "SmcAnchor_a71f", ""},
	}
	for _, c := range cases {
		got := afterLabel(c.line, c.name)
		if got != c.want {
			t.Errorf("line=%q name=%q: got %q, want %q", c.line, c.name, got, c.want)
		}
	}
}
