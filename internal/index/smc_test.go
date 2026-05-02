package index

import (
	"testing"

	"github.com/orlovsky/jwasm-mcp/internal/jwasm"
	"github.com/orlovsky/jwasm-mcp/internal/source"
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

func TestSmcClustersByProc(t *testing.T) {
	idx := buildSmcFixture()
	// buildSmcFixture has FlightModelUpdate writing Var_a81b and Var_a81e.
	// Both should land in one writer cluster of size 2.
	clusters := idx.SmcClustersByProc("writer_proc", "", 2)
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
	if r := idx.SmcClustersByProc("reader_proc", "", 2); len(r) != 0 {
		t.Errorf("reader clusters: %d", len(r))
	}
	// proc filter narrows correctly.
	if r := idx.SmcClustersByProc("writer_proc", "OtherProc", 2); len(r) != 0 {
		t.Errorf("filter narrowed to OtherProc but got %d", len(r))
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
		{"byte SmcAnchor_x", false, "", "", 0},        // missing 'ptr'
		{"qword ptr SmcAnchor_x", false, "", "", 0},   // unsupported size
		{"byte ptr Foo - 1", false, "", "", 0},        // we don't model subtraction
		{"byte ptr Foo + bar", false, "", "", 0},      // non-numeric offset
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
