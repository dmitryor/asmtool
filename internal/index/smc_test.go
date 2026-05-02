package index

import (
	"testing"

	"github.com/orlovsky/jwasm-mcp/internal/source"
)

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
