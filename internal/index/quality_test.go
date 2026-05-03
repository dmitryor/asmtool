package index

import (
	"testing"

	"github.com/orlovsky/jwasm-mcp/internal/source"
)

func buildSpacingFixture() *Index {
	file := "mission.inc"
	lines := []string{}
	// Build a synthetic 200-line file:
	// PROC A from line 1..3
	// 5 blank lines
	// preamble (1 ;-line)
	// PROC B from line 10..12
	for i := 0; i < 200; i++ {
		lines = append(lines, "")
	}
	lines[0] = "ProcA PROC NEAR"
	lines[1] = "    ret"
	lines[2] = "ProcA ENDP"
	// blank lines [3..7] (5 blanks at lines 4..8)
	lines[8] = "; preamble for B"
	lines[9] = "ProcB PROC NEAR"
	lines[10] = "    ret"
	lines[11] = "ProcB ENDP"

	idx := &Index{
		Files: map[string]*source.File{file: {Path: file, Lines: lines}},
		Procs: map[string]*ProcEntry{
			"ProcA": {Name: "ProcA", File: file, StartLine: 1, EndLine: 3},
			"ProcB": {Name: "ProcB", File: file, StartLine: 10, EndLine: 12},
		},
		Symbols: map[string][]*SymbolEntry{},
		Refs:    map[string][]*RefEntry{},
	}
	return idx
}

func TestProcSpacing(t *testing.T) {
	idx := buildSpacingFixture()
	pairs := idx.ProcSpacing("mission.inc")
	if len(pairs) != 1 {
		t.Fatalf("got %d pairs, want 1", len(pairs))
	}
	p := pairs[0]
	if p.PrevProc != "ProcA" || p.NextProc != "ProcB" {
		t.Errorf("pair: %+v", p)
	}
	// Lines 4..8 are blank (5 blanks); preamble at 9; PROC at 10.
	if p.NextPreambleStartLine != 9 {
		t.Errorf("preamble start: %d, want 9", p.NextPreambleStartLine)
	}
	if p.BlankLines != 5 {
		t.Errorf("blank lines: %d, want 5", p.BlankLines)
	}
}

func TestProcHeaderCardCoverage(t *testing.T) {
	file := "x.inc"
	lines := make([]string, 50)
	// Structured card before ProcA at line 12.
	lines[3] = ";=========================================================================="
	lines[4] = "; ProcA -- compute the thing."
	lines[5] = "; In:  AX = input"
	lines[6] = "; Out: BX = output"
	lines[7] = ";=========================================================================="
	lines[8] = "ProcA PROC NEAR"
	lines[9] = "    ret"
	lines[10] = "ProcA ENDP"
	// Legacy banner before ProcB at line 16.
	lines[14] = "; ---- ProcB"
	lines[15] = "ProcB PROC NEAR"
	lines[16] = "    ret"
	lines[17] = "ProcB ENDP"
	// Missing header before ProcC at line 21.
	lines[19] = ""
	lines[20] = "ProcC PROC NEAR"
	lines[21] = "    ret"
	lines[22] = "ProcC ENDP"
	// One-liner before ProcD at line 26.
	lines[24] = "; trivial helper"
	lines[25] = "ProcD PROC NEAR"
	lines[26] = "    ret"
	lines[27] = "ProcD ENDP"

	idx := &Index{
		Files: map[string]*source.File{file: {Path: file, Lines: lines}},
		Procs: map[string]*ProcEntry{
			"ProcA": {Name: "ProcA", File: file, StartLine: 9, EndLine: 11},
			"ProcB": {Name: "ProcB", File: file, StartLine: 16, EndLine: 18},
			"ProcC": {Name: "ProcC", File: file, StartLine: 21, EndLine: 23},
			"ProcD": {Name: "ProcD", File: file, StartLine: 26, EndLine: 28},
		},
		Symbols: map[string][]*SymbolEntry{},
		Refs:    map[string][]*RefEntry{},
	}
	cards := idx.ProcHeaderCardCoverage(file, "")
	got := map[string]ProcHeaderCard{}
	for _, c := range cards {
		got[c.Proc] = c
	}
	if got["ProcA"].HeaderKind != HeaderStructured {
		t.Errorf("ProcA: %+v", got["ProcA"])
	}
	if !contains(got["ProcA"].FieldsPresent, "purpose") || !contains(got["ProcA"].FieldsPresent, "in") {
		t.Errorf("ProcA fields: %v", got["ProcA"].FieldsPresent)
	}
	if got["ProcB"].HeaderKind != HeaderLegacyBanner {
		t.Errorf("ProcB: %+v", got["ProcB"])
	}
	if got["ProcC"].HeaderKind != HeaderMissing {
		t.Errorf("ProcC: %+v", got["ProcC"])
	}
	if got["ProcD"].HeaderKind != HeaderOneLiner {
		t.Errorf("ProcD: %+v", got["ProcD"])
	}
}

func TestParseNumericLiteral(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"0x1234", 0x1234, true},
		{"01234h", 0x1234, true},
		{"1234", 1234, true},
		{"100b", 4, true},
		{"0xff", 0xff, true},
		{"abc", 0, false},
		{"abcd", 0, false},  // bare ident with no marker -- not numeric
		{"", 0, false},
	}
	for _, c := range cases {
		v, ok := parseNumericLiteral(c.in)
		if ok != c.ok {
			t.Errorf("%q: ok=%v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && v != c.want {
			t.Errorf("%q: got %d, want %d", c.in, v, c.want)
		}
	}
}

func TestIsSubstantiveComment_PlaceholderTodos(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// Substantive content -- still true
		{"saturate ceiling", true},
		{"TODO: verify whether DX is preserved across SubStep", true},
		{"PROC for the missile-track update; called per-frame", true},
		// Placeholder banner: exact pattern
		{"FixedMul -- TODO: describe this function.", false},
		{"FixedMul -- TODO: describe this function", false},
		// Bare placeholder tokens
		{"TODO", false},
		{"XXX", false},
		{"FIXME", false},
		{"TODO: describe", false},
		// Empty / verify-script artefacts (existing behaviour)
		{"", false},
		{"b234 c7 06 00 00", false},
	}
	for _, c := range cases {
		got := isSubstantiveComment(c.in)
		if got != c.want {
			t.Errorf("%q: got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestProcHeaderCardCoverage_PlaceholderOneLiner(t *testing.T) {
	file := "x.inc"
	lines := make([]string, 12)
	lines[5] = "; FixedMul -- TODO: describe this function."
	lines[6] = "FixedMul PROC NEAR"
	lines[7] = "    ret"
	lines[8] = "FixedMul ENDP"
	idx := &Index{
		Files: map[string]*source.File{file: {Path: file, Lines: lines}},
		Procs: map[string]*ProcEntry{
			"FixedMul": {Name: "FixedMul", File: file, StartLine: 7, EndLine: 9},
		},
		Symbols: map[string][]*SymbolEntry{},
		Refs:    map[string][]*RefEntry{},
	}
	cards := idx.ProcHeaderCardCoverage(file, "")
	if len(cards) != 1 {
		t.Fatalf("got %d cards, want 1", len(cards))
	}
	if cards[0].HeaderKind != HeaderLegacyBanner {
		t.Errorf("placeholder one-liner should be legacy_banner; got %+v", cards[0])
	}
}

func TestIsSelfEvidentBitPattern(t *testing.T) {
	for _, v := range []uint64{0xFFFF, 0x8000, 0x8080, 0x7FFF, 0x000F, 0xF000, 0xFF00, 0x00FF} {
		if !isSelfEvidentBitPattern(v) {
			t.Errorf("%x should be self-evident", v)
		}
	}
	for _, v := range []uint64{0x1234, 0xb234, 0x100, 0xc8} {
		if isSelfEvidentBitPattern(v) {
			t.Errorf("%x should NOT be self-evident", v)
		}
	}
}

func TestMagicImmediateScan(t *testing.T) {
	file := "perframe.inc"
	lines := []string{
		"AdvanceWeaponState PROC NEAR",
		"    mov ax, 0x3fff       ; saturate ceiling",
		"    cmp dx, 0c8h",
		"    out dx, 200h",
		"    mov si, 0xffff",
		"    cmp ax, 50",
		"AdvanceWeaponState ENDP",
	}
	idx := &Index{
		Files: map[string]*source.File{file: {Path: file, Lines: lines}},
		Procs: map[string]*ProcEntry{
			"AdvanceWeaponState": {Name: "AdvanceWeaponState", File: file, StartLine: 1, EndLine: 7},
		},
		Symbols: map[string][]*SymbolEntry{},
		Refs:    map[string][]*RefEntry{},
	}
	hits := idx.MagicImmediateScan(file, "", 0x100)
	// Expected: 0x3fff (annotated), 0xc8 (excluded -- below threshold; SKIPPED),
	//           0x200 (port; no EQU, not excluded), 0xffff (bit_pattern excluded),
	//           50 (below threshold).
	// 0xc8 is below 0x100, so it's filtered. 50 is below too.
	wantValues := map[int64]bool{0x3fff: true, 0x200: true, 0xffff: true}
	got := map[int64]bool{}
	for _, h := range hits {
		got[h.Value] = true
	}
	for v := range wantValues {
		if !got[v] {
			t.Errorf("missing value 0x%x in scan; got=%v", v, got)
		}
	}
	for _, h := range hits {
		switch h.Value {
		case 0x3fff:
			if !h.HasSubstantiveAnnotation {
				t.Errorf("0x3fff should have substantive annotation; got %+v", h)
			}
		case 0xffff:
			if !h.IsExcluded || h.ExclusionReason != "bit_pattern" {
				t.Errorf("0xffff should be excluded as bit_pattern; got %+v", h)
			}
		}
	}
}

func TestXrefCoverage(t *testing.T) {
	srcFile := "render3d.inc"
	mathFile := "math.inc"
	globalsFile := "globals.inc"
	srcLines := []string{
		"ProjectVertex PROC NEAR",
		"    call FixedMul                            ; signed 16x16 fixed-point product",
		"    mov ax, [ScreenWidth]",
		"    mov [LocalCounter], bx",
		"ProjectVertex ENDP",
	}
	// math.inc: FixedMul at line 5 with a structured preamble (lines 2..4).
	mathLines := make([]string, 10)
	mathLines[1] = ";=========================================================================="
	mathLines[2] = "; Signed 16x16 -> 32 fixed-point multiply."
	mathLines[3] = ";=========================================================================="
	mathLines[4] = "FixedMul PROC NEAR"
	// globals.inc: ScreenWidth at line 5 with NO preamble.
	globalsLines := make([]string, 10)
	globalsLines[4] = "ScreenWidth dw 0"
	idx := &Index{
		Files: map[string]*source.File{
			srcFile:     {Path: srcFile, Lines: srcLines},
			mathFile:    {Path: mathFile, Lines: mathLines},
			globalsFile: {Path: globalsFile, Lines: globalsLines},
		},
		Procs: map[string]*ProcEntry{
			"ProjectVertex": {Name: "ProjectVertex", File: srcFile, StartLine: 1, EndLine: 5},
			"FixedMul":      {Name: "FixedMul", File: mathFile, StartLine: 5, EndLine: 9},
		},
		Symbols: map[string][]*SymbolEntry{
			"FixedMul":     {{Name: "FixedMul", Kind: "PROC", File: mathFile, Line: 5}},
			"ScreenWidth":  {{Name: "ScreenWidth", Kind: "data", File: globalsFile, Line: 5}},
			"LocalCounter": {{Name: "LocalCounter", Kind: "data", File: srcFile, Line: 30}},
		},
		Refs: map[string][]*RefEntry{
			"FixedMul": {{
				Target: "FixedMul", Kind: "call",
				File: srcFile, Line: 2, EnclosingProc: "ProjectVertex",
				Text: "    call FixedMul                            ; signed 16x16 fixed-point product",
			}},
			"ScreenWidth": {{
				Target: "ScreenWidth", Kind: "mem",
				File: srcFile, Line: 3, EnclosingProc: "ProjectVertex",
				Text: "    mov ax, [ScreenWidth]",
			}},
			"LocalCounter": {{
				Target: "LocalCounter", Kind: "mem",
				File: srcFile, Line: 4, EnclosingProc: "ProjectVertex",
				Text: "    mov [LocalCounter], bx",
			}},
		},
	}
	xrefs := idx.XrefCoverageScan(srcFile, "", nil)
	if len(xrefs) != 3 {
		t.Fatalf("got %d xrefs, want 3", len(xrefs))
	}
	got := map[string]XrefCoverage{}
	for _, x := range xrefs {
		got[x.TargetSymbol] = x
	}
	// FixedMul: inline-annotated -> covered via inline.
	if got["FixedMul"].Kind != "call" || !got["FixedMul"].ExternalToModule {
		t.Errorf("FixedMul: %+v", got["FixedMul"])
	}
	if !got["FixedMul"].InlineIsSubstantive {
		t.Errorf("FixedMul should be inline-annotated; got %+v", got["FixedMul"])
	}
	// FixedMul's declaration also has a substantive preamble.
	if !got["FixedMul"].TargetIsSubstantive {
		t.Errorf("FixedMul preamble should be substantive; got block=%q", got["FixedMul"].TargetCommentBlock)
	}
	// ScreenWidth: no inline comment, no declaration preamble -> uncovered.
	if got["ScreenWidth"].Kind != "mem_read" || !got["ScreenWidth"].ExternalToModule {
		t.Errorf("ScreenWidth: %+v", got["ScreenWidth"])
	}
	if got["ScreenWidth"].InlineIsSubstantive || got["ScreenWidth"].TargetIsSubstantive {
		t.Errorf("ScreenWidth should be UNcovered; got %+v", got["ScreenWidth"])
	}
	// LocalCounter: intra-module + write classification.
	if got["LocalCounter"].Kind != "mem_write" || got["LocalCounter"].ExternalToModule {
		t.Errorf("LocalCounter: %+v", got["LocalCounter"])
	}
	// kinds filter
	xrefs = idx.XrefCoverageScan(srcFile, "", []string{"call"})
	if len(xrefs) != 1 || xrefs[0].TargetSymbol != "FixedMul" {
		t.Errorf("call-only filter: %+v", xrefs)
	}
}
