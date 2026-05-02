package jwasm

import "testing"

func TestParseSymbolRow(t *testing.T) {
	cases := []struct {
		line string
		name string
		kind SymbolKind
		val  uint32
	}{
		{"Var_e924 . . . . . . . . . . . .        Byte            E924h CSEG", "Var_e924", SymByte, 0xE924},
		{"DiskCacheFlag . . . . . . . . . .        Number          E922h", "DiskCacheFlag", SymNumber, 0xE922},
		{"WORD_1000_fad0 . . . . . . . . .        L Near          FAD0h CSEG", "WORD_1000_fad0", SymLabelNear, 0xFAD0},
		{"Main . . . . . . . . . . . . . .        P Near   0000     CSEG     022E Public   ", "Main", SymProc, 0x0000},
		{"Blit . . . . . . . . . . . . . .        P Near   65A0     CSEG     0087 Public   ", "Blit", SymProc, 0x65A0},
	}
	for _, c := range cases {
		s, ok := parseSymbolRow(c.line)
		if !ok {
			t.Errorf("failed to parse: %q", c.line)
			continue
		}
		if s.Name != c.name || s.Kind != c.kind || s.Value != c.val {
			t.Errorf("got (%q, %v, %x), want (%q, %v, %x)", s.Name, s.Kind, s.Value, c.name, c.kind, c.val)
		}
	}

	// Length field for PROC rows
	procRow := "Blit . . . . . . . . . . . . . .        P Near   65A0     CSEG     0087 Public   "
	s, _ := parseSymbolRow(procRow)
	if s.Length != 0x0087 {
		t.Errorf("Blit length: got %#x, want 0x87", s.Length)
	}
	procRow2 := "Main . . . . . . . . . . . . . .        P Near   0000     CSEG     022E Public   "
	s2, _ := parseSymbolRow(procRow2)
	if s2.Length != 0x022E {
		t.Errorf("Main length: got %#x, want 0x22e", s2.Length)
	}
}

func TestParseSymbolRowText(t *testing.T) {
	line := "Var_edc5 . . . . . . . . . . . .        Text   byte ptr SmcAnchor_edc4 + 1"
	s, ok := parseSymbolRow(line)
	if !ok {
		t.Fatalf("failed to parse Text row")
	}
	if s.Name != "Var_edc5" || s.Kind != SymText {
		t.Errorf("name/kind: got (%q, %v)", s.Name, s.Kind)
	}
	if s.Text == "" {
		t.Errorf("Text body empty")
	}
}
