package jwasm

import (
	"strings"
	"testing"
)

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

func TestParseInstructionRow(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantOK    bool
		wantAddr  uint32
		wantSize  uint32
		wantBytes string
		wantText  string
	}{
		{
			name:      "simple_3byte",
			line:      "00000000  FA                  C         cli                                     ; 0000  fa",
			wantOK:    true,
			wantAddr:  0,
			wantSize:  1,
			wantBytes: "FA",
			wantText:  "cli",
		},
		{
			name:      "with_user_comment",
			line:      "00000002  8B160200            C         mov     dx, ds:[2]                      ; 0002  PSP_TOP",
			wantOK:    true,
			wantAddr:  0x2,
			wantSize:  4,
			wantBytes: "8B160200",
			wantText:  "mov     dx, ds:[2]                      ; 0002  PSP_TOP",
		},
		{
			name:      "label_only_rejected",
			line:      "0000BE4C                      C         SmcAnchor_be4c::",
			wantOK:    false,
		},
		{
			name:      "comment_only_rejected",
			line:      "                              C ; this is a comment",
			wantOK:    false,
		},
		{
			name:      "equ_row_rejected",
			line:      " = byte ptr SmcAnchor_b47e +  C Var_b47f                equ byte ptr SmcAnchor_b47e + 1",
			wantOK:    false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ins, ok := parseInstructionRow(c.line)
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if ins.Addr != c.wantAddr || ins.Size != c.wantSize ||
				ins.Bytes != c.wantBytes || ins.Text != c.wantText {
				t.Errorf("got {addr:%x size:%d bytes:%q text:%q}, want {addr:%x size:%d bytes:%q text:%q}",
					ins.Addr, ins.Size, ins.Bytes, ins.Text,
					c.wantAddr, c.wantSize, c.wantBytes, c.wantText)
			}
		})
	}
}

func TestStripJwasmSelfComment(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Pure-hex self-comments are stripped.
		{"shl     di, 1                           ; 0232  d1 e7", "shl     di, 1"},
		// User comments are preserved (PSP_TOP is not hex).
		{"mov dx, ds:[2]                      ; 0002  PSP_TOP", "mov dx, ds:[2]                      ; 0002  PSP_TOP"},
		// No comment.
		{"cli", "cli"},
	}
	for _, c := range cases {
		got := stripJwasmSelfComment(c.in)
		// Trim trailing whitespace introduced by the strip for fair compare.
		got = strings.TrimRight(got, " \t")
		want := strings.TrimRight(c.want, " \t")
		if got != want {
			t.Errorf("in=%q\n got=%q\nwant=%q", c.in, got, want)
		}
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
