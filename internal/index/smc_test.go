package index

import "testing"

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
