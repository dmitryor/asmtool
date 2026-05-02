package rename

import "testing"

func TestRewriteLineGlobalWordBoundary(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"        call    Blit", "        call    BlitImage"},
		{"        call    BlitMasked", "        call    BlitMasked"},        // suffix; don't rewrite
		{"        jmp     short Blit", "        jmp     short BlitImage"},
		{"        mov     ax, offset Blit", "        mov     ax, offset BlitImage"},
		{"        ; calls Blit and BlitFullScreen", "        ; calls BlitImage and BlitFullScreen"},
		{"        je      @@Blit", "        je      @@Blit"}, // local prefix; don't touch when renaming global
		{"Blit PROC NEAR", "BlitImage PROC NEAR"},
		{"        ; word Blitting things", "        ; word Blitting things"}, // not a word match
	}
	for _, c := range cases {
		got := rewriteLine(c.in, "Blit", "BlitImage", false)
		if got != c.want {
			t.Errorf("global rename %q\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}

func TestRewriteLineLocal(t *testing.T) {
	got := rewriteLine("        je      @@Done", "Done", "Finished", true)
	want := "        je      @@Finished"
	if got != want {
		t.Errorf("local rename: got %q, want %q", got, want)
	}
	// Ensure global "Done" not rewritten when scoped local
	got = rewriteLine("        call    Done", "Done", "Finished", true)
	want = "        call    Done"
	if got != want {
		t.Errorf("local rename should not touch global Done: got %q", got)
	}
}

func TestValidIdent(t *testing.T) {
	yes := []string{"Foo", "foo_bar", "_x", "ABC123"}
	no := []string{"", "1foo", "foo bar", "foo-bar", "@@foo"}
	for _, s := range yes {
		if !validIdent(s) {
			t.Errorf("validIdent(%q) should be true", s)
		}
	}
	for _, s := range no {
		if validIdent(s) {
			t.Errorf("validIdent(%q) should be false", s)
		}
	}
}

func TestContainsWord(t *testing.T) {
	if !containsWord("calls Blit here", "Blit") {
		t.Error("Blit should match")
	}
	if containsWord("BlitMasked", "Blit") {
		t.Error("substring should not match")
	}
	if !containsWord("Blit", "Blit") {
		t.Error("exact match")
	}
	if !containsWord("Blit ", "Blit") {
		t.Error("trailing space ok")
	}
}
