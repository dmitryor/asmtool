package rename

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dmitryor/asmtool/internal/index"
	"github.com/dmitryor/asmtool/internal/source"
)

func TestRewriteLineGlobalWordBoundary(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"        call    Blit", "        call    BlitImage"},
		{"        call    BlitMasked", "        call    BlitMasked"}, // suffix; don't rewrite
		{"        jmp     short Blit", "        jmp     short BlitImage"},
		{"        mov     ax, offset Blit", "        mov     ax, offset BlitImage"},
		{"        ; calls Blit and BlitFullScreen", "        ; calls BlitImage and BlitFullScreen"},
		{"        je      @@Blit", "        je      @@Blit"}, // local prefix; don't touch when renaming global
		{"Blit PROC NEAR", "BlitImage PROC NEAR"},
		{"Blit ENDP", "BlitImage ENDP"},
		{"        ; word Blitting things", "        ; word Blitting things"}, // not a word match
		{"        db      'Blit'", "        db      'Blit'"},                 // code string literal
		{"        db      'Blit'          ; Blit helper", "        db      'Blit'          ; BlitImage helper"},
		{"        ; don't call Blit yet", "        ; don't call BlitImage yet"},
		{"PUBLIC  Blit, BlitMasked", "PUBLIC  BlitImage, BlitMasked"},
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

func TestCombinePlansPreservesSharedLineEdits(t *testing.T) {
	before := "call OldOne ; jmp OldTwo"
	plans := []*Plan{
		{OldName: "OldOne", NewName: "NewOne", Edits: []Edit{{
			File: "x.inc", Line: 1, Before: before, After: "call NewOne ; jmp OldTwo",
		}}},
		{OldName: "OldTwo", NewName: "NewTwo", Edits: []Edit{{
			File: "x.inc", Line: 1, Before: before, After: "call OldOne ; jmp NewTwo",
		}}},
	}
	got := CombinePlans(plans...)
	if len(got.Edits) != 1 {
		t.Fatalf("got %d edits, want 1", len(got.Edits))
	}
	if got.Edits[0].After != "call NewOne ; jmp NewTwo" {
		t.Fatalf("after = %q", got.Edits[0].After)
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

func TestPlanRenameUpdatesEndpAndComments(t *testing.T) {
	src := `; Foo draws a sprite. Not FooMasked.
Foo PROC NEAR
        call    Other
        db      'Foo'          ; tagged Foo
        ret
Foo ENDP

PUBLIC  Foo, FooMasked

Other PROC NEAR
        call    Foo            ; dispatch to Foo
Other ENDP
`
	plan := planFrom(t, src, "Foo", "FooImage")
	got := map[string]string{}
	for _, e := range plan.Edits {
		got[e.Before] = e.After
	}

	want := []struct{ before, after string }{
		{"; Foo draws a sprite. Not FooMasked.", "; FooImage draws a sprite. Not FooMasked."},
		{"Foo PROC NEAR", "FooImage PROC NEAR"},
		{"        db      'Foo'          ; tagged Foo", "        db      'Foo'          ; tagged FooImage"},
		{"Foo ENDP", "FooImage ENDP"},
		{"PUBLIC  Foo, FooMasked", "PUBLIC  FooImage, FooMasked"},
		{"        call    Foo            ; dispatch to Foo", "        call    FooImage            ; dispatch to FooImage"},
	}
	for _, w := range want {
		if got[w.before] != w.after {
			t.Errorf("line %q\n  got  %q\n  want %q", w.before, got[w.before], w.after)
		}
	}
	for _, e := range plan.Edits {
		if strings.Contains(e.After, "FooImageMasked") {
			t.Errorf("rewrote suffix name FooMasked: %q", e.After)
		}
		if strings.Contains(e.Before, "db") && strings.Contains(e.After, "'FooImage'") {
			t.Errorf("rewrote string literal: %q", e.After)
		}
	}
}

func TestPlanRenameLocalLeavesBareCommentWord(t *testing.T) {
	src := `Outer PROC NEAR
        je      @@Done         ; @@Done, not Done
@@Done:
        ret
Outer ENDP
`
	plan := planFrom(t, src, "Done", "Finished")
	if !plan.IsLocal {
		t.Fatal("expected local rename")
	}
	foundJe, foundLabel, foundBare := false, false, false
	for _, e := range plan.Edits {
		if strings.Contains(e.After, "je      @@Finished") && strings.Contains(e.After, "; @@Finished, not Done") {
			foundJe = true
		}
		if e.After == "@@Finished:" {
			foundLabel = true
		}
		if strings.Contains(e.After, "not Finished") {
			foundBare = true
		}
	}
	if !foundJe {
		t.Error("missing @@Done jump/comment rewrite")
	}
	if !foundLabel {
		t.Error("missing @@Done label rewrite")
	}
	if foundBare {
		t.Error("bare Done in comment should stay; locals only match @@Done")
	}
}

func TestPlanRenameCommentOutsideOtherProc(t *testing.T) {
	src := `Keep PROC NEAR
        nop                    ; mentions Foo in another proc's comment
        ret
Keep ENDP

Foo PROC NEAR
        ret
Foo ENDP
`
	plan := planFrom(t, src, "Foo", "FooImage", withInProc("Keep"))
	for _, e := range plan.Edits {
		if strings.Contains(e.Before, "Foo PROC") || strings.Contains(e.Before, "Foo ENDP") {
			t.Errorf("InProc=Keep should not rewrite Foo's declaration: %q", e.Before)
		}
	}
	found := false
	for _, e := range plan.Edits {
		if strings.Contains(e.After, "mentions FooImage") {
			found = true
		}
	}
	if !found {
		t.Error("comment inside Keep should still rewrite the global name")
	}
}

type planOpt func(*Options)

func withInProc(name string) planOpt {
	return func(o *Options) { o.InProc = name }
}

func planFrom(t *testing.T, src, old, new string, opts ...planOpt) *Plan {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.inc")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := source.ParseFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	idx := index.Build([]*source.File{f}, nil)
	o := Options{}
	for _, opt := range opts {
		opt(&o)
	}
	plan, err := PlanRename(idx, old, new, o)
	if err != nil {
		t.Fatalf("PlanRename: %v", err)
	}
	return plan
}
