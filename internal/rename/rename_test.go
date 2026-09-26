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
		{"        call    Foo            ; dispatch to Foo", "        call    FooImage       ; dispatch to FooImage"},
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

func TestPlanRenameAcceptsAtAtLocalNames(t *testing.T) {
	src := `Outer PROC NEAR
        je      @@Done
@@Done:
        ret
Outer ENDP
`
	plan := planFrom(t, src, "@@Done", "@@Finished", func(o *Options) { o.InProc = "Outer" })
	if !plan.IsLocal || plan.OldName != "Done" || plan.NewName != "Finished" {
		t.Fatalf("plan = local %v, %q -> %q", plan.IsLocal, plan.OldName, plan.NewName)
	}
	found := map[string]bool{}
	for _, e := range plan.Edits {
		found[strings.TrimSpace(e.After)] = true
	}
	if !found["je      @@Finished"] || !found["@@Finished:"] {
		t.Errorf("edits = %+v", plan.Edits)
	}
}

func TestPlanRenameRefusesAtAtForGlobal(t *testing.T) {
	src := `Foo PROC NEAR
        ret
Foo ENDP
`
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
	if _, err := PlanRename(idx, "Foo", "@@Bar", Options{}); err == nil ||
		!strings.Contains(err.Error(), "not a PROC-local label") {
		t.Fatalf("err = %v", err)
	}
}

func TestRewriteLineKeepsPaddedColumns(t *testing.T) {
	cases := []struct {
		in, old, new, want string
	}{
		// Shorter name: the padding grows and the comment column stays.
		{"        call    LongName_Old   ; 70c2  e8 39 ec", "LongName_Old", "Short",
			"        call    Short          ; 70c2  e8 39 ec"},
		{"nested_lo_ground       EQU 7ch", "nested_lo_ground", "nested_ground",
			"nested_ground          EQU 7ch"},
		// Longer name: the padding shrinks, but never below one space.
		{"        call    Foo  ; x", "Foo", "FooImageLonger", "        call    FooImageLonger ; x"},
		// One space is a separator, not alignment.
		{"        call    Foo ; x", "Foo", "FooImage", "        call    FooImage ; x"},
		// Inside a comment the spacing is prose and stays.
		{"        nop     ; Foo   bar", "Foo", "FooImage", "        nop     ; FooImage   bar"},
		// The next padded gap absorbs the change even past other operands.
		{"        mov     byte ptr ds:[Foo], al           ; c71d  a2 4f f0", "Foo", "FooLonger",
			"        mov     byte ptr ds:[FooLonger], al     ; c71d  a2 4f f0"},
		// Two renames on a line add up; a quoted string is not a gap.
		{"        db      Foo, 'a    b', Foo    ; x", "Foo", "Fo",
			"        db      Fo, 'a    b', Fo      ; x"},
		// Nothing after the padding: trailing spaces are left alone.
		{"        call    Foo   ", "Foo", "FooImage", "        call    FooImage   "},
	}
	for _, c := range cases {
		if got := rewriteLine(c.in, c.old, c.new, false); got != c.want {
			t.Errorf("%q: %s -> %s\n  got  %q\n  want %q", c.in, c.old, c.new, got, c.want)
		}
	}
}
