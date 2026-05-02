package source

import (
	"strings"
	"testing"
)

func parseString(t *testing.T, src string) *File {
	t.Helper()
	f, err := parseReader("test.inc", strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f
}

func TestProcBoundaries(t *testing.T) {
	src := `
Foo PROC NEAR
        mov ax, bx
        ret
Foo ENDP

Bar PROC NEAR
        call Foo
Bar ENDP
`
	f := parseString(t, src)
	if len(f.Procs) != 2 {
		t.Fatalf("got %d procs, want 2", len(f.Procs))
	}
	if f.Procs[0].Name != "Foo" || f.Procs[0].StartLine != 2 || f.Procs[0].EndLine != 5 {
		t.Errorf("Foo: %+v", f.Procs[0])
	}
	if f.Procs[1].Name != "Bar" || f.Procs[1].EndLine != 9 {
		t.Errorf("Bar: %+v", f.Procs[1])
	}
}

func TestRefKinds(t *testing.T) {
	src := `
Caller PROC NEAR
        call    Target              ; call ref
        jmp     ElseWhere           ; jmp ref
        mov     ax, offset Marker   ; offset ref
        mov     ax, ds:[Slot]       ; mem ref
        mov     bx, [BasePtr+4]     ; mem ref
        mov     cx, ImmValue        ; imm ref
        dw      JumpTbl, OtherTbl   ; data refs
Caller ENDP
`
	f := parseString(t, src)
	want := map[string]RefKind{
		"Target":    RefCall,
		"ElseWhere": RefJmp,
		"Marker":    RefOffset,
		"Slot":      RefMem,
		"BasePtr":   RefMem,
		"ImmValue":  RefImm,
		"JumpTbl":   RefDataWord,
		"OtherTbl":  RefDataWord,
	}
	got := map[string]RefKind{}
	for _, r := range f.Refs {
		got[r.Target] = r.Kind
	}
	for name, k := range want {
		if got[name] != k {
			t.Errorf("%s: got %v, want %v", name, got[name], k)
		}
	}
}

func TestLocalLabels(t *testing.T) {
	src := `
Outer PROC NEAR
        cmp ax, 0
        je @@Done
        loop @@Done
@@Done:
        ret
Outer ENDP
`
	f := parseString(t, src)
	if len(f.Procs) != 1 {
		t.Fatalf("procs: %d", len(f.Procs))
	}
	if len(f.Procs[0].LocalLabels) != 1 {
		t.Fatalf("local labels: %d", len(f.Procs[0].LocalLabels))
	}
	if f.Procs[0].LocalLabels[0].Name != "Done" {
		t.Errorf("local name: %q", f.Procs[0].LocalLabels[0].Name)
	}
	// Refs to @@Done should also be recorded
	doneRefs := 0
	for _, r := range f.Refs {
		if r.Target == "Done" {
			doneRefs++
		}
	}
	if doneRefs != 2 {
		t.Errorf("got %d Done refs, want 2", doneRefs)
	}
}

func TestExportLabel(t *testing.T) {
	src := `
EntryA::
        ret
`
	f := parseString(t, src)
	found := false
	for _, l := range f.Labels {
		if l.Name == "EntryA" && l.Kind == LabelExport {
			found = true
		}
	}
	if !found {
		t.Errorf("EntryA export label not found; labels=%v", f.Labels)
	}
}

func TestEqu(t *testing.T) {
	src := `
DiskCacheFlag equ 0e922h
TopGunList    equ 0eaf3h
`
	f := parseString(t, src)
	equs := 0
	for _, l := range f.Labels {
		if l.Kind == LabelEqu {
			equs++
		}
	}
	if equs != 2 {
		t.Errorf("got %d EQUs, want 2", equs)
	}
}

func TestNumericLiteralRejection(t *testing.T) {
	src := `
Foo PROC NEAR
        mov ax, 0FFh
        mov bx, 1234h
        mov cx, 100h
Foo ENDP
`
	f := parseString(t, src)
	for _, r := range f.Refs {
		if r.Target == "FFh" || r.Target == "1234h" || r.Target == "100h" {
			t.Errorf("hex literal mistaken for symbol: %q", r.Target)
		}
	}
}
