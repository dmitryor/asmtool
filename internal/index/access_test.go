package index

import "testing"

func TestClassifyAccess(t *testing.T) {
	cases := []struct {
		name   string
		text   string
		target string
		kind   string // ref kind passed to the classifier
		want   string
	}{
		// mov dst, src
		{"mov_write", "mov [Var_a720], ax", "Var_a720", "mem", "write"},
		{"mov_read", "mov ax, [Var_a720]", "Var_a720", "mem", "read"},
		{"mov_word_ptr_write", "mov word ptr [Var_a720], 0", "Var_a720", "mem", "write"},
		{"mov_seg_override_read", "mov bx, ds:[Var_a720]", "Var_a720", "mem", "read"},
		// rw operations
		{"and_rw", "and [Var_a720], 0fh", "Var_a720", "mem", "rw"},
		{"add_rw", "add [Var_a720], cx", "Var_a720", "mem", "rw"},
		{"add_read", "add ax, [Var_a720]", "Var_a720", "mem", "read"},
		{"inc_rw", "inc word ptr [Var_a720]", "Var_a720", "mem", "rw"},
		{"dec_rw", "dec [Counter]", "Counter", "mem", "rw"},
		// xchg both
		{"xchg_rw", "xchg ax, [Var_a720]", "Var_a720", "mem", "rw"},
		// cmp/test read both
		{"cmp_read", "cmp [Var_a720], 5", "Var_a720", "mem", "read"},
		{"test_read", "test [Var_a720], 1", "Var_a720", "mem", "read"},
		// push read, pop write
		{"push_read", "push [Var_a720]", "Var_a720", "mem", "read"},
		{"pop_write", "pop [Var_a720]", "Var_a720", "mem", "write"},
		// non-mem refs return ""
		{"imm_ignored", "mov bx, Var_a720", "Var_a720", "imm", ""},
		{"call_ignored", "call SomeProc", "SomeProc", "call", ""},
		{"offset_ignored", "mov ax, offset Var_a720", "Var_a720", "offset", ""},
		// label-prefixed line
		{"label_then_mov", "Label1: mov [Var], ax", "Var", "mem", "write"},
		// substring guard: Var_a72 should not match Var_a720
		{"substring_guard", "mov [Var_a720], ax", "Var_a72", "mem", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &RefEntry{Target: c.target, Text: c.text, Kind: c.kind}
			got := ClassifyAccess(r)
			if got != c.want {
				t.Errorf("text=%q target=%q: got %q, want %q", c.text, c.target, got, c.want)
			}
		})
	}
}

func TestSplitOperands(t *testing.T) {
	cases := []struct {
		text          string
		mnem, dst, src string
	}{
		{"mov ax, bx", "mov", "ax", "bx"},
		{"add [Var], cx", "add", "[Var]", "cx"},
		{"inc word ptr [Var]", "inc", "word ptr [Var]", ""},
		{"Foo: mov ax, bx", "mov", "ax", "bx"},
		{"mov ax, ds:[Slot+4]", "mov", "ax", "ds:[Slot+4]"},
	}
	for _, c := range cases {
		mnem, dst, src := splitOperands(c.text)
		if mnem != c.mnem || dst != c.dst || src != c.src {
			t.Errorf("%q: got (%q, %q, %q), want (%q, %q, %q)",
				c.text, mnem, dst, src, c.mnem, c.dst, c.src)
		}
	}
}
