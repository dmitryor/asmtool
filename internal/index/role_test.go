package index

import "testing"

func TestClassifyHostRole(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		// value-load family
		{"mov bx, 0", "value_load_imm"},
		{"mov ax, 1234h", "value_load_imm"},
		{"mov bh, 0", "value_load_imm"},
		// stack anchor
		{"mov sp, 0c00h", "stack_anchor"},
		// deferred write (mov to memory)
		{"mov [Var_a720], ax", "deferred_write"},
		{"mov word ptr [Var_a720], 0", "deferred_write"},
		{"mov ds:[Slot], 5", "deferred_write"},
		// threshold
		{"cmp dx, 80h", "threshold"},
		{"cmp byte ptr ds:[Var], 0ch", "threshold"},
		{"test ax, 1", "threshold"},
		// delta
		{"add ax, 4", "delta"},
		{"sub di, 0728h", "delta"},
		{"inc word ptr [Counter]", "delta"},
		// mask
		{"and ax, 0fh", "mask"},
		{"or bx, 0ffffh", "mask"},
		{"xor cx, cx", "mask"},
		// shift
		{"shl di, 1", "shift"},
		{"shr ah, 4", "shift"},
		// interrupt
		{"int 21h", "interrupt_vector"},
		// data
		{"db 0ffh", "data_filler"},
		{"dw 0, 1, 2", "data_filler"},
		// jump
		{"jmp 0a720h", "jump_target"},
		{"call NextStep", "jump_target"},
		// no rule
		{"ret", ""},
		{"out dx, ax", ""},
		// label-prefixed
		{"Foo: mov bx, 0", "value_load_imm"},
	}
	for _, c := range cases {
		got := ClassifyHostRole(c.text)
		if got != c.want {
			t.Errorf("text=%q: got %q, want %q", c.text, got, c.want)
		}
	}
}
