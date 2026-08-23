package index

import "strings"

// ClassifyHostRole returns a coarse semantic tag for the slot-bearing
// instruction. The motivating use case: the agent's SMC-naming decision
// tree branches on a small set of mnemonic patterns -- value-load,
// threshold, delta, deferred-write, etc. -- and emitting the class
// inline saves it from re-parsing the instruction text every time.
//
// Returns "" when no rule fires; callers should treat the field as
// optional. The classifier is text-only (no encoding required) so it
// works equally well on listing instructions and source-line fallbacks.
//
// Vocabulary:
//
//	value_load_imm    -- mov <reg>, <imm>          (incl. mov sp, imm)
//	stack_anchor      -- mov sp, <imm>             (specialisation of value_load_imm)
//	threshold         -- cmp/test <op>, <imm>
//	delta             -- add/sub/adc/sbb <op>, <imm>
//	mask              -- and/or/xor <op>, <imm>
//	shift             -- shl/shr/sar/sal/rol/ror/rcl/rcr <op>, <imm>
//	deferred_write    -- mov [<mem>], <imm>
//	interrupt_vector  -- int <imm>
//	data_filler       -- db/dw/dd <values>
//	jump_target       -- jmp/call/j<cond> <imm>    (rare for SMC slots)
func ClassifyHostRole(text string) string {
	mnem, dst, _ := splitOperands(text)
	if mnem == "" {
		return ""
	}
	// Encoding-macro fallback: this codebase uses macros like
	// `cmp_ax_imm16_long`, `mov_bh_bx_disp16`, `or_bx_imm16_long` that
	// force a specific JWasm encoding for the underlying opcode. The
	// macro name's underscore-prefix is the actual mnemonic, so we
	// re-key on it when the full token isn't a known mnemonic.
	if !mnemonicHasRule(mnem) {
		if u := strings.IndexByte(mnem, '_'); u > 0 && mnemonicHasRule(mnem[:u]) {
			mnem = mnem[:u]
		}
	}
	dstLow := strings.ToLower(dst)
	dstIsMem := strings.HasPrefix(dstLow, "[") ||
		strings.Contains(dstLow, "ptr [") ||
		strings.Contains(dstLow, ":[")

	switch mnem {
	case "mov", "movzx", "movsx":
		if dstIsMem {
			return "deferred_write"
		}
		if dstLow == "sp" || dstLow == "esp" {
			return "stack_anchor"
		}
		return "value_load_imm"
	case "lea":
		// `lea reg, [mem+imm]` rarely carries an SMC slot, but when it
		// does it acts as a value-load of a computed pointer.
		return "value_load_imm"
	case "cmp", "test":
		return "threshold"
	case "add", "sub", "adc", "sbb", "inc", "dec":
		return "delta"
	case "and", "or", "xor":
		return "mask"
	case "shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr":
		return "shift"
	case "int", "into":
		return "interrupt_vector"
	case "db", "dw", "dd", "dq", "dt", "df":
		return "data_filler"
	case "jmp", "call", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
		"ja", "jae", "jb", "jbe", "jc", "jnc", "jo", "jno", "js", "jns",
		"jp", "jnp", "jpe", "jpo", "jcxz", "jecxz",
		"loop", "loope", "loopne", "loopz", "loopnz":
		return "jump_target"
	}
	return ""
}

// mnemonicHasRule reports whether the role classifier has a rule for the
// given mnemonic. Used by the encoding-macro fallback to decide whether a
// trimmed prefix counts as the underlying opcode.
func mnemonicHasRule(m string) bool {
	switch m {
	case "mov", "movzx", "movsx", "lea",
		"cmp", "test",
		"add", "sub", "adc", "sbb", "inc", "dec",
		"and", "or", "xor",
		"shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr",
		"int", "into",
		"db", "dw", "dd", "dq", "dt", "df",
		"jmp", "call",
		"je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
		"ja", "jae", "jb", "jbe", "jc", "jnc", "jo", "jno",
		"js", "jns", "jp", "jnp", "jpe", "jpo", "jcxz", "jecxz",
		"loop", "loope", "loopne", "loopz", "loopnz":
		return true
	}
	return false
}
