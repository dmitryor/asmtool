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
	s := strings.TrimSpace(text)
	// Drop a leading label like "Foo:" or "Foo::".
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		first := s[:i]
		if strings.HasSuffix(first, ":") {
			s = strings.TrimSpace(s[i:])
		}
	}
	// Mnemonic = first whitespace-delimited token.
	i := 0
	for i < len(s) && s[i] != ' ' && s[i] != '\t' {
		i++
	}
	mnem := strings.ToLower(s[:i])
	rest := strings.TrimSpace(s[i:])

	// Destination operand = text before the first top-level comma. We don't
	// need to walk brackets perfectly here -- the dst-vs-src split for the
	// patterns we care about is unambiguous in the codebase.
	var dst string
	if c := indexTopComma(rest); c >= 0 {
		dst = strings.TrimSpace(rest[:c])
	} else {
		dst = rest
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

// indexTopComma returns the index of the first comma at bracket depth 0,
// or -1.
func indexTopComma(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[', '(':
			depth++
		case ']', ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
