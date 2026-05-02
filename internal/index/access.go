package index

import "strings"

// ClassifyAccess inspects a memory-operand reference and returns whether
// the symbol is being read, written, or both. For non-mem refs (call/jmp/
// imm/offset/dw/db/dd) it returns "" -- access semantics don't apply.
//
// The classifier walks the ref's source text, identifies the mnemonic, and
// uses its known operand semantics (mov/lea = dst-write, src-read; cmp/test
// = both read; add/sub/and/... = dst-rw, src-read; inc/dec/not/neg = rw;
// xchg = rw on both sides; pop = write; push/mul/div = read).
//
// The motivating use case: `find_data_refs(Var_NNNN)` returns both
// `mov ax, [Var_NNNN]` (read) and `mov [Var_NNNN], ax` (write) as kind=mem.
// Without this classifier the agent has to substring-match the text to
// separate writers from readers -- an SMC-analysis chore that recurs for
// every var on the worklist.
func ClassifyAccess(r *RefEntry) string {
	if r.Kind != "mem" {
		return ""
	}
	mnem, dst, src := splitOperands(r.Text)
	if mnem == "" {
		return ""
	}
	inDst := containsBracketedTarget(dst, r.Target)
	inSrc := containsBracketedTarget(src, r.Target)
	if !inDst && !inSrc {
		return ""
	}
	switch mnem {
	case "mov", "lea", "movzx", "movsx":
		if inDst {
			return "write"
		}
		return "read"
	case "xchg":
		return "rw"
	case "add", "sub", "and", "or", "xor", "adc", "sbb",
		"shl", "shr", "sal", "sar", "rol", "ror", "rcl", "rcr":
		if inDst {
			return "rw"
		}
		return "read"
	case "inc", "dec", "neg", "not":
		return "rw"
	case "cmp", "test":
		return "read"
	case "push":
		return "read"
	case "pop":
		return "write"
	case "mul", "imul", "div", "idiv":
		return "read"
	case "call", "jmp":
		return "read"
	}
	return ""
}

// splitOperands extracts (mnemonic, destOperand, srcOperand) from a single
// instruction line. Leading labels ("Foo:", "Foo::") are skipped. Comments
// must already have been stripped by the parser.
func splitOperands(text string) (mnem, dst, src string) {
	s := strings.TrimSpace(text)
	// Skip a leading label of the form `Name:` or `Name::`.
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
	mnem = strings.ToLower(s[:i])
	rest := strings.TrimSpace(s[i:])
	// Split first comma (top-level only -- we don't need to handle nested
	// parens or strings; assembly operands here are simple).
	depth := 0
	for j := 0; j < len(rest); j++ {
		c := rest[j]
		switch c {
		case '[', '(':
			depth++
		case ']', ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				return mnem, strings.TrimSpace(rest[:j]), strings.TrimSpace(rest[j+1:])
			}
		}
	}
	return mnem, rest, ""
}

// containsBracketedTarget reports whether `target` appears inside a `[...]`
// memory-operand bracket within `s`. Matches whole-token only, so `Var_a720`
// does not match `Var_a7200`.
func containsBracketedTarget(s, target string) bool {
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case ']':
			if depth > 0 {
				depth--
				if depth == 0 && containsWord(s[start:i], target) {
					return true
				}
			}
		}
	}
	return false
}

// containsWord reports whether `target` appears in `s` as a complete token
// (bounded on both sides by non-identifier characters or string ends).
func containsWord(s, target string) bool {
	for {
		idx := strings.Index(s, target)
		if idx < 0 {
			return false
		}
		before := byte(' ')
		if idx > 0 {
			before = s[idx-1]
		}
		after := byte(' ')
		end := idx + len(target)
		if end < len(s) {
			after = s[end]
		}
		if !isIdentChar(before) && !isIdentChar(after) {
			return true
		}
		s = s[end:]
	}
}

func isIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_' || b == '@'
}
