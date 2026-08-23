// Package classify implements the relocation-blocker scanner.
//
// The premise: a literal numeric token in source is a "relocation blocker"
// when its value encodes a CSEG address (so inserting a NOP earlier in the
// code would invalidate it). Because the assembly is *semantically*
// ambiguous about whether `mov ax, 0x1234` means "load address 0x1234"
// or "load value 0x1234," we classify each candidate with a confidence
// tier and present the worklist for review.
package classify

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/dmitryor/asmtool/internal/index"
)

// Confidence levels for the classifier output.
type Confidence string

const (
	// DefiniteAddress: literal appears as a [imm] memory displacement that
	// resolves exactly to a known label address. Almost certainly a blocker.
	DefiniteAddress Confidence = "definite"
	// ProbableAddress: literal value matches a known label and the operand
	// context is consistent with address use (offset keyword, dw inside data,
	// etc.). Likely a blocker but agent should review.
	ProbableAddress Confidence = "probable"
	// AmbiguousAddress: literal matches a label but operand context is
	// ambiguous (immediate operand of mov/etc.). Either an address or
	// a value that happens to alias.
	AmbiguousAddress Confidence = "ambiguous"
)

// Candidate is one classifier hit. The agent reviews these in confidence
// order and replaces the literal with the suggested symbolic form.
type Candidate struct {
	File          string     `json:"file"`
	Line          int        `json:"line"`
	EnclosingProc string     `json:"in_proc,omitempty"`
	Literal       string     `json:"literal"`
	Value         uint32     `json:"value_hex"`
	Confidence    Confidence `json:"confidence"`
	Context       string     `json:"context"` // mem | imm | data_dw | data_db | offset
	Suggestion    string     `json:"suggestion,omitempty"`
	Text          string     `json:"text"`
}

// CSEGUpper bounds the address space we treat as in-segment for a typical
// 16-bit real-mode image (64KiB code segment). Literals at or above this
// are very unlikely to be CS addresses.
const CSEGUpper = 0x10000

// CSEGLower below this we ignore matches: small literals (0..0xff) are
// overwhelmingly values (counts, masks, port numbers), even if a label
// happens to live there. Tier 1 specifically requires the literal to
// match a label address AND be >= this floor to avoid alias noise.
const CSEGLower = 0x100

// PortHints catches `mov dx, imm; out` / `mov dx, imm; in` patterns where
// the literal is an I/O port number, not a memory address. We approximate
// the heuristic line-locally: if the same line writes to DX and the next
// line is an out/in instruction, classify as port. (Implemented in
// classifier loop.)
//
// (We don't implement DX tracking yet; instead, ports are filtered later
// by examining the surrounding lines when needed.)

// Scan walks all source files in the index and emits candidate blockers.
//
// Tier 1 of the classifier:
//   - Literal in `[...]` (no register) whose value matches a known label
//     address >= CSEGLower → DefiniteAddress.
//   - Literal in `[...]` (no register) with no label match but in CSEG
//     range → ProbableAddress.
//   - Literal in `dw <imm>` data definition, value matches a known label →
//     reported only when the surrounding `dw` block has at least 33% of
//     its entries also resolving to labels (jump tables and pointer
//     arrays). Single-hit coincidental matches in numeric data tables
//     (trig LUTs, etc.) are dropped.
//   - Literal in `mov reg, imm` where imm matches a known label and is
//     >= CSEGLower → AmbiguousAddress.
//
// Out of scope: db sub-word literals, off-by-one constructions like
// `[Foo+1]`, and anything that would require dataflow.
func Scan(idx *index.Index) []Candidate {
	addrToName := map[uint32][]string{}
	for name, syms := range idx.Symbols {
		for _, s := range syms {
			if !s.HasAddr {
				continue
			}
			if s.Kind == "local" {
				// @@-locals are too narrow-scoped to confidently suggest
				// as replacements for arbitrary literals elsewhere.
				continue
			}
			addrToName[s.Addr] = appendUnique(addrToName[s.Addr], name)
		}
	}

	var out []Candidate
	for _, f := range idx.Files {
		dwBlock := newDwBlockTracker(addrToName)
		var currentProc string
		for i, raw := range f.Lines {
			lineNo := i + 1
			code, _ := stripComment(raw)
			if strings.TrimSpace(code) == "" {
				dwBlock.boundary()
				continue
			}
			if proc, ok := procDecl(code); ok {
				currentProc = proc
				dwBlock.boundary()
			}
			if isProcEnd(code) {
				currentProc = ""
				dwBlock.boundary()
			}
			mnemonic, _ := firstMnemonic(code)
			isDw := mnemonic == "dw"
			if !isDw {
				dwBlock.boundary()
			}

			for _, lit := range scanLiterals(code) {
				cand, ok := classifyLiteral(lit, addrToName)
				if !ok {
					continue
				}
				cand.File = filepath.Base(f.Path)
				cand.Line = lineNo
				cand.EnclosingProc = currentProc
				cand.Text = strings.TrimSpace(code)
				if cand.Context == "data_dw" {
					dwBlock.record(cand)
					continue
				}
				out = append(out, cand)
			}
			if isDw {
				// Account for ALL dw values on this line so the cluster
				// ratio is accurate (matches AND non-matches).
				dwBlock.observeAllValues(code)
			}
		}
		out = append(out, dwBlock.flush()...)
	}
	return out
}

// dwBlockTracker buffers candidates inside a contiguous run of `dw` lines
// and only emits them when the block looks like a pointer table -- i.e.
// when the share of entries resolving to labels is high enough to suggest
// real addresses, not coincidental aliases in a numeric LUT.
type dwBlockTracker struct {
	addrToName map[uint32][]string
	pending    []Candidate
	totalVals  int
	matchVals  int
}

const dwClusterThreshold = 0.33 // require ~1/3 of entries to look address-like

func newDwBlockTracker(addrToName map[uint32][]string) *dwBlockTracker {
	return &dwBlockTracker{addrToName: addrToName}
}

func (b *dwBlockTracker) record(cand Candidate) {
	b.pending = append(b.pending, cand)
}

func (b *dwBlockTracker) observeAllValues(code string) {
	for _, lit := range scanLiterals(code) {
		if lit.Context != "data_dw" {
			continue
		}
		b.totalVals++
		if lit.Value >= CSEGLower && lit.Value < CSEGUpper {
			if len(b.addrToName[lit.Value]) > 0 {
				b.matchVals++
			}
		}
	}
}

func (b *dwBlockTracker) boundary() []Candidate {
	out := b.flush()
	b.pending = nil
	b.totalVals = 0
	b.matchVals = 0
	return out
}

func (b *dwBlockTracker) flush() []Candidate {
	if len(b.pending) == 0 {
		return nil
	}
	defer func() {
		b.pending = nil
		b.totalVals = 0
		b.matchVals = 0
	}()
	if b.totalVals == 0 {
		return nil
	}
	ratio := float64(b.matchVals) / float64(b.totalVals)
	if ratio < dwClusterThreshold {
		// Looks like a numeric table with one or two coincidental aliases.
		return nil
	}
	return b.pending
}

func appendUnique(slice []string, v string) []string {
	for _, s := range slice {
		if s == v {
			return slice
		}
	}
	return append(slice, v)
}

// LiteralOccurrence is a numeric literal found in source text along with
// its operand context.
type LiteralOccurrence struct {
	Raw     string // as it appeared in source ("0e922h", "1234h", "0xFF")
	Value   uint32
	Context string // mem | imm | data_dw | data_db | offset
}

// regNames is the set of x86-16 registers we look for inside `[...]` to
// distinguish absolute `[imm]` operands from base-displacement `[reg+imm]`
// or `[reg-imm]` ones. The latter aren't relocation blockers (the literal
// is a struct field offset, not an address).
var regNames = map[string]bool{
	"ax": true, "bx": true, "cx": true, "dx": true,
	"al": true, "ah": true, "bl": true, "bh": true,
	"cl": true, "ch": true, "dl": true, "dh": true,
	"si": true, "di": true, "bp": true, "sp": true,
	"cs": true, "ds": true, "es": true, "ss": true,
}

// scanLiterals finds numeric literals in code and tags their operand context.
//
// Memory-operand classification is two-tier:
//   - "mem"      → `[imm]` with no register inside the brackets (absolute)
//   - "mem_disp" → `[reg + imm]` / `[reg - imm]` (base-displacement; the
//     literal is a field offset, not an address; usually NOT
//     a relocation blocker)
//
// To detect this we mark the start of each `[...]` and then, when we close
// it, look back at whether any register name appeared inside.
func scanLiterals(code string) []LiteralOccurrence {
	var out []LiteralOccurrence
	mnemonic, _ := firstMnemonic(code)
	defaultCtx := "imm"
	switch mnemonic {
	case "dw":
		defaultCtx = "data_dw"
	case "db":
		defaultCtx = "data_db"
	case "dd":
		defaultCtx = "data_dd"
	}

	type bracket struct {
		startOut int  // index into out at bracket open
		hadReg   bool // any register seen inside
	}
	var stack []bracket
	depth := 0
	sawOffset := false
	i := 0
	for i < len(code) {
		c := code[i]
		switch {
		case c == '[':
			stack = append(stack, bracket{startOut: len(out)})
			depth++
			i++
		case c == ']':
			if depth > 0 {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				depth--
				// Retag literals emitted while inside this bracket.
				for k := top.startOut; k < len(out); k++ {
					if out[k].Context != "mem" {
						continue
					}
					if top.hadReg {
						out[k].Context = "mem_disp"
					}
				}
			}
			i++
		case c == '\'' || c == '"':
			q := c
			i++
			for i < len(code) && code[i] != q {
				i++
			}
			if i < len(code) {
				i++
			}
		case isIdentStartByte(c) || c == '@':
			start := i
			if c == '@' && i+1 < len(code) && code[i+1] == '@' {
				i += 2
			}
			for i < len(code) && isIdentByte(code[i]) {
				i++
			}
			tok := strings.ToLower(code[start:i])
			if tok == "offset" {
				sawOffset = true
				continue
			}
			if depth > 0 && regNames[tok] {
				stack[len(stack)-1].hadReg = true
			}
			sawOffset = false
		case c >= '0' && c <= '9':
			start := i
			for i < len(code) && (isHexByte(code[i]) || code[i] == 'x' || code[i] == 'X') {
				i++
			}
			raw := code[start:i]
			val, ok := parseNumLiteral(raw)
			if !ok {
				sawOffset = false
				continue
			}
			ctx := defaultCtx
			if depth > 0 {
				ctx = "mem" // may get retagged to "mem_disp" on `]`
			} else if sawOffset {
				ctx = "offset"
			}
			out = append(out, LiteralOccurrence{Raw: raw, Value: val, Context: ctx})
			sawOffset = false
		default:
			i++
		}
	}
	return out
}

func parseNumLiteral(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	low := strings.ToLower(s)
	switch {
	case strings.HasSuffix(low, "h"):
		v, err := strconv.ParseUint(low[:len(low)-1], 16, 32)
		if err != nil {
			return 0, false
		}
		return uint32(v), true
	case strings.HasPrefix(low, "0x"):
		v, err := strconv.ParseUint(low[2:], 16, 32)
		if err != nil {
			return 0, false
		}
		return uint32(v), true
	default:
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(v), true
	}
}

// classifyLiteral evaluates one literal against the address map and emits
// a Candidate if it warrants attention.
//
// Two paths to a hit:
//
//  1. Exact label match: literal value matches a known label address.
//     Strongest signal -- we know what to suggest as the replacement.
//
//  2. CSEG-range, no label: a `[imm]` memory operand whose value falls
//     in the code segment but doesn't resolve to any declared label.
//     Still a blocker (the literal encodes a position inside the code
//     image), but the suggestion is unknown -- the agent must look at
//     what's at that address and either name it or use an existing
//     label + offset (e.g. `Foo + 3`).
func classifyLiteral(lit LiteralOccurrence, addrToName map[uint32][]string) (Candidate, bool) {
	if lit.Value < CSEGLower || lit.Value >= CSEGUpper {
		return Candidate{}, false
	}
	matches := addrToName[lit.Value]
	c := Candidate{
		Literal: lit.Raw,
		Value:   lit.Value,
		Context: lit.Context,
	}
	if len(matches) > 0 {
		c.Suggestion = matches[0]
	}

	switch lit.Context {
	case "mem":
		// [imm] absolute memory operand (no register inside the brackets):
		// the literal IS being used as an address. Always a blocker;
		// confidence depends on whether we have a suggestion ready.
		if c.Suggestion != "" {
			c.Confidence = DefiniteAddress
		} else {
			c.Confidence = ProbableAddress
			c.Suggestion = "(no exact label; check what's at this address)"
		}
	case "mem_disp":
		// [reg + imm] / [reg - imm]: literal is a field offset off a base
		// register. Almost always a struct/array offset, NOT an address.
		// Skip unless the value matches a label exactly (rare; would mean
		// the displacement coincidentally equals a label addr).
		if c.Suggestion == "" {
			return Candidate{}, false
		}
		// Even with a match, this is low-confidence: report as ambiguous.
		c.Confidence = AmbiguousAddress
	case "data_dw":
		// dw entries: only flag if a label matches (suggests a pointer table).
		// Without a label match it's almost certainly a value, not an address.
		if c.Suggestion == "" {
			return Candidate{}, false
		}
		c.Confidence = ProbableAddress
	case "imm":
		// mov reg, imm: ambiguous -- flag only if a label matches.
		if c.Suggestion == "" {
			return Candidate{}, false
		}
		c.Confidence = AmbiguousAddress
	case "offset":
		// `offset 0x1234` is unusual; if a label matches, suggest it.
		if c.Suggestion == "" {
			return Candidate{}, false
		}
		c.Confidence = ProbableAddress
	default:
		return Candidate{}, false
	}
	return c, true
}

// ----- helpers shared with source/ but kept inline to avoid an import cycle -----

func stripComment(line string) (string, string) {
	if i := strings.IndexByte(line, ';'); i >= 0 {
		inStr := false
		for j := 0; j < len(line); j++ {
			if line[j] == '\'' {
				inStr = !inStr
			}
			if line[j] == ';' && !inStr {
				return strings.TrimRight(line[:j], " \t"), line[j:]
			}
		}
	}
	return strings.TrimRight(line, " \t"), ""
}

func isIdentStartByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}

func isIdentByte(b byte) bool {
	return isIdentStartByte(b) || (b >= '0' && b <= '9')
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// firstMnemonic returns the first non-label whitespace-delimited token of a
// code line, lowercased. If the line begins with `Name PROC` etc., that
// declaration is detected by procDecl/isProcEnd before this is consulted.
func firstMnemonic(code string) (string, int) {
	s := strings.TrimLeft(code, " \t")
	skipped := len(code) - len(s)
	// If the leading token is followed by `:` it's a label declaration --
	// skip it and parse the rest.
	first, end := readWord(s)
	if first == "" {
		return "", 0
	}
	if end < len(s) && s[end] == ':' {
		// `Name:` -- skip past colon(s)
		j := end + 1
		if j < len(s) && s[j] == ':' {
			j++
		}
		s2 := strings.TrimLeft(s[j:], " \t")
		first2, _ := readWord(s2)
		return strings.ToLower(first2), skipped + (len(s) - len(s2)) + 0
	}
	return strings.ToLower(first), skipped + end
}

func readWord(s string) (string, int) {
	i := 0
	for i < len(s) && !unicode.IsSpace(rune(s[i])) && s[i] != ',' && s[i] != ';' {
		i++
	}
	return s[:i], i
}

// procDecl returns ("Name", true) if code looks like `Name PROC ...`.
func procDecl(code string) (string, bool) {
	t := strings.TrimLeft(code, " \t")
	first, end := readWord(t)
	if first == "" {
		return "", false
	}
	rest := strings.TrimLeft(t[end:], " \t")
	kw, _ := readWord(rest)
	if strings.EqualFold(kw, "proc") {
		return first, true
	}
	return "", false
}

func isProcEnd(code string) bool {
	t := strings.TrimLeft(code, " \t")
	_, end := readWord(t)
	rest := strings.TrimLeft(t[end:], " \t")
	kw, _ := readWord(rest)
	return strings.EqualFold(kw, "endp")
}

// FormatSummary renders the classifier output as a short text summary
// (one bucket count per confidence tier) for quick human consumption.
func FormatSummary(c []Candidate) string {
	bucket := map[Confidence]int{}
	for _, x := range c {
		bucket[x.Confidence]++
	}
	return fmt.Sprintf("definite=%d probable=%d ambiguous=%d total=%d",
		bucket[DefiniteAddress], bucket[ProbableAddress], bucket[AmbiguousAddress], len(c))
}
