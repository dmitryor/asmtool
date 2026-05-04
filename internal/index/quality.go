package index

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ----- proc_spacing -----

// ProcSpacingPair is one consecutive ENDP -> next PROC pair in a module.
// `BlankLines` is the count of empty lines (zero non-whitespace) between
// the prev ENDP and the next PROC's preamble. Per round-quality criterion 10
// the project standard is 2; a consumer compares BlankLines against its
// own expected count.
type ProcSpacingPair struct {
	PrevProc              string
	PrevEndpLine          int
	NextProc              string
	NextProcLine          int
	NextPreambleStartLine int
	BlankLines            int
}

// ProcSpacing returns one record per consecutive (ENDP, next PROC) pair
// in the given file. The first PROC and the last ENDP have no pair and
// are excluded.
func (idx *Index) ProcSpacing(file string) []ProcSpacingPair {
	idx.mu.RLock()
	f := idx.Files[file]
	idx.mu.RUnlock()
	if f == nil {
		return nil
	}
	procs := append([]*ProcEntry(nil), idx.ModuleProcs(file)...)
	if len(procs) < 2 {
		return nil
	}
	out := make([]ProcSpacingPair, 0, len(procs)-1)
	for i := 0; i+1 < len(procs); i++ {
		prev := procs[i]
		next := procs[i+1]
		if prev.EndLine <= 0 || next.StartLine <= 0 {
			continue
		}
		preStart := preambleStart(f.Lines, next.StartLine)
		blanks := 0
		for ln := prev.EndLine + 1; ln < preStart && ln <= len(f.Lines); ln++ {
			if isBlankLine(f.Lines[ln-1]) {
				blanks++
			}
		}
		out = append(out, ProcSpacingPair{
			PrevProc:              prev.Name,
			PrevEndpLine:          prev.EndLine,
			NextProc:              next.Name,
			NextProcLine:          next.StartLine,
			NextPreambleStartLine: preStart,
			BlankLines:            blanks,
		})
	}
	return out
}

// preambleStart walks backwards from a PROC's start line over a contiguous
// run of comment lines (lines whose first non-whitespace char is `;`) and
// returns the first line of that block. If no preamble immediately
// precedes the PROC, returns procStart unchanged.
func preambleStart(lines []string, procStart int) int {
	if procStart <= 1 {
		return procStart
	}
	ln := procStart - 1
	for ln >= 1 && ln <= len(lines) {
		s := strings.TrimLeft(lines[ln-1], " \t")
		if !strings.HasPrefix(s, ";") {
			return ln + 1
		}
		ln--
	}
	if ln < 1 {
		return 1
	}
	return ln + 1
}

func isBlankLine(line string) bool {
	return strings.TrimSpace(line) == ""
}

// ----- proc_header_card_coverage -----

// ProcHeaderKind classifies the comment block immediately preceding a PROC.
type ProcHeaderKind string

const (
	HeaderStructured   ProcHeaderKind = "structured"
	HeaderOneLiner     ProcHeaderKind = "one_liner"
	HeaderLegacyBanner ProcHeaderKind = "legacy_banner"
	HeaderMissing      ProcHeaderKind = "missing"
)

// ProcHeaderCard describes the preamble comment block of one PROC.
type ProcHeaderCard struct {
	Proc          string
	Line          int
	HeaderKind    ProcHeaderKind
	HeaderLines   []int
	FieldsPresent []string
	Issues        []string
}

// ProcHeaderCardCoverage classifies each PROC in the file by the shape of
// its preceding comment block. When `procFilter` is non-empty only the
// matching PROC is reported.
func (idx *Index) ProcHeaderCardCoverage(file, procFilter string) []ProcHeaderCard {
	idx.mu.RLock()
	f := idx.Files[file]
	idx.mu.RUnlock()
	if f == nil {
		return nil
	}
	procs := idx.ModuleProcs(file)
	out := make([]ProcHeaderCard, 0, len(procs))
	for _, p := range procs {
		if procFilter != "" && p.Name != procFilter {
			continue
		}
		out = append(out, classifyHeader(f.Lines, p))
	}
	return out
}

func classifyHeader(lines []string, p *ProcEntry) ProcHeaderCard {
	card := ProcHeaderCard{Proc: p.Name, Line: p.StartLine, HeaderKind: HeaderMissing}
	preStart := preambleStart(lines, p.StartLine)
	if preStart >= p.StartLine {
		return card
	}
	for ln := preStart; ln < p.StartLine; ln++ {
		card.HeaderLines = append(card.HeaderLines, ln)
	}
	body := make([]string, 0, len(card.HeaderLines))
	for _, ln := range card.HeaderLines {
		body = append(body, lines[ln-1])
	}
	if len(body) == 0 {
		return card
	}
	// Legacy-banner detection runs first so single-line ones still match.
	for _, ln := range card.HeaderLines {
		text := strings.TrimSpace(lines[ln-1])
		if isLegacyBanner(text, p.Name) {
			card.HeaderKind = HeaderLegacyBanner
			card.Issues = append(card.Issues,
				"PROC name appears on banner line "+strconv.Itoa(ln)+" -- migrate to structured card")
			return card
		}
	}
	if len(body) == 1 {
		// Placeholder-TODO one-liners are reclassified as legacy_banner so
		// the quality audit treats them as a violation that must be
		// migrated to a real header card.
		stripped := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(body[0]), ";"))
		if isPlaceholderTodo(stripped) {
			card.HeaderKind = HeaderLegacyBanner
			card.Issues = append(card.Issues,
				"placeholder TODO comment -- migrate to structured card")
			return card
		}
		card.HeaderKind = HeaderOneLiner
		return card
	}
	first := strings.TrimSpace(body[0])
	last := strings.TrimSpace(body[len(body)-1])
	topBracket := isStructuredBracket(first)
	bottomBracket := isStructuredBracket(last)
	if topBracket && bottomBracket {
		card.HeaderKind = HeaderStructured
		card.FieldsPresent = extractStructuredFields(body)
		if !contains(card.FieldsPresent, "purpose") {
			card.Issues = append(card.Issues, "structured card has no purpose line (first interior line ending with a period)")
		}
		return card
	}
	// Multi-line comment block but neither structured nor banner: treat as
	// one_liner-ish prose. Per the spec, the only acceptable non-structured
	// shape for non-trivial PROCs is HeaderMissing; otherwise we mark as
	// one_liner with an issue noting the multi-line shape.
	card.HeaderKind = HeaderOneLiner
	if len(body) > 1 {
		card.Issues = append(card.Issues, "non-structured multi-line comment block (consider migrating to structured card)")
	}
	return card
}

// isStructuredBracket reports whether `line` is a `;==…==` bracket line:
// starts with `;` followed by 30+ `=` characters.
func isStructuredBracket(line string) bool {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, ";") {
		return false
	}
	rest := strings.TrimLeft(s[1:], " ")
	if !strings.HasPrefix(rest, "==") {
		return false
	}
	count := 0
	for _, c := range rest {
		if c == '=' {
			count++
		} else {
			break
		}
	}
	return count >= 30
}

// extractStructuredFields walks the interior of a bracketed comment block
// and reports which named fields appear. The first interior line ending
// with a period is treated as `purpose`. Optional fields are matched by
// the leading keyword `Purpose:`, `In:`, `Out:`, `Trashes:`, `Notes:`.
func extractStructuredFields(body []string) []string {
	if len(body) <= 2 {
		return nil
	}
	interior := body[1 : len(body)-1]
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range interior {
		text := strings.TrimSpace(raw)
		text = strings.TrimPrefix(text, ";")
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		// Explicit `Field:` lines -- only the leading word counts.
		if i := strings.IndexByte(text, ':'); i > 0 {
			head := strings.ToLower(strings.TrimSpace(text[:i]))
			switch head {
			case "purpose", "in", "out", "trashes", "notes":
				if !seen[head] {
					seen[head] = true
					out = append(out, head)
				}
				continue
			}
		}
		// Otherwise, treat the first sentence-ending line as the purpose.
		if !seen["purpose"] && strings.HasSuffix(text, ".") {
			seen["purpose"] = true
			out = append(out, "purpose")
		}
	}
	// Stable order: purpose, in, out, trashes, notes
	canonical := []string{"purpose", "in", "out", "trashes", "notes"}
	stable := make([]string, 0, len(out))
	for _, k := range canonical {
		if seen[k] {
			stable = append(stable, k)
		}
	}
	return stable
}

func isLegacyBanner(line, procName string) bool {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, ";") {
		return false
	}
	s = strings.TrimSpace(s[1:])
	if !strings.HasPrefix(s, "----") {
		return false
	}
	s = strings.TrimLeft(s, "-")
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	first := s
	if i := strings.IndexAny(s, " \t-"); i >= 0 {
		first = s[:i]
	}
	return first == procName
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ----- magic_immediate_scan -----

// MagicImmediate is one immediate-value site found in a module body.
type MagicImmediate struct {
	Line     int
	Addr     uint32
	HasAddr  bool
	InProc   string
	Mnemonic string
	Operand  string
	Value    int64
	// Annotation
	EOLComment              string
	HasSubstantiveAnnotation bool
	// EQU match
	EquSymbol string
	EquSource string
	// Exclusion class
	IsExcluded     bool
	ExclusionReason string
}

// MagicImmediateScan walks the module's source lines and reports every
// immediate >= minValue, with annotation status, EQU match, and excluded-
// class reasoning per the request spec.
func (idx *Index) MagicImmediateScan(file, procFilter string, minValue int64) []MagicImmediate {
	idx.mu.RLock()
	f := idx.Files[file]
	idx.mu.RUnlock()
	if f == nil {
		return nil
	}
	if minValue == 0 {
		minValue = 0x100
	}
	var out []MagicImmediate
	procAt := func(line int) string {
		p := idx.WhichProc(file, line)
		if p == nil {
			return ""
		}
		return p.Name
	}
	for i, raw := range f.Lines {
		ln := i + 1
		code, comment := splitLineComment(raw)
		mnem, dst, src := splitOperands(code)
		if mnem == "" {
			continue
		}
		// Skip db/dw/dd table lines -- they're handled by the offset_table
		// exclusion class but shouldn't pollute the magic-immediate list
		// with every entry. Surface them as excluded entries.
		isData := mnem == "db" || mnem == "dw" || mnem == "dd"
		operands := []string{dst, src}
		for _, op := range operands {
			val, opText, ok := parseOperandImmediate(op)
			if !ok {
				continue
			}
			if val < minValue {
				continue
			}
			inProc := procAt(ln)
			if procFilter != "" && inProc != procFilter {
				continue
			}
			mi := MagicImmediate{
				Line:        ln,
				InProc:      inProc,
				Mnemonic:    mnem,
				Operand:     opText,
				Value:       val,
				EOLComment:  strings.TrimSpace(strings.TrimPrefix(comment, ";")),
			}
			mi.HasSubstantiveAnnotation = isSubstantiveComment(mi.EOLComment)
			if equ := idx.lookupEquByValue(uint64(val)); equ != nil {
				mi.EquSymbol = equ.Name
				mi.EquSource = filepath.Base(equ.File) + ":" + strconv.Itoa(equ.Line)
			}
			if isData {
				mi.IsExcluded = true
				mi.ExclusionReason = "offset_table"
			} else if mnem == "out" || mnem == "in" {
				if mi.EquSymbol != "" {
					mi.IsExcluded = true
					mi.ExclusionReason = "port_with_equ"
				}
			} else if isSelfEvidentBitPattern(uint64(val)) {
				mi.IsExcluded = true
				mi.ExclusionReason = "bit_pattern"
			}
			out = append(out, mi)
		}
	}
	return out
}

// splitLineComment returns (codePart, commentPart). codePart is everything
// before a top-level `;` (not inside a single-quoted character literal);
// commentPart is the `;` and everything after, or "" if there's no comment.
func splitLineComment(line string) (string, string) {
	inStr := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\'' {
			inStr = !inStr
		}
		if c == ';' && !inStr {
			return strings.TrimRight(line[:i], " \t"), line[i:]
		}
	}
	return strings.TrimRight(line, " \t"), ""
}

// parseOperandImmediate inspects a single operand for a literal numeric
// value. Returns (value, original-operand-text, ok).
func parseOperandImmediate(op string) (int64, string, bool) {
	op = strings.TrimSpace(op)
	if op == "" {
		return 0, "", false
	}
	// Skip operands wrapped in [] (memory) -- the displacement might be
	// a magic literal, but that's covered by check_unaliased_addrs.py.
	if strings.HasPrefix(op, "[") || strings.Contains(op, " ptr [") {
		return 0, "", false
	}
	tok := op
	// `offset Name` -> not an immediate value
	low := strings.ToLower(tok)
	if strings.HasPrefix(low, "offset ") {
		return 0, "", false
	}
	v, ok := parseNumericLiteral(tok)
	if !ok {
		return 0, "", false
	}
	return v, op, true
}

// parseNumericLiteral accepts hex (0x prefix or h suffix), octal (o
// suffix), binary (b suffix), or decimal integer literals.
func parseNumericLiteral(tok string) (int64, bool) {
	t := strings.TrimSpace(tok)
	if t == "" {
		return 0, false
	}
	// 0x / 0X prefix -- hex
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		v, err := strconv.ParseUint(t[2:], 16, 64)
		if err != nil {
			return 0, false
		}
		return int64(v), true
	}
	// Trailing radix marker: h/H, o/O/q/Q, b/B
	last := t[len(t)-1]
	switch last {
	case 'h', 'H':
		body := t[:len(t)-1]
		// hex literals must start with a digit per JWasm convention
		if body == "" || !isAsmDigit(body[0]) {
			return 0, false
		}
		v, err := strconv.ParseUint(body, 16, 64)
		if err != nil {
			return 0, false
		}
		return int64(v), true
	case 'o', 'O', 'q', 'Q':
		body := t[:len(t)-1]
		if body == "" || !isAsmDigit(body[0]) {
			return 0, false
		}
		v, err := strconv.ParseUint(body, 8, 64)
		if err != nil {
			return 0, false
		}
		return int64(v), true
	case 'b', 'B':
		body := t[:len(t)-1]
		// 'b'/'B' is ambiguous with hex (e.g. 1234B = 1234 binary or end-of-hex marker?)
		// Conservative: only treat as binary when body is all 0/1.
		if body == "" {
			return 0, false
		}
		for i := 0; i < len(body); i++ {
			if body[i] != '0' && body[i] != '1' {
				return 0, false
			}
		}
		v, err := strconv.ParseUint(body, 2, 64)
		if err != nil {
			return 0, false
		}
		return int64(v), true
	}
	// Plain decimal -- must be all digits.
	for i := 0; i < len(t); i++ {
		if t[i] < '0' || t[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(t, 10, 64)
	if err != nil {
		return 0, false
	}
	return int64(v), true
}

func isAsmDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isSubstantiveComment(c string) bool {
	if c == "" {
		return false
	}
	// Strip JWasm verify-script byte-list pattern: `<4-hex-addr>  <hex bytes>`.
	tokens := strings.Fields(c)
	if len(tokens) >= 2 {
		allHex := true
		for _, t := range tokens {
			for i := 0; i < len(t); i++ {
				ch := t[i]
				isHex := (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
				if !isHex {
					allHex = false
					break
				}
			}
			if !allHex {
				break
			}
		}
		if allHex {
			return false
		}
	}
	if isPlaceholderTodo(strings.TrimSpace(c)) {
		return false
	}
	return true
}

// isPlaceholderTodo reports whether `c` (already stripped of any leading
// `;` and trimmed) is a quality-lift placeholder banner that the audit
// must NOT count as substantive coverage.
//
// Two shapes:
//
//  1. Exact: `<Name> -- TODO: describe this function[.]`
//     This is the auto-generated stub from an earlier annotation pass --
//     ~250-300 of these exist across src/*.inc.
//
//  2. Bare TODO/XXX/FIXME tokens with no specific question. A
//     substantive TODO like "TODO: verify whether DX is preserved" still
//     counts -- only generic placeholders are rejected.
func isPlaceholderTodo(c string) bool {
	switch c {
	case "TODO", "XXX", "FIXME", "TODO: describe":
		return true
	}
	fields := strings.Fields(c)
	if len(fields) >= 6 &&
		fields[1] == "--" &&
		fields[2] == "TODO:" &&
		fields[3] == "describe" &&
		fields[4] == "this" &&
		(fields[5] == "function." || fields[5] == "function") &&
		len(fields) == 6 {
		return true
	}
	return false
}

// lookupEquByValue scans EQU symbols for one whose Text resolves to a
// matching numeric value. Returns the first match (deterministic via
// sorted iteration).
func (idx *Index) lookupEquByValue(value uint64) *SymbolEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	type match struct {
		entry *SymbolEntry
	}
	var hits []*SymbolEntry
	for _, decls := range idx.Symbols {
		for _, s := range decls {
			if s.Kind != "EQU" {
				continue
			}
			// Direct address match (numeric EQU resolved by listing).
			if s.HasAddr && uint64(s.Addr) == value {
				hits = append(hits, s)
				continue
			}
			// Numeric literal in Text (e.g. `equ 0c8h`).
			t := strings.TrimSpace(s.Text)
			if v, ok := parseNumericLiteral(t); ok && uint64(v) == value {
				hits = append(hits, s)
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].Name < hits[j].Name
	})
	return hits[0]
}

// isSelfEvidentBitPattern returns true for values the project considers
// "self-evident" -- they don't need an annotation because the bit
// pattern speaks for itself.
func isSelfEvidentBitPattern(v uint64) bool {
	switch v {
	case 0xFFFF, 0x8000, 0x8080, 0x7FFF, 0x000F, 0xF000, 0xFF00, 0x00FF:
		return true
	}
	return false
}

// ----- xref_coverage -----

// XrefCoverage is one cross-reference site with its annotation status.
// Coverage is satisfied either by an inline comment on the call site
// OR by a substantive preamble comment at the target's declaration.
type XrefCoverage struct {
	Line             int
	Addr             uint32
	HasAddr          bool
	InProc           string
	Kind             string // call | jmp | mem_read | mem_write
	TargetSymbol     string
	TargetKind       string // proc | data | label | indirect
	ExternalToModule bool
	// Inline annotation on the call site itself.
	InlineComment       string
	InlineIsSubstantive bool
	// Annotation at the target's declaration site (preamble comment block
	// immediately above the declaration line).
	TargetDeclaredIn        string // file:line, empty if target not found
	TargetCommentBlock      string // preamble text (comments joined with newline), empty if none
	TargetIsSubstantive     bool
}

// XrefCoverageScan returns one record per cross-reference site in the
// module. `kinds` (when non-empty) restricts the scan; default is all
// four (call, jmp, mem_read, mem_write).
func (idx *Index) XrefCoverageScan(file, procFilter string, kinds []string) []XrefCoverage {
	idx.mu.RLock()
	f := idx.Files[file]
	idx.mu.RUnlock()
	if f == nil {
		return nil
	}
	want := map[string]bool{}
	if len(kinds) == 0 {
		want = map[string]bool{"call": true, "jmp": true, "mem_read": true, "mem_write": true}
	} else {
		for _, k := range kinds {
			want[k] = true
		}
	}
	var out []XrefCoverage
	idx.mu.RLock()
	for _, refs := range idx.Refs {
		for _, r := range refs {
			if r.File != file {
				continue
			}
			if procFilter != "" && r.EnclosingProc != procFilter {
				continue
			}
			kind := classifyRefKind(r)
			if kind == "" || !want[kind] {
				continue
			}
			x := XrefCoverage{
				Line:         r.Line,
				InProc:       r.EnclosingProc,
				Kind:         kind,
				TargetSymbol: r.Target,
			}
			_, comment := splitLineComment(r.Text)
			x.InlineComment = strings.TrimSpace(strings.TrimPrefix(comment, ";"))
			x.InlineIsSubstantive = isSubstantiveComment(x.InlineComment)
			if decls := idx.Symbols[r.Target]; len(decls) > 0 {
				d := decls[0]
				x.TargetKind = mapDeclKindToTargetKind(d.Kind)
				x.ExternalToModule = d.File != file
				x.TargetDeclaredIn = filepath.Base(d.File) + ":" + strconv.Itoa(d.Line)
				if df := idx.Files[d.File]; df != nil && d.Line > 0 {
					if block, ok := readDeclPreamble(df.Lines, d.Line); ok {
						x.TargetCommentBlock = block
						x.TargetIsSubstantive = isSubstantiveComment(stripCommentPrefixes(block))
					}
				}
			} else {
				x.TargetKind = "indirect"
			}
			out = append(out, x)
		}
	}
	idx.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].TargetSymbol < out[j].TargetSymbol
	})
	return out
}

// readDeclPreamble returns the comment block immediately above
// declaration line `line` (lines starting with `;`, walked backwards).
// Returns (joined, true) when at least one preamble line exists,
// otherwise ("", false).
func readDeclPreamble(lines []string, line int) (string, bool) {
	start := preambleStart(lines, line)
	if start >= line {
		return "", false
	}
	parts := make([]string, 0, line-start)
	for ln := start; ln < line; ln++ {
		parts = append(parts, lines[ln-1])
	}
	return strings.Join(parts, "\n") + "\n", true
}

// ----- audit_summary -----

// AuditSummary is the small counts-only payload that drives the project's
// between-round re-baseline. Each criterion has a fail count plus a total
// (or per-criterion-specific scope total). Counts encode the failure
// rules from the consumer (quality_audit.py) so consumers don't have to
// pull every detail record back through the agent's context.
//
// Codified failure rules:
//
//   c4 (proc_header_card_coverage) - fail when header_kind is missing or
//      legacy_banner, or when a structured card lacks a purpose line.
//      Total = number of PROCs in the file.
//
//   c5 (magic_immediate_scan) - fail when an item has no substantive
//      annotation, no EQU match, AND is not in an excluded class.
//      Total = number of items.
//
//   c6 (xref_coverage) - fail when an external (non-indirect) xref has
//      neither inline nor target-declaration annotation. Total = number
//      of external (non-indirect) xrefs (not raw item count).
//
//   c10 (proc_spacing) - fail when blank_lines_between != 1. Total =
//      number of consecutive PROC pairs.
type AuditSummary struct {
	File       string
	C4Fail     int
	C4Total    int
	C5Fail     int
	C5Total    int
	C6Fail     int
	C6ExtTotal int
	C10Fail    int
	C10Total   int
}

// AuditSummaryFor returns the per-criterion fail/total counts for one
// module. `criteria` is the subset to compute (empty = all). Unknown
// criterion tokens are ignored.
func (idx *Index) AuditSummaryFor(file string, criteria []string) AuditSummary {
	idx.mu.RLock()
	_, ok := idx.Files[file]
	idx.mu.RUnlock()
	if !ok {
		return AuditSummary{File: filepath.Base(file)}
	}
	want := map[string]bool{}
	if len(criteria) == 0 {
		want = map[string]bool{"c4": true, "c5": true, "c6": true, "c10": true}
	} else {
		for _, c := range criteria {
			want[strings.TrimSpace(c)] = true
		}
	}
	out := AuditSummary{File: filepath.Base(file)}
	if want["c4"] {
		cards := idx.ProcHeaderCardCoverage(file, "")
		out.C4Total = len(cards)
		for _, c := range cards {
			if c.HeaderKind == HeaderMissing || c.HeaderKind == HeaderLegacyBanner {
				out.C4Fail++
				continue
			}
			if c.HeaderKind == HeaderStructured && hasNoPurposeIssue(c.Issues) {
				out.C4Fail++
			}
		}
	}
	if want["c5"] {
		hits := idx.MagicImmediateScan(file, "", 0x100)
		out.C5Total = len(hits)
		for _, h := range hits {
			if !h.HasSubstantiveAnnotation && h.EquSymbol == "" && !h.IsExcluded {
				out.C5Fail++
			}
		}
	}
	if want["c6"] {
		xrefs := idx.XrefCoverageScan(file, "", nil)
		for _, x := range xrefs {
			if !x.ExternalToModule || x.TargetKind == "indirect" {
				continue
			}
			out.C6ExtTotal++
			if !x.InlineIsSubstantive && !x.TargetIsSubstantive {
				out.C6Fail++
			}
		}
	}
	if want["c10"] {
		pairs := idx.ProcSpacing(file)
		out.C10Total = len(pairs)
		for _, p := range pairs {
			if p.BlankLines != 1 {
				out.C10Fail++
			}
		}
	}
	return out
}

// AuditSummaryAll returns one AuditSummary per source file currently
// indexed. Useful for whole-corpus re-baselines without a per-module
// loop on the consumer side. Files are returned sorted by basename for
// stable output.
func (idx *Index) AuditSummaryAll(criteria []string) []AuditSummary {
	idx.mu.RLock()
	paths := make([]string, 0, len(idx.Files))
	for p := range idx.Files {
		paths = append(paths, p)
	}
	idx.mu.RUnlock()
	sort.Slice(paths, func(i, j int) bool {
		return filepath.Base(paths[i]) < filepath.Base(paths[j])
	})
	out := make([]AuditSummary, 0, len(paths))
	for _, p := range paths {
		out = append(out, idx.AuditSummaryFor(p, criteria))
	}
	return out
}

func hasNoPurposeIssue(issues []string) bool {
	for _, i := range issues {
		if strings.Contains(i, "no purpose") {
			return true
		}
	}
	return false
}

// stripCommentPrefixes removes the leading `;` (and any spaces after it)
// from each line of a joined preamble block, so isSubstantiveComment
// can evaluate it against the same heuristic used for inline comments.
func stripCommentPrefixes(block string) string {
	out := make([]string, 0)
	for _, line := range strings.Split(block, "\n") {
		s := strings.TrimSpace(line)
		s = strings.TrimPrefix(s, ";")
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

func classifyRefKind(r *RefEntry) string {
	switch r.Kind {
	case "call":
		return "call"
	case "jmp":
		return "jmp"
	case "mem":
		switch ClassifyAccess(r) {
		case "write", "rw":
			return "mem_write"
		case "read":
			return "mem_read"
		}
	}
	return ""
}

func mapDeclKindToTargetKind(declKind string) string {
	switch declKind {
	case "PROC":
		return "proc"
	case "data", "EQU":
		return "data"
	default:
		return "label"
	}
}

