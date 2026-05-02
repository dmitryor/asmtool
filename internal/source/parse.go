package source

import (
	"bufio"
	"io"
	"os"
	"strings"
	"unicode"
)

// reservedWords are tokens that look like identifiers but are JWasm/MASM
// keywords or x86 registers. Anything in this set is NOT a symbol reference.
var reservedWords = map[string]bool{}

func init() {
	for _, w := range []string{
		// 16-bit registers
		"ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "cs", "ds", "es", "ss", "fs", "gs",
		// 8-bit registers
		"al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
		// flag mnemonics that look like idents
		"st",
		// type/size keywords
		"byte", "word", "dword", "qword", "fword", "tbyte", "ptr", "offset", "seg",
		"near", "far", "short", "this", "type", "length", "size", "lengthof", "sizeof",
		// directives
		"db", "dw", "dd", "dq", "dt", "equ", "macro", "endm", "proc", "endp",
		"segment", "ends", "include", "assume", "public", "extrn", "extern", "label",
		"org", "align", "even", "if", "endif", "else", "elseif", "ifdef", "ifndef",
		"ifb", "ifnb", "ife", "while", "endw", "exitm", "goto", "purge",
		"struct", "struc", "union", "record", "comment", "name", "title", "subtitle",
		"option",
		// pseudo-ops we might see
		"end",
	} {
		reservedWords[w] = true
	}
}

// stripComment returns (codePart, comment) where codePart has trailing
// whitespace removed. JWasm comments start with `;`.
//
// Note: this does not parse string literals. JWasm assembly rarely uses
// quoted strings on lines that also contain `;` outside the string, but
// if it does the tokenizer will mishandle it. For v0 this is acceptable.
func stripComment(line string) (code, comment string) {
	if i := strings.IndexByte(line, ';'); i >= 0 {
		// Walk forward to find a `;` not inside single quotes (string chars).
		// We only support straight ASCII single-char strings.
		inStr := false
		for j := 0; j < len(line); j++ {
			c := line[j]
			if c == '\'' {
				inStr = !inStr
			}
			if c == ';' && !inStr {
				return strings.TrimRight(line[:j], " \t"), line[j:]
			}
		}
	}
	return strings.TrimRight(line, " \t"), ""
}

// peelLabel inspects the start of a code line for a label declaration.
//
// Recognised forms:
//
//	Name:                       global label
//	Name::                      cross-PROC export label
//	@@Name:                     PROC-local label
//	Name PROC [NEAR|FAR] ...    procedure declaration
//	Name EQU expr               equate
//	Name MACRO args             macro declaration
//
// Returns the label name (without `@@` prefix), the declared kind, and
// the remainder of the line *after the label form*. For colon-style
// labels the colon is consumed; for keyword-style declarations
// (PROC/EQU/MACRO) the keyword and trailing arguments are returned in
// `rest` so the caller can route on the keyword.
func peelLabel(code string) (name string, kind LabelKind, rest string) {
	trimmed := strings.TrimLeft(code, " \t")
	if trimmed == "" {
		return "", LabelUnknown, code
	}
	hasAt := false
	if strings.HasPrefix(trimmed, "@@") {
		hasAt = true
	}
	start := 0
	if hasAt {
		start = 2
	}
	i := start
	for i < len(trimmed) && isIdentByte(trimmed[i]) {
		i++
	}
	if i == start {
		return "", LabelUnknown, code
	}
	id := trimmed[start:i]
	// Colon-form: `Name:` or `Name::` (or `@@Name:`).
	if i < len(trimmed) && trimmed[i] == ':' {
		doubleColon := i+1 < len(trimmed) && trimmed[i+1] == ':'
		if hasAt {
			kind = LabelLocal
		} else if doubleColon {
			kind = LabelExport
		} else {
			kind = LabelGlobal
		}
		colonEnd := i + 1
		if doubleColon {
			colonEnd = i + 2
		}
		return id, kind, trimmed[colonEnd:]
	}
	if hasAt {
		// `@@Name` without colon is a *use*, not a declaration.
		return "", LabelUnknown, code
	}
	// Keyword form: `Name <kw> ...`. The next non-space token determines kind.
	j := i
	for j < len(trimmed) && (trimmed[j] == ' ' || trimmed[j] == '\t') {
		j++
	}
	if j == i {
		// No whitespace after the ident -- can't be a keyword form.
		return "", LabelUnknown, code
	}
	// Read the keyword token.
	k := j
	for k < len(trimmed) && isIdentByte(trimmed[k]) {
		k++
	}
	kw := strings.ToLower(trimmed[j:k])
	switch kw {
	case "proc":
		return id, LabelProc, trimmed[j:]
	case "equ":
		return id, LabelEqu, trimmed[j:]
	case "macro":
		return id, LabelMacro, trimmed[j:]
	}
	return "", LabelUnknown, code
}

func isIdentStartByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}

func isIdentByte(b byte) bool {
	return isIdentStartByte(b) || (b >= '0' && b <= '9')
}

// firstToken returns the first whitespace-delimited token (lowercased)
// of a code fragment, plus the byte index where it ends.
func firstToken(code string) (tok string, endIdx int) {
	s := strings.TrimLeft(code, " \t")
	skipped := len(code) - len(s)
	i := 0
	for i < len(s) && !unicode.IsSpace(rune(s[i])) {
		i++
	}
	return strings.ToLower(s[:i]), skipped + i
}

// isNumericLiteral returns true if the token looks like a numeric literal
// (hex with h suffix, decimal, char literal, etc.).
func isNumericLiteral(tok string) bool {
	if tok == "" {
		return false
	}
	if tok[0] >= '0' && tok[0] <= '9' {
		return true
	}
	if tok[0] == '\'' || tok[0] == '"' {
		return true
	}
	if strings.HasPrefix(tok, "0x") || strings.HasPrefix(tok, "0X") {
		return true
	}
	return false
}

// extractIdentTokens returns identifier-like tokens in the input string,
// each annotated with whether it appeared inside a `[...]` memory operand
// (mem=true) or following an `offset` keyword (off=true).
//
// This is a small handwritten scanner: we walk characters tracking a few
// pieces of state (bracket depth, "saw `offset`") and emit each identifier.
type identCtx struct {
	Name  string
	Mem   bool
	Off   bool
	Local bool // token was written with `@@` prefix
}

func extractIdentTokens(code string) []identCtx {
	var out []identCtx
	depth := 0
	sawOffset := false
	i := 0
	for i < len(code) {
		c := code[i]
		switch {
		case c == '[':
			depth++
			i++
		case c == ']':
			if depth > 0 {
				depth--
			}
			i++
		case c == ' ' || c == '\t' || c == ',' || c == '+' || c == '-' || c == '*' || c == '/' || c == '(' || c == ')' || c == ':':
			// `offset` only applies to the very next ident, so reset on non-ident transitions
			i++
		case c == '\'' || c == '"':
			// skip string literal
			q := c
			i++
			for i < len(code) && code[i] != q {
				i++
			}
			if i < len(code) {
				i++
			}
		case isIdentStartByte(c) || c == '@':
			// read ident (possibly @@local)
			start := i
			if c == '@' && i+1 < len(code) && code[i+1] == '@' {
				i += 2
			}
			for i < len(code) && isIdentByte(code[i]) {
				i++
			}
			tok := code[start:i]
			lc := strings.ToLower(tok)
			if lc == "offset" {
				sawOffset = true
				continue
			}
			// numeric-suffix check: hex literals like `1234h` / `0FFh`
			// are scanned as identifiers by the loop above; reject here
			// when the token looks numeric.
			if looksNumericIdent(tok) {
				sawOffset = false
				continue
			}
			if reservedWords[lc] {
				sawOffset = false
				continue
			}
			name := tok
			isLocal := false
			if strings.HasPrefix(tok, "@@") {
				name = tok[2:]
				isLocal = true
			}
			out = append(out, identCtx{Name: name, Mem: depth > 0, Off: sawOffset, Local: isLocal})
			sawOffset = false
		default:
			// digits, operators we don't care about specifically
			if c >= '0' && c <= '9' {
				// consume the numeric token entirely so a trailing 'h' doesn't trip us
				for i < len(code) && (isIdentByte(code[i]) || code[i] == '.') {
					i++
				}
				sawOffset = false
				continue
			}
			i++
		}
	}
	return out
}

// looksNumericIdent: tokens like `0FFh`, `1234h`, `0FFFFh` start with a digit.
// peelLabel guarantees idents starting with a letter make it past the digit
// guard above, but JWasm allows lowercase hex ending in 'h' that begins with
// 'a'..'f' if followed by digits (rare). For safety, reject tokens whose
// every char is hex+ trailing 'h'.
func looksNumericIdent(tok string) bool {
	if len(tok) < 2 {
		return false
	}
	last := tok[len(tok)-1]
	if last != 'h' && last != 'H' {
		return false
	}
	for i := 0; i < len(tok)-1; i++ {
		c := tok[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	// Must contain at least one digit (otherwise it's a plain word ending in 'h').
	for i := 0; i < len(tok)-1; i++ {
		if tok[i] >= '0' && tok[i] <= '9' {
			return true
		}
	}
	return false
}

// jumpMnemonics covers conditional and unconditional control transfers we
// care about for caller analysis. We don't need an exhaustive list -- just
// "treat the operand as a code reference."
var jumpMnemonics = map[string]bool{
	"jmp": true, "jmps": true, "jmpf": true,
	"je": true, "jne": true, "jz": true, "jnz": true,
	"jg": true, "jge": true, "jl": true, "jle": true,
	"ja": true, "jae": true, "jb": true, "jbe": true,
	"jc": true, "jnc": true, "jo": true, "jno": true,
	"js": true, "jns": true, "jp": true, "jnp": true,
	"jpe": true, "jpo": true, "jcxz": true, "jecxz": true,
	"loop": true, "loope": true, "loopne": true, "loopnz": true, "loopz": true,
}

// dataMnemonics maps db/dw/dd/dq/dt to RefKind values.
var dataMnemonics = map[string]RefKind{
	"db": RefDataByte,
	"dw": RefDataWord,
	"dd": RefDataDword,
	// dq/dt produce 64/80-bit emits; we don't classify those for now.
}

// ParseFile reads and parses a single source file.
func ParseFile(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseReader(path, f)
}

func parseReader(path string, r io.Reader) (*File, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	out := &File{Path: path}
	var currentProc *Proc
	for scanner.Scan() {
		line := scanner.Text()
		out.Lines = append(out.Lines, line)
		lineNo := len(out.Lines)

		code, _ := stripComment(line)
		if strings.TrimSpace(code) == "" {
			continue
		}

		// 1. Peel a leading label declaration if present.
		labelName, labelKind, rest := peelLabel(code)
		if labelName != "" {
			lab := &Label{
				Name: labelName,
				Kind: labelKind,
				File: path,
				Line: lineNo,
			}
			if currentProc != nil {
				lab.EnclosingProc = currentProc.Name
				if labelKind == LabelLocal {
					currentProc.LocalLabels = append(currentProc.LocalLabels, lab)
				}
			}
			out.Labels = append(out.Labels, lab)
		}

		// 2. Examine the rest of the line for directives or instructions.
		// The "rest" we're routing on is what came AFTER any peeled label.
		// For keyword-form declarations (`Foo PROC ...`) peelLabel already
		// stripped the name, so rest still begins with the keyword.
		// For scope-closers like `Foo ENDP` peelLabel rejects them (no
		// known keyword), so rest == original code and tok is the name --
		// in that case we look at the *second* token for the directive.
		tok, _ := firstToken(rest)
		closer := ""
		if labelName == "" {
			// Check for `<ident> endp|endm|ends` pattern.
			rawTrim := strings.TrimLeft(code, " \t")
			fields := strings.Fields(rawTrim)
			if len(fields) >= 2 {
				low := strings.ToLower(fields[1])
				if low == "endp" || low == "endm" || low == "ends" {
					closer = low
				}
			}
		}

		switch {
		case tok == "":
			continue
		case tok == "proc":
			if labelName == "" {
				continue
			}
			p := &Proc{
				Name:          labelName,
				File:          path,
				StartLine:     lineNo,
				FirstBodyLine: lineNo + 1,
			}
			out.Procs = append(out.Procs, p)
			currentProc = p
			continue
		case tok == "endp" || closer == "endp":
			if currentProc != nil {
				currentProc.EndLine = lineNo
				currentProc = nil
			}
			continue
		case tok == "macro" || tok == "endm" || tok == "equ" || closer == "endm":
			continue
		case tok == "include":
			parts := strings.Fields(rest)
			if len(parts) >= 2 {
				out.Includes = append(out.Includes, parts[1])
			}
			continue
		case tok == "segment" || tok == "ends" || tok == "assume" ||
			tok == "public" || tok == "extrn" || tok == "extern" ||
			tok == "org" || tok == "align" || tok == "even" || tok == "end" ||
			tok == ".8086" || tok == ".8087" || tok == "option" || closer == "ends":
			continue
		}

		// 3. Either an instruction or a data-definition.
		// Special case: data definitions classify references differently.
		if dk, isData := dataMnemonics[tok]; isData {
			operandStart := strings.IndexFunc(rest, func(r rune) bool { return !unicode.IsSpace(r) })
			if operandStart < 0 {
				continue
			}
			// Skip the mnemonic itself.
			afterMnemonic := strings.TrimLeft(rest[operandStart:], " \t")
			afterMnemonic = strings.TrimLeft(afterMnemonic[len(tok):], " \t")
			for _, ic := range extractIdentTokens(afterMnemonic) {
				if labelName != "" && ic.Name == labelName {
					// the data label itself is not a reference to itself
					continue
				}
				ref := &Ref{
					Target:  ic.Name,
					Kind:    dk,
					File:    path,
					Line:    lineNo,
					IsLocal: ic.Local,
					Text:    strings.TrimSpace(code),
				}
				if currentProc != nil {
					ref.EnclosingProc = currentProc.Name
				}
				// If the data label was peeled, retag its kind to LabelData.
				if labelName != "" {
					for _, l := range out.Labels {
						if l.Line == lineNo && l.Name == labelName {
							l.Kind = LabelData
							break
						}
					}
				}
				out.Refs = append(out.Refs, ref)
			}
			continue
		}

		// Generic instruction. Determine default RefKind by mnemonic.
		var defaultKind RefKind
		switch {
		case tok == "call":
			defaultKind = RefCall
		case jumpMnemonics[tok]:
			defaultKind = RefJmp
		default:
			defaultKind = RefImm
		}

		afterMnemonic := strings.TrimLeft(rest, " \t")
		// Drop the mnemonic
		if idx := strings.IndexAny(afterMnemonic, " \t"); idx >= 0 {
			afterMnemonic = afterMnemonic[idx:]
		} else {
			afterMnemonic = ""
		}

		for _, ic := range extractIdentTokens(afterMnemonic) {
			refKind := defaultKind
			switch {
			case ic.Off:
				refKind = RefOffset
			case ic.Mem:
				refKind = RefMem
			}
			ref := &Ref{
				Target:  ic.Name,
				Kind:    refKind,
				File:    path,
				Line:    lineNo,
				IsLocal: ic.Local,
				Text:    strings.TrimSpace(code),
			}
			if currentProc != nil {
				ref.EnclosingProc = currentProc.Name
			}
			out.Refs = append(out.Refs, ref)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
