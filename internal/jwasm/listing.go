package jwasm

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// SymbolKind classifies entries in the JWasm listing's "Symbols:" section.
type SymbolKind int

const (
	SymUnknown   SymbolKind = iota
	SymNumber               // bare numeric EQU (Number)
	SymByte                 // Byte-typed label in segment
	SymWord                 // Word-typed label in segment
	SymDword                // Dword-typed label
	SymLabelNear            // L Near
	SymLabelFar             // L Far
	SymProc                 // Proc
	SymText                 // Text equate (expression-valued EQU)
)

func (k SymbolKind) String() string {
	switch k {
	case SymNumber:
		return "Number"
	case SymByte:
		return "Byte"
	case SymWord:
		return "Word"
	case SymDword:
		return "Dword"
	case SymLabelNear:
		return "L Near"
	case SymLabelFar:
		return "L Far"
	case SymProc:
		return "Proc"
	case SymText:
		return "Text"
	}
	return "?"
}

// Symbol is one row of the JWasm listing's symbol table.
type Symbol struct {
	Name    string
	Kind    SymbolKind
	Value   uint32 // resolved address or numeric value (when known)
	HasAddr bool   // true if Value is an address in some segment
	Segment string
	Text    string // raw type/value text for Text-kind equates
	// Length is the size in bytes of a PROC, taken from the P Near row.
	// Zero for non-PROC symbols.
	Length uint32
}

// Instruction is one assembled instruction row from the listing body.
// Addr is the CSEG offset of the first emitted byte; Size counts the bytes
// JWasm emitted for this row; Bytes carries the raw hex pairs (e.g.
// "8E060100" for `mov es, ds:[(SmcAnchor_0c33+1)]`); Text is the source
// text JWasm printed for this row, with any trailing self-comment stripped.
//
// The motivating use case: an SMC slot at `anchor + N` may land inside an
// instruction *after* the one labelled by the anchor (anchored regions
// often span 2-3 instructions). Knowing per-instruction byte ranges lets
// the index report which instruction actually contains the patched byte.
type Instruction struct {
	Addr  uint32
	Size  uint32
	Bytes string
	Text  string
}

// ListingFile is the parsed view of a jwasm .lst file.
type ListingFile struct {
	Symbols []Symbol
	// Instructions holds every code row JWasm assembled, sorted by Addr
	// ascending. Built once at parse time; consumed via Index lookup.
	Instructions []Instruction
	// Path -> map of source line number -> address (for files we identified
	// in the listing). Many lines have no address (comments, blank lines,
	// EQU declarations that emit no bytes); those simply have no entry.
	LineAddr map[string]map[int]uint32
}

// ParseListing reads the JWasm listing at path and extracts the symbol tables.
//
// JWasm emits at least three relevant sections at the tail of a listing:
//
//	Macros:                                   -- macro definitions (skipped)
//	Procedures, parameters and locals:        -- PROCs + @@-local labels with addresses
//	Symbols:                                  -- everything else (data, EQU, exports)
//
// Procedure rows appear flush-left ("Name  P Near  addr ..."); their local
// labels are indented with two spaces ("  @@Foo  L Near  addr ..."). We
// collect both so the index can resolve every PROC and every @@-local site
// that JWasm assigned an address to.
func ParseListing(path string) (*ListingFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	out := &ListingFile{
		LineAddr: map[string]map[int]uint32{},
	}
	const (
		secNone = iota
		secMacros
		secSegments
		secProcedures
		secSymbols
	)
	section := secNone
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Macros:"):
			section = secMacros
			continue
		case strings.HasPrefix(line, "Segments and Groups:"):
			section = secSegments
			continue
		case strings.HasPrefix(line, "Procedures, parameters and locals:"):
			section = secProcedures
			continue
		case strings.HasPrefix(line, "Symbols:"):
			section = secSymbols
			continue
		}
		if section == secNone || section == secMacros || section == secSegments {
			// Body section: instruction and data rows. Most of these are
			// not interesting, but instruction rows feed Instructions.
			if instr, ok := parseInstructionRow(line); ok {
				out.Instructions = append(out.Instructions, instr)
			}
			continue
		}
		// In the procedures section both flush-left rows (PROCs) and
		// indented rows (@@-locals) carry addresses we want.
		if sym, ok := parseSymbolRow(line); ok {
			out.Symbols = append(out.Symbols, sym)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseSymbolRow handles JWasm symbol-table entries like:
//
//	Var_e924 . . . . . . . . . . . .        Byte            E924h CSEG
//	Var_edc5 . . . . . . . . . . . .        Text   byte ptr SmcAnchor_edc4 + 1
//	DiskCacheFlag . . . .                   Number          E922h
//	WORD_1000_fad0 . . . . . . . . .        L Near          FAD0h CSEG
//	Main . . . . . . . . . . . . . .        L Near Proc     0000h CSEG  Length= 022Eh Public
func parseSymbolRow(line string) (Symbol, bool) {
	if line == "" {
		return Symbol{}, false
	}
	// Allow leading whitespace -- @@-local rows are indented in the
	// Procedures section. Only skip lines that are *entirely* whitespace.
	t := strings.TrimLeft(line, " \t")
	if t == "" {
		return Symbol{}, false
	}
	// Skip the "N a m e  Type ..." header lines that JWasm prints at the top
	// of each section.
	if strings.HasPrefix(t, "N a m e") || strings.HasPrefix(strings.ToLower(t), "name") {
		return Symbol{}, false
	}
	// Name is the run of non-space chars at the start
	i := 0
	for i < len(t) && t[i] != ' ' && t[i] != '\t' && t[i] != '.' {
		i++
	}
	name := t[:i]
	if name == "" {
		return Symbol{}, false
	}
	line = t // proceed with the trimmed copy
	// Skip the "name . . . . . ." padding then the kind block
	rest := strings.TrimSpace(line[i:])
	rest = strings.TrimLeft(rest, ". \t")
	if rest == "" {
		return Symbol{}, false
	}

	sym := Symbol{Name: name}

	// Order matters: longer prefixes first
	switch {
	case strings.HasPrefix(rest, "P Near"):
		sym.Kind = SymProc
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "P Near"))
	case strings.HasPrefix(rest, "P Far"):
		sym.Kind = SymProc
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "P Far"))
	case strings.HasPrefix(rest, "L Near"):
		sym.Kind = SymLabelNear
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "L Near"))
	case strings.HasPrefix(rest, "L Far"):
		sym.Kind = SymLabelFar
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "L Far"))
	case strings.HasPrefix(rest, "Number"):
		sym.Kind = SymNumber
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "Number"))
	case strings.HasPrefix(rest, "Dword"):
		sym.Kind = SymDword
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "Dword"))
	case strings.HasPrefix(rest, "Word"):
		sym.Kind = SymWord
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "Word"))
	case strings.HasPrefix(rest, "Byte"):
		sym.Kind = SymByte
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "Byte"))
	case strings.HasPrefix(rest, "Text"):
		sym.Kind = SymText
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "Text"))
		sym.Text = rest
		return sym, true
	default:
		// Unknown kind row (e.g., 'Macros:' header rows we don't care about)
		return Symbol{}, false
	}

	// rest now starts with the value. Two formats live here:
	//
	//   Label rows:  "E924h CSEG"
	//   PROC rows:   "65A0     CSEG     0087 Public"
	//                <addr>   <seg>    <length> <visibility>
	parts := strings.Fields(rest)
	if len(parts) == 0 {
		return Symbol{}, false
	}
	if v, ok := parseHexVal(parts[0]); ok {
		sym.Value = v
		sym.HasAddr = sym.Kind != SymNumber
	}
	if len(parts) >= 2 {
		sym.Segment = parts[1]
	}
	if sym.Kind == SymProc && len(parts) >= 3 {
		if l, ok := parseHexVal(parts[2]); ok {
			sym.Length = l
		}
	}
	return sym, true
}

// parseInstructionRow recognises a JWasm body row of the form
//
//	0000022E  8E060100            C         mov     es, ds:[...]               ; 022e  8e 06 34 0c
//	^^^^^^^^  ^^^^^^^^            ^         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//	addr      bytes               marker    source-text                         self-comment
//
// Layout is fixed-column: addr in [0,8), 2 spaces, bytes in [10,30), the
// segment-marker character at column 30 ('C' for CSEG code), source text
// from column 31. Label-only rows (no bytes) and continuation/comment
// rows (no leading addr) are rejected by returning ok=false.
func parseInstructionRow(line string) (Instruction, bool) {
	if len(line) < 32 || line[30] != 'C' {
		return Instruction{}, false
	}
	addr, ok := parseHexFixed(line[:8])
	if !ok {
		return Instruction{}, false
	}
	bytesPart := strings.TrimSpace(line[10:30])
	if bytesPart == "" {
		// Label-only or struct-row -- no instruction emitted.
		return Instruction{}, false
	}
	// JWasm allows non-hex characters here when expansion is partial; defend
	// against that to keep the address index honest.
	for i := 0; i < len(bytesPart); i++ {
		c := bytesPart[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
		if !isHex {
			return Instruction{}, false
		}
	}
	text := strings.TrimSpace(stripJwasmSelfComment(line[31:]))
	return Instruction{
		Addr:  addr,
		Size:  uint32(len(bytesPart) / 2),
		Bytes: bytesPart,
		Text:  text,
	}, true
}

// parseHexFixed accepts exactly 8 hex digits. Used for the listing's
// fixed-width address column where any non-hex character means we're
// not on an instruction row.
func parseHexFixed(s string) (uint32, bool) {
	if len(s) != 8 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
		if !isHex {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// stripJwasmSelfComment removes the auto-emitted "; <addr> <bytes>"
// suffix JWasm appends to every assembled row. Only stripped when the
// comment body is purely hex tokens -- so user comments like
// "; PSP_TOP" or "; CLS=CS | flight.inc:418" pass through unchanged.
func stripJwasmSelfComment(s string) string {
	idx := strings.LastIndex(s, ";")
	if idx < 0 {
		return s
	}
	body := strings.TrimSpace(s[idx+1:])
	if body == "" {
		return s[:idx]
	}
	for _, tok := range strings.Fields(body) {
		hex := true
		for i := 0; i < len(tok); i++ {
			c := tok[i]
			isHex := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
			if !isHex {
				hex = false
				break
			}
		}
		if !hex {
			return s
		}
	}
	return s[:idx]
}

func parseHexVal(s string) (uint32, bool) {
	// Listing values come in two formats:
	//   - L Near rows:  "FAD0h"   (suffix h)
	//   - P Near rows:  "65A0"    (bare hex)
	// Accept both. Labels and numerics also use the trailing 'h'.
	s = strings.TrimSuffix(s, "h")
	s = strings.TrimSuffix(s, "H")
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}
