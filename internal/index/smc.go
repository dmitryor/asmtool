package index

import (
	"strconv"
	"strings"
)

// SmcSlot describes the location and shape of a self-modifying-code slot:
// a Var_NNNN EQU resolves to a typed pointer at an offset into the byte
// stream of an instruction labelled by SmcAnchor_NNNN. Knowing all three
// pieces (anchor, offset, slot size) lets a caller see exactly which bytes
// of which instruction get rewritten at run time.
type SmcSlot struct {
	Anchor string // anchor symbol name (e.g. SmcAnchor_a71f)
	Size   string // "byte" | "word" | "dword"
	Offset int    // byte offset into the anchor instruction
}

// ParseSmcEqu parses a JWasm Text-EQU body of the form
//
//	"byte ptr SmcAnchor_xxxx + N"   (offset >= 0)
//	"byte ptr SmcAnchor_xxxx"       (offset == 0)
//	"word ptr SmcAnchor_xxxx + 1"
//	"dword ptr SmcAnchor_xxxx + 2"
//
// and returns the SMC slot it points at. Returns ok=false for any other
// shape so callers can distinguish SMC-style EQUates from plain numeric or
// expression equates.
func ParseSmcEqu(text string) (slot SmcSlot, ok bool) {
	parts := strings.Fields(text)
	if len(parts) < 3 {
		return SmcSlot{}, false
	}
	size := strings.ToLower(parts[0])
	switch size {
	case "byte", "word", "dword":
	default:
		return SmcSlot{}, false
	}
	if strings.ToLower(parts[1]) != "ptr" {
		return SmcSlot{}, false
	}
	anchor := parts[2]
	offset := 0
	if len(parts) >= 5 && parts[3] == "+" {
		v, err := strconv.Atoi(parts[4])
		if err != nil {
			return SmcSlot{}, false
		}
		offset = v
	} else if len(parts) >= 4 {
		// Unrecognised trailer (e.g. arithmetic we don't model).
		return SmcSlot{}, false
	}
	return SmcSlot{Anchor: anchor, Size: size, Offset: offset}, true
}

// FindEquAliasesOf returns EQU symbols whose Text-form right-hand side
// references `name` as the anchor of an SMC slot. The motivating case:
// `find_data_refs(SmcAnchor_a71f)` returns no refs because no instruction
// names the anchor directly -- the writes go through the EQU'd `Var_a720`.
// Surfacing the alias list lets the agent immediately re-query against
// the right name.
func (idx *Index) FindEquAliasesOf(name string) []*SymbolEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	var out []*SymbolEntry
	for _, decls := range idx.Symbols {
		for _, s := range decls {
			if s.Text == "" {
				continue
			}
			slot, ok := ParseSmcEqu(s.Text)
			if !ok || slot.Anchor != name {
				continue
			}
			out = append(out, s)
		}
	}
	return out
}

// HostInstruction returns the instruction text at the SMC anchor's source
// site, with any leading label stripped. If the anchor sits on its own
// line (`SmcAnchor_xxx::` followed by the instruction on the next line),
// the next non-blank line is returned. Returns "" if the source isn't
// loaded or the line is unreachable.
func (idx *Index) HostInstruction(anchor *SymbolEntry) string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	f := idx.Files[anchor.File]
	if f == nil || anchor.Line < 1 || anchor.Line > len(f.Lines) {
		return ""
	}
	line := stripInlineComment(f.Lines[anchor.Line-1])
	if instr := afterLabel(line, anchor.Name); instr != "" {
		return strings.TrimSpace(instr)
	}
	for i := anchor.Line; i < len(f.Lines); i++ {
		next := strings.TrimSpace(stripInlineComment(f.Lines[i]))
		if next == "" {
			continue
		}
		return next
	}
	return ""
}

func stripInlineComment(line string) string {
	if i := strings.IndexByte(line, ';'); i >= 0 {
		return strings.TrimRight(line[:i], " \t")
	}
	return strings.TrimRight(line, " \t")
}

// afterLabel returns the substring of `line` following a leading
// `<name>:` or `<name>::` declaration. Returns "" if no instruction
// follows the label on the same line.
func afterLabel(line, name string) string {
	s := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(s, name) {
		return strings.TrimSpace(s)
	}
	rest := s[len(name):]
	if !strings.HasPrefix(rest, ":") {
		return strings.TrimSpace(s)
	}
	rest = strings.TrimPrefix(rest, ":")
	rest = strings.TrimPrefix(rest, ":")
	return strings.TrimSpace(rest)
}
