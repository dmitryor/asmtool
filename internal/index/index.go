// Package index combines parsed source with a JWasm listing-derived symbol
// table in one query model.
package index

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/dmitryor/asmtool/internal/jwasm"
	"github.com/dmitryor/asmtool/internal/source"
)

// SymbolEntry is the unified declaration record: it merges
// what the source parser saw (declaration site, kind, scope) with what
// JWasm resolved (address, segment).
type SymbolEntry struct {
	Name          string
	Kind          string // PROC | export | global | local | data | EQU | MACRO
	File          string
	Line          int
	EnclosingProc string // for @@-locals, the parent PROC
	Addr          uint32
	HasAddr       bool
	Segment       string
	// Text carries the right-hand side of a Text-kind EQU as JWasm resolved
	// it (e.g. "byte ptr SmcAnchor_a71f + 1"). Empty for non-EQU symbols and
	// for EQUates that resolve to a bare number.
	Text string
}

// ProcEntry exposes a parsed PROC plus its resolved address range.
type ProcEntry struct {
	Name      string
	File      string
	StartLine int
	EndLine   int
	Addr      uint32
	HasAddr   bool
	// EndAddr is the address one past the last byte of the PROC, derived
	// from the address of the next labelled site (or the end of the file's
	// address window). When unknown it equals Addr.
	EndAddr uint32
}

// RefEntry exposes a parsed reference enriched with the caller's PROC.
type RefEntry struct {
	Target        string
	Kind          string // call | jmp | offset | mem | imm | dw | db | dd
	File          string
	Line          int
	EnclosingProc string
	IsLocal       bool // true if the source wrote `@@Target` (PROC-scoped use)
	Text          string
}

// Index is the queryable view. After Build returns, callers may share
// it across goroutines for read-only access.
type Index struct {
	mu sync.RWMutex

	// Source files keyed by absolute path.
	Files map[string]*source.File

	// Symbols keyed by canonical name. For names declared in multiple
	// scopes (e.g. `Done` declared in many PROCs as `@@Done`), the slice
	// holds one entry per declaration site.
	Symbols map[string][]*SymbolEntry

	// Procs keyed by PROC name (PROC names are unique across the project).
	Procs map[string]*ProcEntry

	// All PROCs sorted by Addr -- used for which_proc and addr_to_location.
	procsByAddr []*ProcEntry

	// Reverse references: for each symbol, all source uses.
	Refs map[string][]*RefEntry

	// Instructions (sorted by Addr ascending) carries the per-row address
	// + size + source text JWasm produced. Populated when a listing is
	// available; used by SMC tools to identify the instruction whose byte
	// range contains a slot offset (anchor regions can span 2-3 instructions).
	instructions []jwasm.Instruction
}

// Build assembles the Index from a slice of parsed source files plus an
// optional listing (may be nil if the build hasn't run yet).
func Build(files []*source.File, listing *jwasm.ListingFile) *Index {
	idx := &Index{
		Files:   map[string]*source.File{},
		Symbols: map[string][]*SymbolEntry{},
		Procs:   map[string]*ProcEntry{},
		Refs:    map[string][]*RefEntry{},
	}
	listingByName := map[string]jwasm.Symbol{}
	if listing != nil {
		for _, s := range listing.Symbols {
			listingByName[s.Name] = s
		}
		// Copy + sort the instruction stream once; SMC queries binary-search it.
		idx.instructions = append([]jwasm.Instruction(nil), listing.Instructions...)
		sort.Slice(idx.instructions, func(i, j int) bool {
			return idx.instructions[i].Addr < idx.instructions[j].Addr
		})
	}

	for _, f := range files {
		idx.Files[f.Path] = f

		for _, lab := range f.Labels {
			entry := &SymbolEntry{
				Name:          lab.Name,
				Kind:          lab.Kind.String(),
				File:          lab.File,
				Line:          lab.Line,
				EnclosingProc: lab.EnclosingProc,
			}
			if s, ok := listingByName[lab.Name]; ok {
				entry.Addr = s.Value
				entry.HasAddr = s.HasAddr
				entry.Segment = s.Segment
				entry.Text = s.Text
			}
			idx.Symbols[lab.Name] = append(idx.Symbols[lab.Name], entry)
		}

		for _, p := range f.Procs {
			pe := &ProcEntry{
				Name:      p.Name,
				File:      p.File,
				StartLine: p.StartLine,
				EndLine:   p.EndLine,
			}
			if s, ok := listingByName[p.Name]; ok && s.HasAddr {
				pe.Addr = s.Value
				pe.HasAddr = true
				if s.Length > 0 {
					pe.EndAddr = s.Value + s.Length
				}
			}
			idx.Procs[p.Name] = pe
		}

		for _, r := range f.Refs {
			re := &RefEntry{
				Target:        r.Target,
				Kind:          r.Kind.String(),
				File:          r.File,
				Line:          r.Line,
				EnclosingProc: r.EnclosingProc,
				IsLocal:       r.IsLocal,
				Text:          r.Text,
			}
			idx.Refs[r.Target] = append(idx.Refs[r.Target], re)
		}
	}

	// Build addr-sorted PROC slice. EndAddr was already set above from the
	// listing's Length column when available; here we only fall back to the
	// next-PROC heuristic for entries that didn't carry a Length (rare --
	// JWasm always emits Length for PROCs we know about).
	for _, p := range idx.Procs {
		if p.HasAddr {
			idx.procsByAddr = append(idx.procsByAddr, p)
		}
	}
	sort.Slice(idx.procsByAddr, func(i, j int) bool {
		return idx.procsByAddr[i].Addr < idx.procsByAddr[j].Addr
	})
	for i, p := range idx.procsByAddr {
		if p.EndAddr > p.Addr {
			continue
		}
		if i+1 < len(idx.procsByAddr) {
			p.EndAddr = idx.procsByAddr[i+1].Addr
		} else {
			p.EndAddr = p.Addr
		}
	}
	return idx
}

// InstructionAt returns the instruction whose byte range
// [Addr, Addr+Size) contains addr, or nil if no match (or when no
// listing has been parsed yet).
func (idx *Index) InstructionAt(addr uint32) *jwasm.Instruction {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if len(idx.instructions) == 0 {
		return nil
	}
	// Binary search for the largest Addr <= addr.
	i := sort.Search(len(idx.instructions), func(i int) bool {
		return idx.instructions[i].Addr > addr
	})
	if i == 0 {
		return nil
	}
	candidate := &idx.instructions[i-1]
	if addr < candidate.Addr || addr >= candidate.Addr+candidate.Size {
		return nil
	}
	return candidate
}

// InstructionsCovering returns every instruction whose byte range overlaps
// [start, end). Used to walk an SMC anchor region from its declaration
// through the instruction containing the patch slot. The slice is in
// ascending-address order; callers should not mutate it.
func (idx *Index) InstructionsCovering(start, end uint32) []jwasm.Instruction {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if len(idx.instructions) == 0 || end <= start {
		return nil
	}
	first := sort.Search(len(idx.instructions), func(i int) bool {
		return idx.instructions[i].Addr+idx.instructions[i].Size > start
	})
	if first == len(idx.instructions) {
		return nil
	}
	var out []jwasm.Instruction
	for i := first; i < len(idx.instructions); i++ {
		ins := idx.instructions[i]
		if ins.Addr >= end {
			break
		}
		out = append(out, ins)
	}
	return out
}

// SymbolsCoveringRange returns every symbol declaration whose address
// falls inside [start, end). Used by data_refs_at to find every alias
// that maps onto a byte range -- for example the byte EQU `Var_d5c8` and
// the word label `VideoDetectResult` both at 0xd5c8.
//
// Symbols without an address (sourceless EQUs, locals not in the listing)
// are skipped.
func (idx *Index) SymbolsCoveringRange(start, end uint32) []*SymbolEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if end <= start {
		return nil
	}
	var out []*SymbolEntry
	for _, decls := range idx.Symbols {
		for _, s := range decls {
			if !s.HasAddr {
				continue
			}
			if s.Addr < start || s.Addr >= end {
				continue
			}
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr < out[j].Addr
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// BareLocalName strips the `@@` prefix of a PROC-local label. The index keys
// locals by their bare name, since `@@` marks scope rather than spelling, so
// "@@Done" and "Done" name the same local and every lookup accepts both.
func BareLocalName(name string) string {
	return strings.TrimPrefix(name, "@@")
}

// FindSymbol returns all declarations of the given name.
func (idx *Index) FindSymbol(name string) []*SymbolEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	out := idx.Symbols[BareLocalName(name)]
	dup := make([]*SymbolEntry, len(out))
	copy(dup, out)
	return dup
}

// FindRefs returns all references to the given name.
func (idx *Index) FindRefs(name string) []*RefEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	out := idx.Refs[BareLocalName(name)]
	dup := make([]*RefEntry, len(out))
	copy(dup, out)
	return dup
}

// FindDataRefs returns refs whose kind is mem/imm/offset/dw/db/dd -- i.e.
// non-control-transfer uses. The counterpart to FindCallers; useful for
// understanding how a data symbol is read or written.
//
// Scope rules: when the queried name is declared as a global symbol
// (PROC, export, global, EQU, data, MACRO) anywhere in the project,
// only non-local refs are returned. When the name is declared *only* as
// a local (`@@Foo` inside one or more PROCs), only @@-prefixed refs are
// returned -- and an inProc filter narrows further if requested. Pass
// `""` for inProc when no PROC narrowing is wanted.
func (idx *Index) FindDataRefs(name, inProc string) []*RefEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	hasGlobalDecl := false
	for _, s := range idx.Symbols[name] {
		switch s.Kind {
		case "PROC", "export", "global", "EQU", "data", "MACRO":
			hasGlobalDecl = true
		}
	}
	var out []*RefEntry
	for _, r := range idx.Refs[name] {
		if r.Kind == "call" || r.Kind == "jmp" {
			continue
		}
		if hasGlobalDecl {
			if r.IsLocal {
				continue
			}
		} else {
			if !r.IsLocal {
				continue
			}
			if inProc != "" && r.EnclosingProc != inProc {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// FindCallers returns refs whose kind is `call` or `jmp` (control transfers).
//
// Scope handling: when the queried name is declared as a global symbol
// (PROC, export, global, EQU) anywhere in the project, only non-local
// references are returned. When the name is declared *only* as a local
// (`@@Foo` inside one or more PROCs), only @@-prefixed references are
// returned -- and an inProc filter narrows further if requested. Pass
// `""` for inProc when no PROC narrowing is wanted.
//
// This prevents `find_callers("Done")` from drowning the agent in 1,400+
// hits across every PROC that has its own `@@Done` label.
func (idx *Index) FindCallers(name, inProc string) []*RefEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	hasGlobalDecl := false
	for _, s := range idx.Symbols[name] {
		switch s.Kind {
		case "PROC", "export", "global", "EQU", "data", "MACRO":
			hasGlobalDecl = true
		}
	}
	var out []*RefEntry
	for _, r := range idx.Refs[name] {
		if r.Kind != "call" && r.Kind != "jmp" {
			continue
		}
		if hasGlobalDecl {
			if r.IsLocal {
				continue
			}
		} else {
			if !r.IsLocal {
				continue
			}
			if inProc != "" && r.EnclosingProc != inProc {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// FindCallees returns external and internal callees of the given PROC:
//
//   - external: cross-PROC `call` and `jmp` targets (the actual outgoing
//     edges of the call graph)
//   - internal: `@@local`-prefixed jumps that stay within this PROC
//     (control flow noise for most queries)
//
// Each list is deduped by (target,kind). Returns nil,nil if procName is not
// a known PROC.
func (idx *Index) FindCallees(procName string) (external, internal []*RefEntry) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if _, ok := idx.Procs[procName]; !ok {
		return nil, nil
	}
	seenExt := map[string]bool{}
	seenInt := map[string]bool{}
	for _, refs := range idx.Refs {
		for _, r := range refs {
			if r.EnclosingProc != procName {
				continue
			}
			if r.Kind != "call" && r.Kind != "jmp" {
				continue
			}
			key := r.Target + "|" + r.Kind
			if r.IsLocal {
				if seenInt[key] {
					continue
				}
				seenInt[key] = true
				internal = append(internal, r)
			} else {
				if seenExt[key] {
					continue
				}
				seenExt[key] = true
				external = append(external, r)
			}
		}
	}
	cmp := func(a, b *RefEntry) bool {
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.Kind < b.Kind
	}
	sort.Slice(external, func(i, j int) bool { return cmp(external[i], external[j]) })
	sort.Slice(internal, func(i, j int) bool { return cmp(internal[i], internal[j]) })
	return
}

// WhichProc returns the PROC enclosing (file, line), or nil.
func (idx *Index) WhichProc(file string, line int) *ProcEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	for _, p := range idx.Procs {
		if p.File != file || p.StartLine == 0 {
			continue
		}
		if line < p.StartLine {
			continue
		}
		if p.EndLine > 0 && line > p.EndLine {
			continue
		}
		return p
	}
	return nil
}

// AddrToProc returns the PROC whose address range encloses addr, or nil.
func (idx *Index) AddrToProc(addr uint32) *ProcEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if len(idx.procsByAddr) == 0 {
		return nil
	}
	// Binary search for the largest Addr <= addr.
	i := sort.Search(len(idx.procsByAddr), func(i int) bool {
		return idx.procsByAddr[i].Addr > addr
	})
	if i == 0 {
		return nil
	}
	candidate := idx.procsByAddr[i-1]
	if candidate.EndAddr > candidate.Addr && addr >= candidate.EndAddr {
		return nil
	}
	return candidate
}

// ModuleProcs lists the PROCs declared in the given file, sorted by start line.
func (idx *Index) ModuleProcs(file string) []*ProcEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	var out []*ProcEntry
	for _, p := range idx.Procs {
		if p.File == file {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartLine < out[j].StartLine })
	return out
}

// ReadProc returns the source lines from PROC start through ENDP, inclusive.
// If the PROC has no detected ENDP, returns lines from start through file end.
func (idx *Index) ReadProc(name string) (string, error) {
	idx.mu.RLock()
	p, ok := idx.Procs[name]
	if !ok {
		idx.mu.RUnlock()
		return "", fmt.Errorf("proc %q not found", name)
	}
	f := idx.Files[p.File]
	idx.mu.RUnlock()
	if f == nil {
		return "", fmt.Errorf("file %q not loaded", p.File)
	}
	end := p.EndLine
	if end <= 0 || end > len(f.Lines) {
		end = len(f.Lines)
	}
	if p.StartLine <= 0 || p.StartLine > len(f.Lines) {
		return "", fmt.Errorf("proc %q has invalid line range", name)
	}
	var b strings.Builder
	for i := p.StartLine; i <= end; i++ {
		b.WriteString(f.Lines[i-1])
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// ResolveSourceFiles walks the configured source paths, identifies .inc/.asm
// files, and returns absolute paths.
func ResolveSourceFiles(sourcePaths []string) ([]string, error) {
	var out []string
	for _, root := range sourcePaths {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			ext := filepath.Ext(path)
			if ext != ".inc" && ext != ".asm" {
				return nil
			}
			out = append(out, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
