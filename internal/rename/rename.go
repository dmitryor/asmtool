// Package rename implements scope-aware atomic renaming of JWasm symbols
// across the source tree (and optionally markdown docs).
//
// The agent's existing alternative is `Edit replace_all` over each .inc
// file plus each doc, with no awareness of word boundaries, label scope,
// or destination collisions. This package replaces that with:
//
//   - Word-boundary token matching: `Blit` won't rewrite `BlitMasked`,
//     `BlitFullScreen`, or "Blit" inside `BlitGlyph`.
//   - Scope awareness: an `@@Foo` local rename is confined to its
//     enclosing PROC; rewriting a global `Foo` does not touch unrelated
//     PROCs whose private `@@Foo` happens to share the name.
//   - Collision refusal: if the target name already exists as a global
//     declaration, the rename refuses (or, for locals, allows in PROCs
//     where it doesn't collide).
//   - Matching closers and comments: a PROC rename updates `Name ENDP`
//     and free-form `; comments`, not just the PROC line and indexed
//     instruction operands. String literals in code are left alone.
//   - Dry-run preview: returns the exact (file, line, before, after)
//     edit list before touching disk.
package rename

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dmitryor/asmtool/internal/index"
	"github.com/dmitryor/asmtool/internal/source"
)

// Edit is one substitution about to be applied (or just previewed).
type Edit struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Plan is the dry-run preview returned by Plan and applied by Apply.
type Plan struct {
	OldName      string `json:"old"`
	NewName      string `json:"new"`
	IsLocal      bool   `json:"is_local"` // rename is scoped to one PROC
	InProc       string `json:"in_proc,omitempty"`
	Edits        []Edit `json:"edits"`
	FilesTouched int    `json:"files_touched"`
}

// CombinePlans merges independent rename previews into one write plan. This
// preserves multiple substitutions that happen to share a source line.
func CombinePlans(plans ...*Plan) *Plan {
	combined := &Plan{}
	byLocation := map[string]Edit{}
	files := map[string]bool{}
	for _, plan := range plans {
		for _, edit := range plan.Edits {
			key := fmt.Sprintf("%s:%d", edit.File, edit.Line)
			if current, ok := byLocation[key]; ok {
				current.After = rewriteLine(current.After, plan.OldName, plan.NewName, plan.IsLocal)
				byLocation[key] = current
			} else {
				byLocation[key] = edit
			}
			files[edit.File] = true
		}
	}
	for _, edit := range byLocation {
		combined.Edits = append(combined.Edits, edit)
	}
	sort.Slice(combined.Edits, func(i, j int) bool {
		if combined.Edits[i].File != combined.Edits[j].File {
			return combined.Edits[i].File < combined.Edits[j].File
		}
		return combined.Edits[i].Line < combined.Edits[j].Line
	})
	combined.FilesTouched = len(files)
	return combined
}

// Options controls what gets rewritten.
type Options struct {
	// InProc, if set, restricts rename to a single enclosing PROC. For
	// labels that exist *only* as PROC-locals, this is effectively
	// required (see AllowLocalsAcrossProcs to override).
	InProc string
	// AllowLocalsAcrossProcs: when true, lets a local-only label be
	// renamed across every PROC that declares it. Off by default because
	// common local names (`Done`, `Loop`, `Ret`) appear in dozens of
	// PROCs and an unscoped rename is almost always a mistake.
	AllowLocalsAcrossProcs bool
	// IncludeDocs: when true, also rewrites markdown files configured as
	// rename targets. When false, only .inc/.asm under source paths are
	// touched.
	IncludeDocs bool
	// DocPaths is the list of root directories to scan for *.md files
	// when IncludeDocs is true.
	DocPaths []string
}

// PlanRename builds an Edit list without touching disk.
func PlanRename(idx *index.Index, oldName, newName string, opts Options) (*Plan, error) {
	// A PROC-local label may be named with or without its `@@`; the plan
	// works on the bare name the index keys it by.
	atLabel := strings.HasPrefix(oldName, "@@") || strings.HasPrefix(newName, "@@")
	oldName = index.BareLocalName(oldName)
	newName = index.BareLocalName(newName)
	if oldName == newName {
		return nil, fmt.Errorf("rename: old and new are identical")
	}
	if !validIdent(newName) {
		return nil, fmt.Errorf("rename: %q is not a valid JWasm identifier", newName)
	}

	declSyms := idx.FindSymbol(oldName)
	if len(declSyms) == 0 {
		return nil, fmt.Errorf("rename: no declaration of %q found", oldName)
	}

	// Determine scope from the existing declarations.
	hasGlobalDecl := false
	allLocal := true
	for _, s := range declSyms {
		switch s.Kind {
		case "local":
			// stays local
		default:
			hasGlobalDecl = true
			allLocal = false
		}
	}

	if atLabel && !allLocal {
		return nil, fmt.Errorf("rename: %q is not a PROC-local label, so neither name takes `@@`", oldName)
	}

	// Safety: if the symbol is purely local AND declared in multiple PROCs,
	// require either an explicit InProc scope or an explicit override flag.
	// Names like "Done"/"Loop"/"Ret" appear in dozens of unrelated PROCs as
	// `@@Done:` etc. -- an unscoped rename is almost certainly a mistake.
	if allLocal && opts.InProc == "" && !opts.AllowLocalsAcrossProcs && len(declSyms) > 1 {
		var procs []string
		seen := map[string]bool{}
		for _, s := range declSyms {
			if !seen[s.EnclosingProc] {
				seen[s.EnclosingProc] = true
				procs = append(procs, s.EnclosingProc)
			}
		}
		preview := procs
		more := 0
		if len(preview) > 5 {
			more = len(preview) - 5
			preview = preview[:5]
		}
		return nil, fmt.Errorf(
			"rename: %q is a PROC-local label declared in %d PROCs (%s%s); pass `in_proc` to scope to one or `allow_locals_across_procs:true` to rename all",
			oldName, len(procs), strings.Join(preview, ", "),
			func() string {
				if more > 0 {
					return fmt.Sprintf(", +%d more", more)
				}
				return ""
			}(),
		)
	}

	// Collision check against the new name.
	for _, s := range idx.FindSymbol(newName) {
		if hasGlobalDecl {
			return nil, fmt.Errorf("rename: %q already declared (%s in %s:%d) -- refusing to collide",
				newName, s.Kind, filepath.Base(s.File), s.Line)
		}
		// allLocal: collision only matters in the same PROC scope.
		if opts.InProc != "" && s.EnclosingProc == opts.InProc {
			return nil, fmt.Errorf("rename: %q already declared in PROC %s (%s:%d)",
				newName, opts.InProc, filepath.Base(s.File), s.Line)
		}
	}

	plan := &Plan{
		OldName: oldName,
		NewName: newName,
		IsLocal: allLocal,
		InProc:  opts.InProc,
	}

	// Build the per-file line edits by scanning source ranges rather than
	// only indexed decl/ref sites. The parser drops ENDP names and comment
	// text, so a site list would miss `Foo ENDP` and `; see Foo`.
	editsByFile := map[string][]Edit{}
	seenLine := map[string]bool{}
	for _, rg := range renameScanRanges(idx, declSyms, allLocal, opts.InProc) {
		f := idx.Files[rg.file]
		if f == nil {
			continue
		}
		end := rg.end
		if end > len(f.Lines) {
			end = len(f.Lines)
		}
		for line := rg.start; line <= end; line++ {
			if line <= 0 {
				continue
			}
			key := fmt.Sprintf("%s:%d", rg.file, line)
			if seenLine[key] {
				continue
			}
			seenLine[key] = true
			before := f.Lines[line-1]
			after := rewriteLine(before, oldName, newName, allLocal)
			if after == before {
				continue
			}
			editsByFile[rg.file] = append(editsByFile[rg.file], Edit{
				File: rg.file, Line: line, Before: before, After: after,
			})
		}
	}

	// 3. Doc rewrites (text-only, word-boundary). Only applied for global
	// renames; renaming a PROC-local across docs makes no sense.
	if opts.IncludeDocs && !allLocal {
		docFiles := []string{}
		for _, root := range opts.DocPaths {
			err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return err
				}
				if filepath.Ext(path) == ".md" {
					docFiles = append(docFiles, path)
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("walk %s: %w", root, err)
			}
		}
		for _, path := range docFiles {
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			lines := strings.Split(string(b), "\n")
			for i, line := range lines {
				if !containsWord(line, oldName) {
					continue
				}
				after := rewriteLine(line, oldName, newName, false)
				if after == line {
					continue
				}
				editsByFile[path] = append(editsByFile[path], Edit{File: path, Line: i + 1, Before: line, After: after})
			}
		}
	}

	// Flatten and sort for stable output.
	for _, edits := range editsByFile {
		sort.Slice(edits, func(i, j int) bool { return edits[i].Line < edits[j].Line })
		plan.Edits = append(plan.Edits, edits...)
	}
	sort.Slice(plan.Edits, func(i, j int) bool {
		if plan.Edits[i].File != plan.Edits[j].File {
			return plan.Edits[i].File < plan.Edits[j].File
		}
		return plan.Edits[i].Line < plan.Edits[j].Line
	})
	plan.FilesTouched = len(editsByFile)
	return plan, nil
}

// Apply writes the edits to disk. Files are rewritten as a whole image
// (read, splice line edits, write) so partial failures leave each file
// either fully rewritten or untouched.
func Apply(plan *Plan) error {
	editsByFile := map[string][]Edit{}
	for _, e := range plan.Edits {
		editsByFile[e.File] = append(editsByFile[e.File], e)
	}
	for path, edits := range editsByFile {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		// Preserve trailing newline behaviour by checking the last byte.
		hadFinalNL := len(b) > 0 && b[len(b)-1] == '\n'
		text := string(b)
		if hadFinalNL {
			text = text[:len(text)-1]
		}
		lines := strings.Split(text, "\n")
		for _, e := range edits {
			if e.Line <= 0 || e.Line > len(lines) {
				return fmt.Errorf("apply %s:%d: out of range (file has %d lines)", path, e.Line, len(lines))
			}
			if lines[e.Line-1] != e.Before {
				return fmt.Errorf("apply %s:%d: before-text mismatch (file changed since plan)", path, e.Line)
			}
			lines[e.Line-1] = e.After
		}
		out := strings.Join(lines, "\n")
		if hadFinalNL {
			out += "\n"
		}
		// Write to a temp file in the same dir then rename, so a crash mid-write
		// can't corrupt the target.
		dir := filepath.Dir(path)
		tmp, err := os.CreateTemp(dir, ".rename-"+filepath.Base(path)+".*.tmp")
		if err != nil {
			return fmt.Errorf("create tmp: %w", err)
		}
		if _, err := tmp.WriteString(out); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return fmt.Errorf("write tmp: %w", err)
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmp.Name())
			return fmt.Errorf("close tmp: %w", err)
		}
		if err := os.Rename(tmp.Name(), path); err != nil {
			os.Remove(tmp.Name())
			return fmt.Errorf("rename tmp -> %s: %w", path, err)
		}
	}
	return nil
}

// scanRange is a 1-indexed inclusive line span in one indexed source file.
type scanRange struct {
	file  string
	start int
	end   int
}

// renameScanRanges chooses which source lines a rename may touch.
//
// Global unscoped renames scan every indexed file so matching ENDP/PUBLIC
// lines and comment-only mentions are included. Local labels (and any
// rename with InProc set) stay inside the relevant PROC, including its
// header and ENDP line.
func renameScanRanges(idx *index.Index, declSyms []*index.SymbolEntry, allLocal bool, inProc string) []scanRange {
	if !allLocal && inProc == "" {
		out := make([]scanRange, 0, len(idx.Files))
		for path, f := range idx.Files {
			if f == nil || len(f.Lines) == 0 {
				continue
			}
			out = append(out, scanRange{file: path, start: 1, end: len(f.Lines)})
		}
		return out
	}

	procs := map[string]bool{}
	if inProc != "" {
		procs[inProc] = true
	} else {
		for _, s := range declSyms {
			if s.EnclosingProc != "" {
				procs[s.EnclosingProc] = true
			}
		}
	}

	out := make([]scanRange, 0, len(procs))
	for name := range procs {
		p := idx.Procs[name]
		if p == nil {
			continue
		}
		f := idx.Files[p.File]
		end := p.EndLine
		if f != nil && (end <= 0 || end > len(f.Lines)) {
			end = len(f.Lines)
		}
		if p.StartLine <= 0 || end < p.StartLine {
			continue
		}
		out = append(out, scanRange{file: p.File, start: p.StartLine, end: end})
	}
	if len(out) > 0 {
		return out
	}

	// Local with no enclosing PROC recorded: fall back to the declaration
	// files so the label line itself is still rewritten.
	seen := map[string]bool{}
	for _, s := range declSyms {
		if inProc != "" && s.EnclosingProc != inProc {
			continue
		}
		f := idx.Files[s.File]
		if f == nil || seen[s.File] {
			continue
		}
		seen[s.File] = true
		out = append(out, scanRange{file: s.File, start: 1, end: len(f.Lines)})
	}
	return out
}

// validIdent checks that newName is a plausible JWasm identifier (letter or
// underscore start, no spaces or punctuation). We don't enforce reserved-
// word checks here; if the user picks `proc` they'll find out at the next
// jwasm run.
func validIdent(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// rewriteLine replaces every word-bounded occurrence of oldName in `line`
// with newName. When local is true, we look for `@@oldName`; otherwise we
// require the surrounding chars not to be ident continuations.
//
// Code string/character literals (`'Foo'` / `"Foo"`) are copied unchanged
// so a data string that happens to match a symbol is not treated as a
// reference. After a `;` comment starter that is not inside a literal,
// quotes are ordinary text -- so "don't" in a comment does not hide the
// rest of the line, and free-form `; see Foo` mentions are rewritten.
func rewriteLine(line, oldName, newName string, local bool) string {
	target := oldName
	if local {
		target = "@@" + oldName
	}
	var b strings.Builder
	b.Grow(len(line))
	i := 0
	inComment := false
	// shift is how far the code so far has moved right. The next padded gap
	// (two or more spaces before more text, typically the `; addr bytes`
	// comment) absorbs it, down to one space, so aligned columns stay put.
	shift := 0
	for i < len(line) {
		if shift != 0 && !inComment && line[i] == ' ' {
			j := i
			for j < len(line) && line[j] == ' ' {
				j++
			}
			if run := j - i; run >= 2 && j < len(line) {
				pad := run - shift
				if pad < 1 {
					pad = 1
				}
				b.WriteString(strings.Repeat(" ", pad))
				shift = 0
				i = j
				continue
			}
		}
		if !inComment {
			c := line[i]
			if c == '\'' || c == '"' {
				q := c
				b.WriteByte(c)
				i++
				for i < len(line) && line[i] != q {
					b.WriteByte(line[i])
					i++
				}
				if i < len(line) {
					b.WriteByte(line[i])
					i++
				}
				continue
			}
			if c == ';' {
				inComment = true
			}
		}
		if !startsWith(line, i, target) {
			b.WriteByte(line[i])
			i++
			continue
		}
		// Boundary check: chars before/after must not be ident-continuation.
		if i > 0 && isIdentByte(line[i-1]) {
			b.WriteByte(line[i])
			i++
			continue
		}
		end := i + len(target)
		if end < len(line) && isIdentByte(line[end]) {
			b.WriteByte(line[i])
			i++
			continue
		}
		// Special prefix: don't rewrite `@@oldName` when looking for a
		// global oldName (the `@@` prefix means it's a different symbol).
		if !local && i >= 2 && line[i-1] == '@' && line[i-2] == '@' {
			b.WriteByte(line[i])
			i++
			continue
		}
		if local {
			b.WriteString("@@")
			b.WriteString(newName)
		} else {
			b.WriteString(newName)
		}
		i = end
		if !inComment {
			shift += len(newName) - len(oldName)
		}
	}
	return b.String()
}

func startsWith(s string, i int, prefix string) bool {
	if i+len(prefix) > len(s) {
		return false
	}
	return s[i:i+len(prefix)] == prefix
}

func isIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_'
}

func containsWord(line, word string) bool {
	idx := strings.Index(line, word)
	if idx < 0 {
		return false
	}
	if idx > 0 && isIdentByte(line[idx-1]) {
		return false
	}
	end := idx + len(word)
	if end < len(line) && isIdentByte(line[end]) {
		return false
	}
	return true
}

// Reparse re-parses the affected source files after Apply, producing an
// updated index. Caller substitutes the new index atomically.
func Reparse(idx *index.Index, paths []string) ([]*source.File, error) {
	out := make([]*source.File, 0, len(paths))
	for _, p := range paths {
		f, err := source.ParseFile(p)
		if err != nil {
			return nil, fmt.Errorf("reparse %s: %w", p, err)
		}
		out = append(out, f)
	}
	return out, nil
}
