package tool

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dmitryor/asmtool/internal/index"
)

type callerSite struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Kind        string `json:"kind"`
	InProc      string `json:"in_proc"`
	Text        string `json:"text"`
	Surrounding string `json:"surrounding"`
}

type calleeRef struct {
	Target string `json:"target"`
	Kind   string `json:"kind"`
	Line   int    `json:"line"`
	Text   string `json:"text"`
}

type functionContextResult struct {
	Name              string       `json:"name"`
	Found             bool         `json:"found"`
	File              string       `json:"file,omitempty"`
	Addr              string       `json:"addr,omitempty"`
	StartLine         int          `json:"start_line,omitempty"`
	EndLine           int          `json:"end_line,omitempty"`
	SizeBytes         uint32       `json:"size_bytes,omitempty"`
	Body              string       `json:"body,omitempty"`
	Callers           []callerSite `json:"callers,omitempty"`
	CallerCount       int          `json:"caller_count"`
	ExternalCallees   []calleeRef  `json:"external_callees,omitempty"`
	ExternalCount     int          `json:"external_callee_count"`
	InternalJumpCount int          `json:"internal_jump_count"`
	PrevProc          string       `json:"prev_proc,omitempty"`
	NextProc          string       `json:"next_proc,omitempty"`
	Locals            []string     `json:"locals,omitempty"`
}

// buildFunctionContext is the composite query that goal 2 hangs on. It
// returns body + callers (with a small surrounding-lines window) + callees
// + sibling PROCs in the same module + @@-local labels declared inside.
// One command should give the caller everything needed for a naming decision.
func buildFunctionContext(idx *index.Index, name string, ctxLines int) (functionContextResult, error) {
	res := functionContextResult{Name: name}
	p, ok := idx.Procs[name]
	if !ok {
		return res, fmt.Errorf("PROC %q not found", name)
	}
	res.Found = true
	res.File = filepath.Base(p.File)
	res.Addr = fmt.Sprintf("0x%04x", p.Addr)
	res.StartLine = p.StartLine
	res.EndLine = p.EndLine
	res.SizeBytes = p.EndAddr - p.Addr
	if body, err := idx.ReadProc(name); err == nil {
		res.Body = body
	}

	callers := idx.FindCallers(name, "")
	res.CallerCount = len(callers)
	for _, c := range callers {
		surr := surroundingLines(idx, c.File, c.Line, ctxLines)
		res.Callers = append(res.Callers, callerSite{
			File:        filepath.Base(c.File),
			Line:        c.Line,
			Kind:        c.Kind,
			InProc:      c.EnclosingProc,
			Text:        c.Text,
			Surrounding: surr,
		})
	}

	external, internal := idx.FindCallees(name)
	res.ExternalCount = len(external)
	res.InternalJumpCount = len(internal)
	for _, c := range external {
		res.ExternalCallees = append(res.ExternalCallees, calleeRef{
			Target: c.Target,
			Kind:   c.Kind,
			Line:   c.Line,
			Text:   c.Text,
		})
	}
	// internal @@-local jumps suppressed by default -- they're internal
	// control flow noise; the body field already shows them in context.

	// Siblings: previous/next PROC in the same file by start line.
	res.PrevProc, res.NextProc = siblingProcs(idx, p.File, p.StartLine)

	// Local labels: read from the source file's parsed Procs.
	if f := idx.Files[p.File]; f != nil {
		for _, sp := range f.Procs {
			if sp.Name != name {
				continue
			}
			for _, l := range sp.LocalLabels {
				res.Locals = append(res.Locals, l.Name)
			}
		}
	}
	sort.Strings(res.Locals)
	return res, nil
}

func surroundingLines(idx *index.Index, file string, line, n int) string {
	if n <= 0 {
		return ""
	}
	f := idx.Files[file]
	if f == nil {
		return ""
	}
	start := line - n
	if start < 1 {
		start = 1
	}
	end := line + n
	if end > len(f.Lines) {
		end = len(f.Lines)
	}
	var b strings.Builder
	for i := start; i <= end; i++ {
		marker := "  "
		if i == line {
			marker = "->"
		}
		fmt.Fprintf(&b, "%s %5d  %s\n", marker, i, f.Lines[i-1])
	}
	return b.String()
}

func siblingProcs(idx *index.Index, file string, startLine int) (prev, next string) {
	procs := idx.ModuleProcs(file)
	for i, p := range procs {
		if p.StartLine != startLine {
			continue
		}
		if i > 0 {
			prev = procs[i-1].Name
		}
		if i+1 < len(procs) {
			next = procs[i+1].Name
		}
		return
	}
	return
}
