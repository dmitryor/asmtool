// Package mcp wires the index query layer onto the MCP protocol surface.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/orlovsky/jwasm-mcp/internal/classify"
	"github.com/orlovsky/jwasm-mcp/internal/config"
	"github.com/orlovsky/jwasm-mcp/internal/index"
	"github.com/orlovsky/jwasm-mcp/internal/rename"
	"github.com/orlovsky/jwasm-mcp/internal/source"
)

// Server holds the live index plus mutable state to support reloads.
type Server struct {
	cfg *config.Config
	mu  sync.RWMutex
	idx *index.Index
	// rebuild, when non-nil, runs a full re-parse and jwasm rebuild and
	// swaps the resulting index. Called synchronously by write tools
	// (rename_symbol) so addresses survive across edits without waiting
	// for the watcher's debounce window.
	rebuild func() error
}

func New(cfg *config.Config, idx *index.Index) *Server {
	return &Server{cfg: cfg, idx: idx}
}

// SetRebuild installs the rebuild callback. Pass nil to clear.
func (s *Server) SetRebuild(fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rebuild = fn
}

func (s *Server) rebuildFn() func() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rebuild
}

func (s *Server) Index() *index.Index {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.idx
}

func (s *Server) SetIndex(idx *index.Index) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idx = idx
}

// Build returns a fully-wired MCP server backed by s. Caller can pass it to
// server.ServeStdio for stdio transport.
func (s *Server) Build() *server.MCPServer {
	srv := server.NewMCPServer(
		"jwasm-mcp",
		"0.1.0",
		server.WithToolCapabilities(false),
	)
	s.registerTools(srv)
	return srv
}

// jsonText marshals v to indented JSON and wraps it as a text tool result.
// All structured replies go through this so the agent always gets the same
// JSON-shaped surface regardless of which tool produced the result.
func jsonText(v any) *mcp.CallToolResult {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError("internal: marshal: " + err.Error())
	}
	return mcp.NewToolResultText(string(b))
}

func errResult(msg string) *mcp.CallToolResult {
	return mcp.NewToolResultError(msg)
}

// resolveFile lets callers refer to files by basename ("render3d.inc") or
// absolute path. Returns the absolute path used by the index.
func (s *Server) resolveFile(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	idx := s.Index()
	for path := range idx.Files {
		if filepath.Base(path) == name {
			return path
		}
	}
	for _, sp := range s.cfg.SourcePaths {
		candidate := filepath.Join(sp, name)
		if _, ok := idx.Files[candidate]; ok {
			return candidate
		}
	}
	return name
}

// parseAddrArg accepts decimal or hex (with optional 0x prefix or h suffix).
func parseAddrArg(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.TrimSuffix(s, "h")
	s = strings.TrimSuffix(s, "H")
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		// fallback to decimal if hex didn't parse
		if v2, err2 := strconv.ParseUint(s, 10, 32); err2 == nil {
			return uint32(v2), nil
		}
		return 0, fmt.Errorf("addr %q: not a valid hex/decimal value: %w", s, err)
	}
	return uint32(v), nil
}

// ----- Tool registration -----

func (s *Server) registerTools(srv *server.MCPServer) {
	srv.AddTool(mcp.NewTool("which_proc",
		mcp.WithDescription("Return the PROC enclosing a (file, line) location."),
		mcp.WithString("file", mcp.Required(),
			mcp.Description("Source file (basename like render3d.inc, or absolute path)")),
		mcp.WithNumber("line", mcp.Required(),
			mcp.Description("1-indexed source line number")),
	), s.handleWhichProc)

	srv.AddTool(mcp.NewTool("read_proc",
		mcp.WithDescription("Return the full source of a PROC, from declaration through ENDP."),
		mcp.WithString("name", mcp.Required(),
			mcp.Description("PROC name")),
	), s.handleReadProc)

	srv.AddTool(mcp.NewTool("find_callers",
		mcp.WithDescription("Return call/jmp references targeting the given symbol. When the name resolves to a global declaration (PROC/export/global/EQU), only non-@@ refs are returned. When the name only exists as a PROC-local label, only @@-refs are returned -- pass `in_proc` to scope to one PROC."),
		mcp.WithString("name", mcp.Required()),
		mcp.WithString("in_proc",
			mcp.Description("Optional: enclosing PROC name (only relevant for local labels)")),
	), s.handleFindCallers)

	srv.AddTool(mcp.NewTool("find_data_refs",
		mcp.WithDescription("Counterpart to find_callers for data symbols. Returns memory-operand, immediate, offset-keyword, and dw/db/dd references (every use that isn't a call/jmp). Use to understand how a data label or EQU is read/written -- the natural read tool when naming an unresolved data symbol. Output groups counts by `kind` and, for memory-operand refs, by `access` (`read`/`write`/`rw`) so writers and readers can be sorted without substring-matching `text`. When the queried name is an SMC anchor with no direct refs, the response includes an `aliases` list pointing to its EQU'd Var_* slots."),
		mcp.WithString("name", mcp.Required()),
		mcp.WithString("in_proc",
			mcp.Description("Optional: enclosing PROC name (only relevant for local labels)")),
	), s.handleFindDataRefs)

	srv.AddTool(mcp.NewTool("find_callees",
		mcp.WithDescription("Return distinct call/jmp targets from a PROC body, split into `external` (cross-PROC outgoing edges of the call graph -- what most queries want) and `internal` (`@@local` jumps that stay inside this PROC -- usually internal control flow noise). De-duplicated by (target, kind)."),
		mcp.WithString("name", mcp.Required(),
			mcp.Description("Containing PROC name")),
	), s.handleFindCallees)

	srv.AddTool(mcp.NewTool("module_layout",
		mcp.WithDescription("List PROCs in a module file, sorted by start line, with addresses if known."),
		mcp.WithString("file", mcp.Required()),
	), s.handleModuleLayout)

	srv.AddTool(mcp.NewTool("addr_to_location",
		mcp.WithDescription("Map a CS offset to its enclosing PROC. Accepts hex (0xa17c, A17Ch) or decimal."),
		mcp.WithString("addr", mcp.Required()),
	), s.handleAddrToLocation)

	srv.AddTool(mcp.NewTool("find_symbol",
		mcp.WithDescription("Look up declarations of a symbol by name. Returns one entry per declaration site."),
		mcp.WithString("name", mcp.Required()),
	), s.handleFindSymbol)

	srv.AddTool(mcp.NewTool("function_context",
		mcp.WithDescription("Composite read for a PROC. Returns in one call: full body, every caller site (with N lines of surrounding code so you see what arguments/registers are set up), external callees (cross-PROC; internal @@-local jumps are counted but suppressed as noise), prev/next sibling PROCs in the same module, and the @@-local label list. Use this to name an unresolved scaffolding PROC without making 5+ separate read/grep calls."),
		mcp.WithString("name", mcp.Required()),
		mcp.WithNumber("caller_context_lines",
			mcp.Description("Lines of surrounding code per call site (default 5; 0 to suppress)")),
	), s.handleFunctionContext)

	srv.AddTool(mcp.NewTool("rename_symbol",
		mcp.WithDescription("Atomic, scope-aware rename of a JWasm symbol across the source tree. Word-boundary matching avoids substring hits; @@-local renames are confined to one PROC; collisions with existing names are refused. Pass dry_run=true to preview the edits without writing."),
		mcp.WithString("old", mcp.Required(),
			mcp.Description("Existing symbol name (without `@@` prefix; pass in_proc to scope locals)")),
		mcp.WithString("new", mcp.Required(),
			mcp.Description("New name (must be a valid JWasm identifier)")),
		mcp.WithString("in_proc",
			mcp.Description("For @@-local renames: the enclosing PROC. Required when old is only declared as a local label.")),
		mcp.WithBoolean("dry_run",
			mcp.Description("If true, return the edit list without writing (default: true; pass false to apply).")),
		mcp.WithBoolean("include_docs",
			mcp.Description("If true, also rewrite *.md files under doc_paths (global renames only). Default: false.")),
		mcp.WithBoolean("allow_locals_across_procs",
			mcp.Description("When old is a PROC-local label declared in many PROCs, this opt-in allows renaming every instance. Off by default to prevent accidental sweeping renames of common labels (Done/Loop/Ret).")),
	), s.handleRenameSymbol)

	srv.AddTool(mcp.NewTool("scan_relocation_blockers",
		mcp.WithDescription("Scan the project for hardcoded literal addresses that would prevent moving the code. Returns confidence-tagged candidates: 'definite' (literal in [imm] memory operand matching a known label) needs no review; 'probable' (dw entries matching labels) needs spot-check; 'ambiguous' (mov reg, imm matching label) needs review."),
		mcp.WithString("file",
			mcp.Description("Optional: limit scan to a single source file (basename or absolute path)")),
		mcp.WithString("confidence",
			mcp.Description("Optional filter: 'definite', 'probable', or 'ambiguous' (default: all)")),
		mcp.WithNumber("limit",
			mcp.Description("Max entries to return (default 200)")),
	), s.handleScanBlockers)

	srv.AddTool(mcp.NewTool("smc_clusters",
		mcp.WithDescription("Group SMC anchors that sit close together in CSEG into clusters -- typically the runs of 2-3 consecutive immediates a single writer PROC patches at once. Two anchors are placed in the same cluster when they share a source file and their CSEG addresses are within `max_gap` bytes of each other (default 16). Each cluster surfaces its members (anchor, var alias, slot info, host instruction) plus the distinct PROCs that write to any var in it -- the natural unit of SMC analysis when annotating a 100+-var backlog. Use this BEFORE per-var annotation: name the cluster's purpose first, then individual vars inherit the role."),
		mcp.WithString("file",
			mcp.Description("Optional: limit scan to a single source file (basename or absolute path)")),
		mcp.WithNumber("max_gap",
			mcp.Description("Max byte gap between consecutive anchors to keep them in the same cluster (default 16)")),
		mcp.WithNumber("min_size",
			mcp.Description("Minimum cluster size -- singletons are usually noise (default 2)")),
		mcp.WithNumber("limit",
			mcp.Description("Max clusters to return (default 50)")),
	), s.handleSmcClusters)

	srv.AddTool(mcp.NewTool("smc_var_info",
		mcp.WithDescription("Composite read for a self-modifying-code variable. Accepts either the Var_NNNN EQU alias or its SmcAnchor_NNNN host label, and returns the var's typed-pointer slot (size + byte offset), the anchor declaration with address, the host instruction's source line, and a writer/reader split derived from access classification of every memory-operand ref. Replaces the four-call dance (read globals.inc EQU + find_symbol(anchor) + Read host line + find_data_refs(var)) with one call -- the natural primitive for the SMC-annotation worklist."),
		mcp.WithString("name", mcp.Required(),
			mcp.Description("Var_NNNN alias or SmcAnchor_NNNN host label")),
	), s.handleSmcVarInfo)

	srv.AddTool(mcp.NewTool("unresolved",
		mcp.WithDescription("Return symbols that still carry auto-generated scaffolding names (FUN_*, Lxxxx, WORD_1000_*, BYTE_1000_*, DAT_*, Var_<hex>) ranked by reference count -- the highest-leverage entries are the ones with most callers/uses. The natural worklist source for a 'name what's still unnamed' session: pick a high-rank entry, run function_context (PROC) or find_data_refs (data) to understand it, propose a name, then rename_symbol with dry_run=true to preview."),
		mcp.WithString("kind",
			mcp.Description("'procs' (default) for FUN_/Lxxxx PROCs, 'data' for WORD_/BYTE_/DAT_/Var_ data labels, 'all' for both")),
		mcp.WithNumber("limit",
			mcp.Description("Max entries to return (default 50)")),
	), s.handleUnresolved)
}

// ----- Tool handlers -----

func (s *Server) handleWhichProc(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	file, err := req.RequireString("file")
	if err != nil {
		return errResult("missing 'file': " + err.Error()), nil
	}
	line, err := req.RequireFloat("line")
	if err != nil {
		return errResult("missing 'line': " + err.Error()), nil
	}
	abs := s.resolveFile(file)
	idx := s.Index()
	if _, ok := idx.Files[abs]; !ok {
		return jsonText(map[string]any{
			"found": false,
			"file":  filepath.Base(abs),
			"line":  int(line),
			"note":  "file not in the index; check basename or pass an absolute path covered by source_paths",
		}), nil
	}
	p := idx.WhichProc(abs, int(line))
	if p == nil {
		return jsonText(map[string]any{
			"found": false,
			"file":  filepath.Base(abs),
			"line":  int(line),
			"note":  "no PROC encloses this line (likely header comment, EQU declaration, or inline data between PROCs)",
		}), nil
	}
	return jsonText(map[string]any{
		"found":      true,
		"name":       p.Name,
		"file":       filepath.Base(p.File),
		"start_line": p.StartLine,
		"end_line":   p.EndLine,
		"addr":       fmt.Sprintf("0x%04x", p.Addr),
		"end_addr":   fmt.Sprintf("0x%04x", p.EndAddr),
		"size_bytes": p.EndAddr - p.Addr,
	}), nil
}

func (s *Server) handleReadProc(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return errResult("missing 'name': " + err.Error()), nil
	}
	idx := s.Index()
	body, err := idx.ReadProc(name)
	if err != nil {
		return errResult(err.Error()), nil
	}
	p := idx.Procs[name]
	return jsonText(map[string]any{
		"name":       p.Name,
		"file":       filepath.Base(p.File),
		"start_line": p.StartLine,
		"end_line":   p.EndLine,
		"addr":       fmt.Sprintf("0x%04x", p.Addr),
		"size_bytes": p.EndAddr - p.Addr,
		"body":       body,
	}), nil
}

func (s *Server) handleFindCallers(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return errResult("missing 'name': " + err.Error()), nil
	}
	inProc := req.GetString("in_proc", "")
	refs := s.Index().FindCallersScoped(name, inProc)
	out := make([]map[string]any, 0, len(refs))
	for _, r := range refs {
		out = append(out, map[string]any{
			"file":           filepath.Base(r.File),
			"line":           r.Line,
			"kind":           r.Kind,
			"in_proc":        r.EnclosingProc,
			"text":           r.Text,
		})
	}
	return jsonText(map[string]any{
		"target":      name,
		"caller_count": len(out),
		"callers":     out,
	}), nil
}

func (s *Server) handleFindDataRefs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return errResult("missing 'name': " + err.Error()), nil
	}
	inProc := req.GetString("in_proc", "")
	idx := s.Index()
	refs := idx.FindDataRefsScoped(name, inProc)
	out := make([]map[string]any, 0, len(refs))
	byKind := map[string]int{}
	byAccess := map[string]int{}
	for _, r := range refs {
		entry := map[string]any{
			"file":    filepath.Base(r.File),
			"line":    r.Line,
			"kind":    r.Kind,
			"in_proc": r.EnclosingProc,
			"text":    r.Text,
		}
		if a := index.ClassifyAccess(r); a != "" {
			entry["access"] = a
			byAccess[a]++
		}
		out = append(out, entry)
		byKind[r.Kind]++
	}
	res := map[string]any{
		"target":    name,
		"ref_count": len(out),
		"by_kind":   byKind,
		"refs":      out,
	}
	if len(byAccess) > 0 {
		res["by_access"] = byAccess
	}
	// SMC anchor case: when the queried name is a label-only export with no
	// memory-operand uses, the writes typically go through Var_NNNN EQUates
	// of the form `byte ptr <Anchor> + N`. Surface those aliases so the
	// caller can re-query without grepping.
	if len(out) == 0 {
		if aliases := idx.FindEquAliasesOf(name); len(aliases) > 0 {
			aliasList := make([]map[string]any, 0, len(aliases))
			for _, a := range aliases {
				slot, _ := index.ParseSmcEqu(a.Text)
				aliasList = append(aliasList, map[string]any{
					"name":   a.Name,
					"file":   filepath.Base(a.File),
					"line":   a.Line,
					"size":   slot.Size,
					"offset": slot.Offset,
					"text":   a.Text,
				})
			}
			res["aliases"] = aliasList
			res["note"] = "no direct refs -- this looks like an SMC anchor exported as a label only; writes/reads go through the EQU'd Var_* aliases listed under `aliases`. Try smc_var_info(<alias>) or find_data_refs(<alias>) for the full picture."
		}
	}
	return jsonText(res), nil
}

func (s *Server) handleFindCallees(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return errResult("missing 'name': " + err.Error()), nil
	}
	idx := s.Index()
	if _, ok := idx.Procs[name]; !ok {
		// Helpful redirect: distinguish "no such symbol at all" from
		// "symbol exists but isn't a PROC."
		if syms := idx.FindSymbol(name); len(syms) > 0 {
			return errResult(fmt.Sprintf(
				"%q is %s (declared in %s:%d), not a PROC -- try find_data_refs for non-control-transfer uses",
				name, syms[0].Kind, filepath.Base(syms[0].File), syms[0].Line)), nil
		}
		return errResult("PROC not found: " + name + " (and no other declarations in the index)"), nil
	}
	external, internal := idx.FindCalleesScoped(name)
	mkList := func(refs []*index.RefEntry) []map[string]any {
		out := make([]map[string]any, 0, len(refs))
		for _, r := range refs {
			out = append(out, map[string]any{
				"target": r.Target,
				"kind":   r.Kind,
				"line":   r.Line,
				"text":   r.Text,
			})
		}
		return out
	}
	return jsonText(map[string]any{
		"proc":            name,
		"external":        mkList(external),
		"external_count":  len(external),
		"internal":        mkList(internal),
		"internal_count":  len(internal),
	}), nil
}

func (s *Server) handleModuleLayout(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	file, err := req.RequireString("file")
	if err != nil {
		return errResult("missing 'file': " + err.Error()), nil
	}
	abs := s.resolveFile(file)
	idx := s.Index()
	src, indexed := idx.Files[abs]
	procs := idx.ModuleProcs(abs)
	out := make([]map[string]any, 0, len(procs))
	for _, p := range procs {
		out = append(out, map[string]any{
			"name":       p.Name,
			"start_line": p.StartLine,
			"end_line":   p.EndLine,
			"addr":       fmt.Sprintf("0x%04x", p.Addr),
			"end_addr":   fmt.Sprintf("0x%04x", p.EndAddr),
			"size_bytes": p.EndAddr - p.Addr,
		})
	}
	res := map[string]any{
		"file":       filepath.Base(abs),
		"proc_count": len(out),
		"procs":      out,
	}
	if !indexed {
		res["note"] = "file not in the index; check basename or pass an absolute path covered by source_paths"
	} else if len(out) == 0 {
		// Could be the master .asm with only INCLUDEs, or globals-only.
		if src != nil && len(src.Includes) > 0 {
			res["note"] = "this file contains no PROCs but has INCLUDEs -- likely the master .asm; included modules:"
			res["includes"] = src.Includes
		} else {
			res["note"] = "no PROCs declared in this file (likely globals/EQU-only)"
		}
	}
	return jsonText(res), nil
}

func (s *Server) handleAddrToLocation(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	addrStr, err := req.RequireString("addr")
	if err != nil {
		return errResult("missing 'addr': " + err.Error()), nil
	}
	addr, err := parseAddrArg(addrStr)
	if err != nil {
		return errResult(err.Error()), nil
	}
	idx := s.Index()
	p := idx.AddrToProc(addr)
	if p == nil {
		// Could be in globals_lo/_hi (above last PROC's end_addr) or simply
		// outside CSEG. Surface that to the caller.
		return jsonText(map[string]any{
			"found": false,
			"addr":  fmt.Sprintf("0x%04x", addr),
			"note":  "no PROC encloses this address (likely globals_lo, DSEG, or outside CSEG)",
		}), nil
	}
	offsetWithin := addr - p.Addr
	res := map[string]any{
		"found":          true,
		"addr":           fmt.Sprintf("0x%04x", addr),
		"proc":           p.Name,
		"file":           filepath.Base(p.File),
		"proc_start":     fmt.Sprintf("0x%04x", p.Addr),
		"offset_in_proc": fmt.Sprintf("0x%x", offsetWithin),
	}
	// SMC enrichment: if the addr lands on an anchor (or one of its var-aliased
	// slots) we already know the host instruction without making the caller
	// open the source file. Surface it inline so addr->host-instr is a single
	// query for the agent's SMC-annotation worklist.
	if site := idx.SmcSiteAt(addr); site != nil {
		smc := map[string]any{
			"anchor":           site.Anchor.Name,
			"anchor_addr":      fmt.Sprintf("0x%04x", site.Anchor.Addr),
			"host_instruction": site.HostInstruction,
			"src_file":         filepath.Base(site.Anchor.File),
			"src_line":         site.Anchor.Line,
		}
		if site.Var != nil {
			smc["var"] = site.Var.Name
			smc["slot"] = map[string]any{
				"size":   site.Slot.Size,
				"offset": site.Slot.Offset,
			}
			smc["role"] = "slot"
		} else {
			smc["role"] = "anchor"
		}
		res["smc_site"] = smc
	}
	return jsonText(res), nil
}

func (s *Server) handleFindSymbol(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return errResult("missing 'name': " + err.Error()), nil
	}
	syms := s.Index().FindSymbol(name)
	out := make([]map[string]any, 0, len(syms))
	for _, sym := range syms {
		entry := map[string]any{
			"file":           filepath.Base(sym.File),
			"line":           sym.Line,
			"kind":           sym.Kind,
			"enclosing_proc": sym.EnclosingProc,
		}
		if sym.HasAddr {
			entry["addr"] = fmt.Sprintf("0x%04x", sym.Addr)
		}
		if sym.Segment != "" {
			entry["segment"] = sym.Segment
		}
		out = append(out, entry)
	}
	return jsonText(map[string]any{
		"name":         name,
		"declarations": out,
		"count":        len(out),
	}), nil
}

// isProcScaffolding tests for naming patterns that indicate an unresolved
// PROC name: Ghidra-style FUN_*, Lxxxx where xxxx is hex (an unnamed branch
// target later promoted to a PROC), or Lb<hex> variants observed in retal.
func isProcScaffolding(name string) bool {
	switch {
	case strings.HasPrefix(name, "FUN_"):
		return true
	case strings.HasPrefix(name, "Lb"):
		return looksHexTail(strings.TrimPrefix(name, "Lb"))
	case len(name) >= 4 && name[0] == 'L' && looksHexTail(name[1:]):
		return true
	}
	return false
}

// isDataScaffolding tests for naming patterns that indicate an unresolved
// data label: Ghidra's WORD_/BYTE_/DAT_ exports, plus the Var_<hex> EQUates
// commonly used as placeholder data symbols in this project.
func isDataScaffolding(name string) bool {
	switch {
	case strings.HasPrefix(name, "WORD_"):
		return true
	case strings.HasPrefix(name, "BYTE_"):
		return true
	case strings.HasPrefix(name, "DAT_"):
		return true
	case strings.HasPrefix(name, "Var_"):
		// Var_<hex> -- the trailing token must look hex
		return looksHexTail(strings.TrimPrefix(name, "Var_"))
	}
	return false
}

// isScaffoldingName tests both PROC and data forms.
func isScaffoldingName(name string) bool {
	return isProcScaffolding(name) || isDataScaffolding(name)
}

func looksHexTail(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

func (s *Server) handleUnresolved(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := int(req.GetFloat("limit", 50))
	if limit <= 0 {
		limit = 50
	}
	kind := strings.ToLower(req.GetString("kind", "procs"))
	wantProcs, wantData := false, false
	switch kind {
	case "procs", "":
		wantProcs = true
	case "data":
		wantData = true
	case "all":
		wantProcs, wantData = true, true
	default:
		return errResult("unresolved: kind must be 'procs', 'data', or 'all'"), nil
	}
	idx := s.Index()
	type item struct {
		Name     string
		Kind     string
		File     string
		Line     int
		Addr     uint32
		HasAddr  bool
		Size     uint32
		RefCount int
	}
	var items []item
	if wantProcs {
		for name, p := range idx.Procs {
			if !isProcScaffolding(name) {
				continue
			}
			items = append(items, item{
				Name:     name,
				Kind:     "PROC",
				File:     filepath.Base(p.File),
				Line:     p.StartLine,
				Addr:     p.Addr,
				HasAddr:  p.HasAddr,
				Size:     p.EndAddr - p.Addr,
				RefCount: len(idx.FindCallers(name)),
			})
		}
	}
	if wantData {
		// Iterate symbols (deduped by name; first declaration wins for
		// presentation). PROCs were handled above so skip them here.
		seen := map[string]bool{}
		for name, decls := range idx.Symbols {
			if seen[name] || isProcScaffolding(name) || !isDataScaffolding(name) {
				continue
			}
			if _, isProc := idx.Procs[name]; isProc {
				continue
			}
			seen[name] = true
			refs := idx.FindRefs(name)
			d := decls[0]
			items = append(items, item{
				Name:     name,
				Kind:     d.Kind,
				File:     filepath.Base(d.File),
				Line:     d.Line,
				Addr:     d.Addr,
				HasAddr:  d.HasAddr,
				RefCount: len(refs),
			})
		}
	}
	// sort by refcount desc, tiebreak by addr asc
	sort.Slice(items, func(i, j int) bool {
		if items[i].RefCount != items[j].RefCount {
			return items[i].RefCount > items[j].RefCount
		}
		return items[i].Addr < items[j].Addr
	})
	total := len(items)
	if len(items) > limit {
		items = items[:limit]
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		entry := map[string]any{
			"name":      it.Name,
			"kind":      it.Kind,
			"file":      it.File,
			"line":      it.Line,
			"ref_count": it.RefCount,
		}
		if it.HasAddr {
			entry["addr"] = fmt.Sprintf("0x%04x", it.Addr)
		}
		if it.Size > 0 {
			entry["size_bytes"] = it.Size
		}
		out = append(out, entry)
	}
	return jsonText(map[string]any{
		"total_unresolved": total,
		"limit":            limit,
		"kind":             kind,
		"items":            out,
	}), nil
}

func (s *Server) handleRenameSymbol(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	oldName, err := req.RequireString("old")
	if err != nil {
		return errResult("missing 'old': " + err.Error()), nil
	}
	newName, err := req.RequireString("new")
	if err != nil {
		return errResult("missing 'new': " + err.Error()), nil
	}
	inProc := req.GetString("in_proc", "")
	// Default dry_run=true. The caller has to opt in to applying.
	dryRun := req.GetBool("dry_run", true)
	includeDocs := req.GetBool("include_docs", false)
	allowLocals := req.GetBool("allow_locals_across_procs", false)

	idx := s.Index()
	plan, err := rename.PlanRename(idx, oldName, newName, rename.Options{
		InProc:                 inProc,
		IncludeDocs:            includeDocs,
		AllowLocalsAcrossProcs: allowLocals,
		DocPaths:               s.cfg.DocPaths,
	})
	if err != nil {
		return errResult(err.Error()), nil
	}
	if dryRun {
		out := map[string]any{
			"dry_run":       true,
			"old":           plan.OldName,
			"new":           plan.NewName,
			"is_local":      plan.IsLocal,
			"in_proc":       plan.InProc,
			"files_touched": plan.FilesTouched,
			"edit_count":    len(plan.Edits),
			"edits":         plan.Edits,
		}
		if len(plan.Edits) == 0 {
			hint := "no edits planned -- old name resolved but produced no rewrites"
			if plan.IsLocal && plan.InProc != "" {
				hint = fmt.Sprintf("no @@%s declaration found inside PROC %q -- check spelling or query find_symbol(%q) for the actual enclosing PROCs",
					plan.OldName, plan.InProc, plan.OldName)
			}
			out["note"] = hint
		}
		return jsonText(out), nil
	}
	if err := rename.Apply(plan); err != nil {
		return errResult("apply: " + err.Error()), nil
	}
	// Trigger a full rebuild (jwasm + reparse + atomic swap) so addresses
	// survive the rename. Falls back to a fast partial reparse (no listing)
	// if no rebuild callback is registered -- that branch loses addresses
	// until the next watcher fire, but never serves stale source.
	rebuilt := false
	if fn := s.rebuildFn(); fn != nil {
		if err := fn(); err != nil {
			return errResult("apply succeeded but rebuild failed: " + err.Error()), nil
		}
		rebuilt = true
	} else {
		touched := map[string]bool{}
		for _, e := range plan.Edits {
			if filepath.Ext(e.File) == ".inc" || filepath.Ext(e.File) == ".asm" {
				touched[e.File] = true
			}
		}
		var paths []string
		for p := range touched {
			paths = append(paths, p)
		}
		if files, err := rename.Reparse(idx, paths); err == nil {
			s.replaceParsedFiles(files)
		}
	}
	return jsonText(map[string]any{
		"applied":              true,
		"old":                  plan.OldName,
		"new":                  plan.NewName,
		"is_local":             plan.IsLocal,
		"in_proc":              plan.InProc,
		"files_touched":        plan.FilesTouched,
		"edit_count":           len(plan.Edits),
		"index_fully_rebuilt":  rebuilt,
	}), nil
}

// replaceParsedFiles swaps the parsed Files entries for the given paths
// and rebuilds the index. It does not re-run jwasm; symbol-table addresses
// remain stale until the next full rebuild. Most queries (callers, body,
// PROCs by name) are unaffected -- only address-bearing tools regress.
func (s *Server) replaceParsedFiles(updated []*source.File) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.idx
	if cur == nil {
		return
	}
	all := make([]*source.File, 0, len(cur.Files))
	updatedByPath := map[string]*source.File{}
	for _, f := range updated {
		updatedByPath[f.Path] = f
	}
	for path, f := range cur.Files {
		if u, ok := updatedByPath[path]; ok {
			all = append(all, u)
		} else {
			all = append(all, f)
		}
	}
	s.idx = index.Build(all, nil)
	// Note: we lose addresses on this fast path. A subsequent full rebuild
	// (via the watcher or restart) will restore them.
}

func (s *Server) handleScanBlockers(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fileFilter := req.GetString("file", "")
	confFilter := strings.ToLower(req.GetString("confidence", ""))
	limit := int(req.GetFloat("limit", 200))
	if limit <= 0 {
		limit = 200
	}
	all := classify.Scan(s.Index())
	var fileAbs string
	if fileFilter != "" {
		fileAbs = filepath.Base(s.resolveFile(fileFilter))
	}
	var filtered []classify.Candidate
	for _, c := range all {
		if fileAbs != "" && c.File != fileAbs {
			continue
		}
		if confFilter != "" && string(c.Confidence) != confFilter {
			continue
		}
		filtered = append(filtered, c)
	}
	out := filtered
	if len(out) > limit {
		out = out[:limit]
	}
	bucket := map[classify.Confidence]int{}
	for _, c := range filtered {
		bucket[c.Confidence]++
	}
	return jsonText(map[string]any{
		"total":      len(filtered),
		"shown":      len(out),
		"definite":   bucket[classify.DefiniteAddress],
		"probable":   bucket[classify.ProbableAddress],
		"ambiguous":  bucket[classify.AmbiguousAddress],
		"candidates": out,
	}), nil
}

// handleSmcClusters returns SMC anchors grouped by spatial proximity --
// the high-level view of "which anchors are written together by one PROC."
// See Index.SmcClusters for the grouping heuristic.
func (s *Server) handleSmcClusters(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fileFilter := req.GetString("file", "")
	maxGap := uint32(req.GetFloat("max_gap", 16))
	if maxGap == 0 {
		maxGap = 16
	}
	minSize := int(req.GetFloat("min_size", 2))
	if minSize < 1 {
		minSize = 2
	}
	limit := int(req.GetFloat("limit", 50))
	if limit <= 0 {
		limit = 50
	}
	idx := s.Index()
	var fileAbs string
	if fileFilter != "" {
		fileAbs = s.resolveFile(fileFilter)
	}
	clusters := idx.SmcClusters(fileAbs, maxGap, minSize)
	total := len(clusters)
	if len(clusters) > limit {
		clusters = clusters[:limit]
	}
	out := make([]map[string]any, 0, len(clusters))
	for _, c := range clusters {
		anchors := make([]map[string]any, 0, len(c.Anchors))
		for _, a := range c.Anchors {
			row := map[string]any{
				"anchor":           a.Anchor.Name,
				"addr":             fmt.Sprintf("0x%04x", a.Anchor.Addr),
				"line":             a.Anchor.Line,
				"host_instruction": a.HostInstr,
			}
			if a.Var != nil {
				row["var"] = a.Var.Name
				row["slot"] = map[string]any{
					"size":   a.Slot.Size,
					"offset": a.Slot.Offset,
				}
			}
			anchors = append(anchors, row)
		}
		entry := map[string]any{
			"file":         filepath.Base(c.File),
			"start_addr":   fmt.Sprintf("0x%04x", c.StartAddr),
			"end_addr":     fmt.Sprintf("0x%04x", c.EndAddr),
			"size_bytes":   c.EndAddr - c.StartAddr,
			"anchor_count": len(c.Anchors),
			"anchors":      anchors,
		}
		if len(c.Procs) > 0 {
			entry["writer_procs"] = c.Procs
		}
		out = append(out, entry)
	}
	return jsonText(map[string]any{
		"total":    total,
		"shown":    len(out),
		"max_gap":  maxGap,
		"min_size": minSize,
		"clusters": out,
	}), nil
}

// handleSmcVarInfo resolves the var↔anchor pairing for a self-modifying
// code slot and returns the host instruction plus a writer/reader split.
// Accepts either side of the pair: a Var_NNNN EQU alias or the SmcAnchor_NNNN
// label it points at.
func (s *Server) handleSmcVarInfo(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return errResult("missing 'name': " + err.Error()), nil
	}
	idx := s.Index()
	decls := idx.FindSymbol(name)
	if len(decls) == 0 {
		return errResult("symbol not found: " + name), nil
	}

	// Resolve to (varName, anchorName, slot).
	var varDecl *index.SymbolEntry
	var anchorName string
	var slot index.SmcSlot
	for _, d := range decls {
		if d.Kind == "EQU" {
			if sl, ok := index.ParseSmcEqu(d.Text); ok {
				varDecl = d
				anchorName = sl.Anchor
				slot = sl
				break
			}
		}
	}
	if varDecl == nil {
		// Try the other direction: name is the anchor; find any aliasing EQU.
		aliases := idx.FindEquAliasesOf(name)
		if len(aliases) == 0 {
			return errResult(fmt.Sprintf(
				"%q is not an SMC var (no `<size> ptr <anchor> + N` EQU) and no Var_* EQU aliases this symbol either",
				name)), nil
		}
		// Use the first alias as the canonical view; surface the others.
		varDecl = aliases[0]
		sl, _ := index.ParseSmcEqu(varDecl.Text)
		anchorName = sl.Anchor
		slot = sl
	}

	anchorDecls := idx.FindSymbol(anchorName)
	if len(anchorDecls) == 0 {
		return errResult(fmt.Sprintf(
			"var %q references anchor %q but no declaration of the anchor was found",
			varDecl.Name, anchorName)), nil
	}
	anchor := anchorDecls[0]

	res := map[string]any{
		"var":    varDecl.Name,
		"anchor": anchor.Name,
		"slot": map[string]any{
			"size":   slot.Size,
			"offset": slot.Offset,
		},
		"var_decl": map[string]any{
			"file": filepath.Base(varDecl.File),
			"line": varDecl.Line,
			"kind": varDecl.Kind,
			"text": varDecl.Text,
		},
	}
	anchorEntry := map[string]any{
		"file": filepath.Base(anchor.File),
		"line": anchor.Line,
		"kind": anchor.Kind,
	}
	if anchor.HasAddr {
		anchorEntry["addr"] = fmt.Sprintf("0x%04x", anchor.Addr)
	}
	res["anchor_decl"] = anchorEntry
	if instr := idx.HostInstruction(anchor); instr != "" {
		res["host_instruction"] = map[string]any{
			"file": filepath.Base(anchor.File),
			"line": anchor.Line,
			"text": instr,
		}
	}

	// Writer/reader split. Memory-operand refs against the var alias are
	// the patches; reads through the anchor itself are implicit (the
	// runtime reads the patched immediate every time the host instruction
	// executes), so we only surface mem-operand refs here.
	refs := idx.FindDataRefs(varDecl.Name)
	mkRef := func(r *index.RefEntry) map[string]any {
		return map[string]any{
			"file":    filepath.Base(r.File),
			"line":    r.Line,
			"kind":    r.Kind,
			"in_proc": r.EnclosingProc,
			"text":    r.Text,
		}
	}
	var writers, readers, other []map[string]any
	for _, r := range refs {
		entry := mkRef(r)
		switch index.ClassifyAccess(r) {
		case "write":
			writers = append(writers, entry)
		case "rw":
			entry["access"] = "rw"
			writers = append(writers, entry)
		case "read":
			readers = append(readers, entry)
		default:
			other = append(other, entry)
		}
	}
	res["writers"] = writers
	res["writer_count"] = len(writers)
	res["readers"] = readers
	res["reader_count"] = len(readers)
	if len(other) > 0 {
		res["other_refs"] = other
		res["other_ref_count"] = len(other)
	}
	return jsonText(res), nil
}

// handleFunctionContext is wired by the dedicated context package.
// Implemented in context_handler.go to keep this file focused.
func (s *Server) handleFunctionContext(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return errResult("missing 'name': " + err.Error()), nil
	}
	cl := int(req.GetFloat("caller_context_lines", 5))
	if cl < 0 {
		cl = 0
	}
	idx := s.Index()
	out, err := buildFunctionContext(idx, name, cl)
	if err != nil {
		return errResult(err.Error()), nil
	}
	return jsonText(out), nil
}
