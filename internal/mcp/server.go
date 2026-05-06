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

	srv.AddTool(mcp.NewTool("data_refs_at",
		mcp.WithDescription("Address-keyed counterpart to find_data_refs. Returns the union of memory-operand/imm/offset/dw/db/dd refs from every symbol whose declared address falls in [addr, addr+size). Closes the alias-overlap case where a byte EQU (e.g. Var_d5c8) lives at the same byte as a word label (VideoDetectResult): writes go through the word alias and don't show up under the byte symbol's refs. Output groups refs by the source symbol they were declared against, with access classification per ref."),
		mcp.WithString("addr", mcp.Required(),
			mcp.Description("Start address. Hex (0xa720, A720h) or decimal.")),
		mcp.WithNumber("size",
			mcp.Description("Byte range to cover (default 1 -- byte query)")),
	), s.handleDataRefsAt)

	srv.AddTool(mcp.NewTool("smc_clusters",
		mcp.WithDescription("Group SMC anchors into clusters. Three grouping modes:\n  - by=\"proximity\" (default): anchors that share a source file AND lie within `max_gap` bytes of each other (default 16). Catches runs of 2-3 consecutive immediates patched together.\n  - by=\"writer_proc\" / \"reader_proc\": vars touched by the same PROC. Catches matrix-broadcast patterns where a single PROC reads or writes 4+ slots back-to-back even when they span ~150 source lines. Module-scope refs surface under the synthetic key `<file>:module-scope`.\n  - by=\"writer_file\" / \"reader_file\": coarser, file-keyed grouping. Right shape for module-scope setup blocks (e.g. polydraw.inc's 18 SMC slots all written at file scope without a PROC wrapper).\nEach cluster surfaces its members (anchor, var alias, slot info, host instruction). Proximity clusters also list the writer PROCs that touch any var in the cluster. Use proc/file-keyed clustering BEFORE per-var annotation: name the cluster's purpose first, then individual vars inherit the role."),
		mcp.WithString("by",
			mcp.Description("Cluster key: 'proximity' (default), 'writer_proc', 'reader_proc', 'writer_file', 'reader_file'")),
		mcp.WithString("proc",
			mcp.Description("With by=writer_proc/reader_proc: filter to one PROC name. For module-scope refs use '<basename>:module-scope'.")),
		mcp.WithString("file",
			mcp.Description("With by=proximity: limit anchor scan to a single source file. With by=writer_file/reader_file: limit cluster output to vars whose writers/readers live in that file.")),
		mcp.WithNumber("max_gap",
			mcp.Description("With by=proximity: max byte gap between consecutive anchors (default 16)")),
		mcp.WithNumber("min_size",
			mcp.Description("Minimum cluster size -- singletons are usually noise (default 2)")),
		mcp.WithNumber("limit",
			mcp.Description("Max clusters to return (default 50)")),
		mcp.WithNumber("sub_max_line_gap",
			mcp.Description("With by=writer_*/reader_*: gap (in source lines) below which adjacent writer/reader sites are sub-grouped. Default 25; 0 disables sub-clustering. Surfaces the 4-sub-cluster shape of e.g. perframe.inc (motion-delta broadcast, SP-anchor pair, LOD-scale group, timer pair) inside what would otherwise be a single 30-var blob.")),
	), s.handleSmcClusters)

	srv.AddTool(mcp.NewTool("find_mirror_writes",
		mcp.WithDescription("For a writer PROC, return groups of consecutive memory-write refs whose SOURCE operand text is identical -- i.e. the PROC computed one value and broadcast it to N SMC slots back-to-back. Catches the ComputeViewMatrix pattern (one matrix element computed, stored to 3 mirror sites: vertex projection / face renderer / AaBb cull) without the agent having to scan source for triple-stores. Groups are ordered by the lowest source line in the group."),
		mcp.WithString("proc", mcp.Required(),
			mcp.Description("Writer PROC name (or '<basename>:module-scope' for module-scope writers)")),
		mcp.WithNumber("max_line_gap",
			mcp.Description("Max gap (in source lines) between consecutive writes to keep them in the same group. Default 5.")),
		mcp.WithNumber("min_size",
			mcp.Description("Minimum group size (default 2)")),
	), s.handleFindMirrorWrites)

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
	refs := s.Index().FindCallers(name, inProc)
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
	refs := idx.FindDataRefs(name, inProc)
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
	// Alias surface. Two flavours:
	//
	//   1. EQU-style aliases pointing at this name as their SMC anchor
	//      (e.g. SmcAnchor_a71f -> Var_a720). Always surfaced regardless
	//      of ref count -- multi-var anchors carry useful structure.
	//
	//   2. Same-address aliases: any other symbol declared at the same
	//      byte address as the queried one. This catches the byte-EQU /
	//      word-label overlap (Var_d5c8 vs VideoDetectResult) where the
	//      writes go through the wider symbol and don't surface under
	//      the narrower one. Surfaced only when the narrower name has
	//      ref_count == 0 and the wider sibling has refs of its own --
	//      we don't want to noise up every query that happens to share
	//      an address.
	aliasList := make([]map[string]any, 0)
	for _, a := range idx.FindEquAliasesOf(name) {
		slot, _ := index.ParseSmcEqu(a.Text)
		aliasList = append(aliasList, map[string]any{
			"name":   a.Name,
			"kind":   "smc_var",
			"file":   filepath.Base(a.File),
			"line":   a.Line,
			"size":   slot.Size,
			"offset": slot.Offset,
			"text":   a.Text,
		})
	}
	// Same-address aliases (strict equality on the queried name's address).
	if len(out) == 0 {
		myDecls := idx.FindSymbol(name)
		var myAddr uint32
		hasMyAddr := false
		for _, d := range myDecls {
			if d.HasAddr {
				myAddr = d.Addr
				hasMyAddr = true
				break
			}
		}
		if hasMyAddr {
			for _, sib := range idx.SymbolsCoveringRange(myAddr, myAddr+1) {
				if sib.Name == name {
					continue
				}
				sibRefs := idx.FindDataRefs(sib.Name, "")
				if len(sibRefs) == 0 {
					continue
				}
				aliasList = append(aliasList, map[string]any{
					"name":      sib.Name,
					"kind":      "same_addr",
					"file":      filepath.Base(sib.File),
					"line":      sib.Line,
					"addr":      fmt.Sprintf("0x%04x", sib.Addr),
					"sym_kind":  sib.Kind,
					"ref_count": len(sibRefs),
				})
			}
		}
	}
	if len(aliasList) > 0 {
		res["aliases"] = aliasList
		if len(out) == 0 {
			res["note"] = "no direct refs against this name -- writes/reads likely go through the listed aliases. Try smc_var_info(<alias>), find_data_refs(<alias>), or data_refs_at(<addr>, <size>) to union them."
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
	external, internal := idx.FindCallees(name)
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
				RefCount: len(idx.FindCallers(name, "")),
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

// handleDataRefsAt unions data refs from every symbol whose address
// falls inside [addr, addr+size). Resolves the byte-slot-inside-word case
// where a write to the wide alias is invisible under the narrow alias.
func (s *Server) handleDataRefsAt(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	addrStr, err := req.RequireString("addr")
	if err != nil {
		return errResult("missing 'addr': " + err.Error()), nil
	}
	addr, err := parseAddrArg(addrStr)
	if err != nil {
		return errResult(err.Error()), nil
	}
	size := uint32(req.GetFloat("size", 1))
	if size == 0 {
		size = 1
	}
	idx := s.Index()
	syms := idx.SymbolsCoveringRange(addr, addr+size)
	bySym := make([]map[string]any, 0, len(syms))
	totalRefs := 0
	totalByAccess := map[string]int{}
	for _, sym := range syms {
		refs := idx.FindDataRefs(sym.Name, "")
		entries := make([]map[string]any, 0, len(refs))
		byAccess := map[string]int{}
		for _, r := range refs {
			row := map[string]any{
				"file":    filepath.Base(r.File),
				"line":    r.Line,
				"kind":    r.Kind,
				"in_proc": r.EnclosingProc,
				"text":    r.Text,
			}
			if a := index.ClassifyAccess(r); a != "" {
				row["access"] = a
				byAccess[a]++
				totalByAccess[a]++
			}
			entries = append(entries, row)
		}
		bySym = append(bySym, map[string]any{
			"symbol":    sym.Name,
			"kind":      sym.Kind,
			"addr":      fmt.Sprintf("0x%04x", sym.Addr),
			"file":      filepath.Base(sym.File),
			"line":      sym.Line,
			"ref_count": len(entries),
			"by_access": byAccess,
			"refs":      entries,
		})
		totalRefs += len(entries)
	}
	res := map[string]any{
		"addr":       fmt.Sprintf("0x%04x", addr),
		"size":       size,
		"sym_count":  len(syms),
		"ref_count":  totalRefs,
		"by_access":  totalByAccess,
		"symbols":    bySym,
	}
	if len(syms) == 0 {
		res["note"] = "no symbols declared in this byte range -- check the addr or pass a wider size"
	}
	return jsonText(res), nil
}

// handleFindMirrorWrites scans a writer PROC's mem-write refs and groups
// consecutive runs whose source operand text is identical. Each group is
// the broadcast of a single computed value to multiple SMC slots --
// ComputeViewMatrix's 9-element-x-3-mirror pattern is the canonical case.
func (s *Server) handleFindMirrorWrites(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	proc, err := req.RequireString("proc")
	if err != nil {
		return errResult("missing 'proc': " + err.Error()), nil
	}
	maxGap := int(req.GetFloat("max_line_gap", 5))
	if maxGap < 0 {
		maxGap = 0
	}
	minSize := int(req.GetFloat("min_size", 2))
	if minSize < 2 {
		minSize = 2
	}
	idx := s.Index()
	groups := idx.FindMirrorWrites(proc, maxGap, minSize)
	out := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		writes := make([]map[string]any, 0, len(g.Writes))
		for _, w := range g.Writes {
			writes = append(writes, map[string]any{
				"file":   filepath.Base(w.File),
				"line":   w.Line,
				"target": w.Target,
				"text":   w.Text,
			})
		}
		out = append(out, map[string]any{
			"source":     g.Source,
			"size":       len(g.Writes),
			"line_start": g.LineStart,
			"line_end":   g.LineEnd,
			"writes":     writes,
		})
	}
	return jsonText(map[string]any{
		"proc":   proc,
		"groups": out,
		"count":  len(out),
	}), nil
}

// handleSmcClusters returns SMC anchors grouped either by spatial proximity
// or by shared writer/reader PROC. See Index.SmcClusters and
// Index.SmcClustersByProc for the two grouping heuristics.
func (s *Server) handleSmcClusters(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	by := strings.ToLower(req.GetString("by", "proximity"))
	procFilter := req.GetString("proc", "")
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

	switch by {
	case "writer_proc", "reader_proc", "writer", "reader",
		"writer_file", "reader_file":
		role := "writer"
		if by == "reader_proc" || by == "reader" || by == "reader_file" {
			role = "reader"
		}
		subMaxLineGap := int(req.GetFloat("sub_max_line_gap", 25))
		if subMaxLineGap < 0 {
			subMaxLineGap = 0
		}
		var procClusters []*index.SmcProcCluster
		switch by {
		case "writer_file", "reader_file":
			procClusters = idx.SmcClustersByFile(by, fileFilter, minSize, subMaxLineGap)
		default:
			procClusters = idx.SmcClustersByProc(by, procFilter, minSize, subMaxLineGap)
		}
		total := len(procClusters)
		if len(procClusters) > limit {
			procClusters = procClusters[:limit]
		}
		groupKey := "proc"
		if by == "writer_file" || by == "reader_file" {
			groupKey = "file"
		}
		out := make([]map[string]any, 0, len(procClusters))
		for _, c := range procClusters {
			vars := make([]map[string]any, 0, len(c.Vars))
			roleCounts := map[string]int{}
			for _, v := range c.Vars {
				hostRole := index.ClassifyHostRole(v.HostInstr)
				row := map[string]any{
					"var":              v.Var.Name,
					"anchor":           v.Anchor.Name,
					"addr":             fmt.Sprintf("0x%04x", v.Anchor.Addr),
					"line":             v.Anchor.Line,
					"file":             filepath.Base(v.Anchor.File),
					"slot":             map[string]any{"size": v.Slot.Size, "offset": v.Slot.Offset},
					"host_instruction": v.HostInstr,
				}
				if hostRole != "" {
					row["role"] = hostRole
					roleCounts[hostRole]++
				} else {
					roleCounts[""]++
				}
				vars = append(vars, row)
			}
			entry := map[string]any{
				groupKey:    c.Proc,
				"role":      c.Role,
				"var_count": len(c.Vars),
				"vars":      vars,
			}
			if len(roleCounts) > 0 {
				entry["role_counts"] = roleCounts
			}
			if len(c.SubClusters) > 0 {
				subs := make([]map[string]any, 0, len(c.SubClusters))
				for _, sc := range c.SubClusters {
					subVars := make([]map[string]any, 0, len(sc.Vars))
					subRoleCounts := map[string]int{}
					for _, v := range sc.Vars {
						hostRole := index.ClassifyHostRole(v.HostInstr)
						subRow := map[string]any{
							"var":    v.Var.Name,
							"anchor": v.Anchor.Name,
							"addr":   fmt.Sprintf("0x%04x", v.Anchor.Addr),
							"slot":   map[string]any{"size": v.Slot.Size, "offset": v.Slot.Offset},
						}
						if hostRole != "" {
							subRow["role"] = hostRole
							subRoleCounts[hostRole]++
						} else {
							subRoleCounts[""]++
						}
						subVars = append(subVars, subRow)
					}
					subEntry := map[string]any{
						"line_start": sc.LineStart,
						"line_end":   sc.LineEnd,
						"var_count":  len(sc.Vars),
						"vars":       subVars,
					}
					if len(subRoleCounts) > 0 {
						subEntry["role_counts"] = subRoleCounts
					}
					subs = append(subs, subEntry)
				}
				entry["sub_clusters"] = subs
				entry["sub_cluster_count"] = len(subs)
			}
			out = append(out, entry)
		}
		return jsonText(map[string]any{
			"by":       by,
			"role":     role,
			"total":    total,
			"shown":    len(out),
			"min_size": minSize,
			"clusters": out,
		}), nil
	}

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
		roleCounts := map[string]int{}
		for _, a := range c.Anchors {
			hostRole := index.ClassifyHostRole(a.HostInstr)
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
			if hostRole != "" {
				row["role"] = hostRole
				roleCounts[hostRole]++
			} else {
				roleCounts[""]++
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
		if len(roleCounts) > 0 {
			entry["role_counts"] = roleCounts
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

	slotEntry := map[string]any{
		"size":   slot.Size,
		"offset": slot.Offset,
	}
	// Sibling-overlap detection: when more than one Var_* aliases the
	// same SmcAnchor, vars whose byte ranges overlap are byte-slice
	// views of each other. The agent's round-4 idea: surface the
	// relationship so high-byte-of / low-byte-of patterns are
	// self-documenting (Var_ae68 word at +1, Var_ae69 byte at +2 →
	// Var_ae69 is the high byte of Var_ae68).
	rels := make([]map[string]any, 0)
	for _, r := range idx.SiblingSlotRelations(varDecl.Name, anchor.Name, slot) {
		rels = append(rels, map[string]any{
			"kind":    r.Kind,
			"sibling": r.Sibling,
			"sibling_slot": map[string]any{
				"size":   r.SiblingSlot.Size,
				"offset": r.SiblingSlot.Offset,
			},
		})
	}
	if kind, sibling := idx.CarryChainPair(anchor); kind != "" {
		rels = append(rels, map[string]any{
			"kind":    kind,
			"sibling": sibling,
		})
	}
	if len(rels) > 0 {
		slotEntry["relations"] = rels
	}
	// Self-storing list-head pattern: anchor is `mov reg, imm` and a
	// writer writes the same `reg` back into the slot. Surface so the
	// agent recognises the WalkListAndCullAaBb-style pattern at a glance.
	if reg, writes := idx.SelfStoringWrites(varDecl.Name, anchor); reg != "" {
		entries := make([]map[string]any, 0, len(writes))
		for _, w := range writes {
			entries = append(entries, map[string]any{
				"file":    filepath.Base(w.File),
				"line":    w.Line,
				"in_proc": w.EnclosingProc,
				"text":    w.Text,
			})
		}
		slotEntry["self_storing"] = map[string]any{
			"register": reg,
			"writes":   entries,
			"count":    len(entries),
		}
	}
	res := map[string]any{
		"var":    varDecl.Name,
		"anchor": anchor.Name,
		"slot":   slotEntry,
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
	// Multi-instruction host walk. When a listing is loaded, walk the
	// instruction stream from the anchor's address through the byte that
	// contains the slot. The slot may land inside the *second* or *third*
	// instruction (Var_d2a7 case: anchor at d2a0, sub is 5 bytes, the +7
	// slot is in the cmp at d2a5). We surface the whole run so the agent
	// sees the patched-by-which-instruction without re-reading the source.
	if anchor.HasAddr {
		slotAddr := anchor.Addr + uint32(slot.Offset)
		end := slotAddr + 1
		switch slot.Size {
		case "word":
			end = slotAddr + 2
		case "dword":
			end = slotAddr + 4
		}
		if instrs := idx.InstructionsCovering(anchor.Addr, end); len(instrs) > 0 {
			arr := make([]map[string]any, 0, len(instrs))
			var hostText, hostBytes, hostRole string
			var hostAddr uint32
			var hostSize uint32
			for _, ins := range instrs {
				row := map[string]any{
					"addr":     fmt.Sprintf("0x%04x", ins.Addr),
					"size":     ins.Size,
					"encoding": ins.Bytes,
					"text":     ins.Text,
				}
				if slotAddr >= ins.Addr && slotAddr < ins.Addr+ins.Size {
					row["contains_slot"] = true
					row["slot_byte_offset_in_instr"] = int(slotAddr - ins.Addr)
					if role := index.ClassifyHostRole(ins.Text); role != "" {
						row["role"] = role
						hostRole = role
					}
					hostText = ins.Text
					hostBytes = ins.Bytes
					hostAddr = ins.Addr
					hostSize = ins.Size
				}
				arr = append(arr, row)
			}
			res["host_instructions"] = arr
			// Backwards-compat singular: prefer the slot-containing one.
			if hostText != "" {
				host := map[string]any{
					"addr":     fmt.Sprintf("0x%04x", hostAddr),
					"size":     hostSize,
					"encoding": hostBytes,
					"text":     hostText,
				}
				if hostRole != "" {
					host["role"] = hostRole
				}
				res["host_instruction"] = host
			}
		}
	}
	// Source-level fallback (or supplement when the listing isn't loaded):
	// the anchor's source line. Always set as `host_instruction_source`
	// so callers that previously read host_instruction.text for *anchor*
	// (not slot) text still have access to it.
	if instr := idx.HostInstruction(anchor); instr != "" {
		srcEntry := map[string]any{
			"file": filepath.Base(anchor.File),
			"line": anchor.Line,
			"text": instr,
		}
		if role := index.ClassifyHostRole(instr); role != "" {
			srcEntry["role"] = role
		}
		res["host_instruction_source"] = srcEntry
		// If the listing wasn't available we never set host_instruction;
		// fall back to the source line so the field is never missing.
		if _, ok := res["host_instruction"]; !ok {
			res["host_instruction"] = srcEntry
		}
	}

	// Writer/reader split. Memory-operand refs against the var alias are
	// the patches; reads through the anchor itself are implicit (the
	// runtime reads the patched immediate every time the host instruction
	// executes), so we only surface mem-operand refs here.
	refs := idx.FindDataRefs(varDecl.Name, "")
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
