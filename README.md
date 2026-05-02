# jwasm-mcp

MCP server that gives an LLM agent fast, structural access to a JWasm/MASM
assembly project — symbol resolution, PROC navigation, address↔source
mapping, and relocation-blocker scanning.

Designed for projects where the agent works in a tree of `.inc` files included
into a single master `.asm` file (the JWasm INCLUDE-concatenation pattern,
common in DOS-era reverse-engineering reconstructions).

## Configuration

Each project carries a `.jwasm-mcp.toml`:

```toml
root          = "src/retal.asm"
source_paths  = ["src"]
doc_paths     = ["doc"]
jwasm         = "jwasm"
verify        = "python3 src/verify_modules.py"
cache_dir     = ".jwasm-mcp-cache"
```

The server watches `source_paths` and `doc_paths`; any `.inc/.asm/.toml`
change triggers a debounced rebuild (jwasm + reparse + atomic index swap).

## Tools

Read-only navigation:

- `which_proc(file, line)` — enclosing PROC at a source location
- `read_proc(name)` — full PROC body with surrounding comments
- `find_callers(name, in_proc?)` — `call`/`jmp` references; scope-aware
  for `@@`-local labels (pass `in_proc` to narrow)
- `find_callees(name)` — outgoing call/jmp targets from a PROC
- `module_layout(file)` — PROCs in a module with addr/size info
- `addr_to_location(addr)` — map a CS offset to file:line + enclosing PROC.
  When the addr lands on an SMC anchor (or on one of its var-aliased
  patch slots) the response also surfaces the anchor name, host
  instruction, and slot info — a single round-trip for the agent's SMC
  worklist.
- `find_symbol(name)` — every declaration site of a name
- `data_refs_at(addr, size?)` — address-keyed counterpart to
  `find_data_refs`. Unions refs from every symbol declared in
  `[addr, addr+size)`. Closes the byte-EQU / word-label overlap case
  where writes go through the wider alias and don't surface under the
  narrow one.

Composite:

- `function_context(name)` — body + callers (with surrounding lines) +
  callees + sibling PROCs + locals; the goal-2 naming-decision tool
- `smc_var_info(name)` — SMC slot resolver: takes either a `Var_NNNN` EQU
  alias or its `SmcAnchor_NNNN` host label and returns the typed slot
  (size + offset, plus `relations` linking sibling vars whose byte
  ranges overlap — e.g. `byte_slice_of: Var_ae68` for a high-byte
  view), the anchor address, every instruction from the anchor through
  the slot byte (with byte encoding, a `contains_slot` marker, and a
  coarse `role` tag on the patched one — `value_load_imm`, `threshold`,
  `delta`, `deferred_write`, `mask`, `shift`, `interrupt_vector`,
  `data_filler`, `jump_target`, `stack_anchor`; encoding-macros like
  `cmp_ax_imm16_long` are classified by their underscore prefix), and a
  writer/reader split (memory-operand refs classified by access).
- `smc_clusters(by?, proc?, file?, max_gap?, min_size?)` — group SMC
  anchors. Three modes:
  - `by="proximity"` (default): same source file + addr gap ≤
    `max_gap`. Catches consecutive-immediate runs.
  - `by="writer_proc"` / `by="reader_proc"`: vars touched by the
    same PROC. Catches matrix-broadcast patterns (4-8 SMC slots
    written by one PROC, read by another, even when they span
    ~150 source lines). Module-scope refs surface under the
    synthetic key `<basename>:module-scope`.
  - `by="writer_file"` / `by="reader_file"`: coarser, file-keyed
    grouping. Right shape for module-scope setup blocks (e.g.
    polydraw.inc's 18 SMC slots all written at file scope without
    a PROC wrapper).
- `unresolved(kind, limit)` — scaffolding backlog ranked by reference count;
  `kind` ∈ `procs` (default), `data`, `all`

Goal-1 / movability:

- `scan_relocation_blockers(file?, confidence?)` — confidence-tagged
  candidates (`definite`, `probable`, `ambiguous`)

Write tool:

- `rename_symbol(old, new, in_proc?, dry_run?, include_docs?, allow_locals_across_procs?)` —
  scope-aware atomic rewrite. Word-boundary matching, refuses on
  collision, defaults to `dry_run=true`. Refuses to rename a PROC-local
  name without `in_proc` unless `allow_locals_across_procs` is set
  (common locals like `Done`/`Loop`/`Ret` appear in many PROCs).

## Workflows

### Name an unresolved scaffolding PROC

```
1. unresolved(kind="procs")              → pick highest-ref entry
2. function_context(name)                → body + callers + callees in 1 call
3. propose a semantic name
4. rename_symbol(old, new, dry_run=true) → review the edit list
5. rename_symbol(old, new, dry_run=false) → apply (sync rebuild)
```

### Name an unresolved data EQU / scaffolding label

```
1. unresolved(kind="data")               → pick highest-ref entry
2. find_data_refs(name)                  → see access patterns by kind/access
3. for each reader PROC: function_context(reader_proc) → context
4. propose a semantic name
5. rename_symbol(old, new, dry_run=true / false)
```

### Annotate a self-modifying-code variable

```
1. unresolved(kind="data")               → pick a Var_NNNN entry
2. smc_var_info(Var_NNNN)                → slot + anchor + host instr +
                                           writers/readers in one call
3. propose a semantic name (often based on what the writers compute)
4. rename_symbol(old, new, dry_run=true / false)
```

### Annotate a cluster of SMC anchors at once

```
1. smc_clusters()                        → groups of anchors patched together
2. function_context(<writer_proc>)       → see what the writer is computing
3. name the cluster's purpose, then    → anchors share the same role
   rename each Var_NNNN inside it.
```

For an arbitrary CSEG offset (e.g. from a Ghidra cross-reference):

```
1. addr_to_location(0xa720)              → file:line + PROC; if the addr
                                           is an SMC slot, the response
                                           also includes anchor name,
                                           host instruction, and slot info
```

### Map a Ghidra address to source

```
1. addr_to_location("0xa17c")            → PROC + offset
2. read_proc(proc_name)                  → full body
```

### Audit movability (relocation blockers)

```
1. scan_relocation_blockers()            → confidence-tagged list
2. review `definite` first; `probable` and `ambiguous` need eyeballs
```

Empty results in this codebase mean the corpus is already movable -- not a bug.

### Renaming a `@@`-local label safely

```
1. find_symbol(name)                     → see every PROC declaring it
2. rename_symbol(old, new,
       in_proc=<the_one_proc>,
       dry_run=true)                     → preview
```

Without `in_proc`, the tool refuses any local rename that would touch >1 PROC,
unless `allow_locals_across_procs=true` is passed explicitly.
