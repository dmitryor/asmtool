# asmtool

`asmtool` is a command-line structural browser and refactoring tool for
JWasm/MASM projects. It understands procedures, scoped `@@` labels, symbols,
references, source/address mappings, and self-modifying-code slots.

## Install

```sh
go install github.com/dmitryor/asmtool/cmd/asmtool@latest
```

Or from a clone of this repository:

```sh
go build -o asmtool ./cmd/asmtool
```

JWasm must be on `PATH`, or named in the project config. JWasm's include
search path is taken from the `INCLUDE` environment variable.

## Configure a project

Place `.asmtool.toml` at the project root. Paths in that file are relative
to the config file, not to a hardcoded machine directory.

```toml
root         = "src/main.asm"
source_paths = ["src"]
doc_paths    = ["doc"]
jwasm        = "jwasm"
cache_dir    = ".asmtool-cache"
```

The CLI discovers this file from the current directory or its parents.
`--config PATH` and `ASMTOOL_CONFIG` override discovery.

## Use

```sh
asmtool index
asmtool context DrawSprite
asmtool callers DrawLine
asmtool data-refs PlayerX
asmtool address 0xa17c
asmtool unresolved --kind data
asmtool rename OldName NewName
asmtool rename --apply OldName NewName
asmtool rename-batch renames.json
```

Run `asmtool help` for the full command list. Results are pretty-printed JSON
on stdout; diagnostics go to stderr. Rename previews are the default;
`--apply` is required to modify source.

Batch files are JSON arrays of independent renames:

```json
[
  {"old": "OldOne", "new": "NewOne"},
  {"old": "Done", "new": "Finished", "in_proc": "SomeProc"}
]
```

Preview with `asmtool rename-batch renames.json`; add `--apply` to write all
combined edits and rebuild the index once.

## Index cache

The cache is content-addressed under the configured `cache_dir`
(default `.asmtool-cache`):

```text
.asmtool-cache/
  manifest.json
  indexes/
    <fingerprint>.json.gz
  listings/
    <fingerprint>.lst
    <fingerprint>.exe
```

The fingerprint covers the config, configured `.asm`/`.inc` files, the JWasm
binary, and `INCLUDE`. Branch switches and dirty source edits therefore select
different snapshots; switching back reuses the earlier snapshot. The snapshot
stores its schema version internally. `asmtool index` or `--reindex` forces a
refresh.

## License

MIT. See [LICENSE](LICENSE).
