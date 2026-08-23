// Command asmtool provides structural navigation and safe refactoring for
// JWasm/MASM source trees.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dmitryor/asmtool/internal/cache"
	"github.com/dmitryor/asmtool/internal/config"
	query "github.com/dmitryor/asmtool/internal/tool"
)

const version = "0.1.0"

type command struct {
	tool string
	args map[string]any
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "asmtool:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, argv []string) error {
	global := flag.NewFlagSet("asmtool", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	configPath := global.String("config", "", "project config (default: discover .asmtool.toml)")
	forceIndex := global.Bool("reindex", false, "rebuild the cached index before running")
	global.Usage = usage
	if err := global.Parse(argv); err != nil {
		return err
	}
	args := global.Args()
	if len(args) == 0 {
		usage()
		return errors.New("missing command")
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		usage()
		return nil
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Println(version)
		return nil
	}

	path, err := findConfig(*configPath)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	cached, err := cache.Open(cfg, *forceIndex || args[0] == "index")
	if err != nil {
		return fmt.Errorf("index: %w", err)
	}
	if cached.Run.Err != nil {
		fmt.Fprintf(os.Stderr, "asmtool: warning: JWasm failed; address data is unavailable: %v\n%s",
			cached.Run.Err, cached.Run.Stderr)
	}
	if args[0] == "index" {
		return printJSON(map[string]any{
			"fingerprint": cached.Fingerprint,
			"cache_hit":   cached.Hit,
			"files":       cached.NumFiles,
			"snapshot":    cached.Snapshot,
			"listing":     cached.Listing,
		})
	}

	engine := query.New(cfg, cached.Index)
	engine.SetRebuild(func() error {
		fresh, err := cache.Open(cfg, true)
		if err == nil {
			engine.SetIndex(fresh.Index)
		}
		return err
	})
	if args[0] == "rename-batch" {
		return runRenameBatch(ctx, engine, args[1:])
	}
	call, err := parseCommand(args[0], args[1:])
	if err != nil {
		return err
	}
	out, err := engine.Invoke(ctx, call.tool, call.args)
	if err != nil {
		return err
	}
	return printJSON(out)
}

func findConfig(explicit string) (string, error) {
	if explicit == "" {
		explicit = os.Getenv("ASMTOOL_CONFIG")
	}
	if explicit != "" {
		return explicit, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		path := filepath.Join(dir, ".asmtool.toml")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("no .asmtool.toml found in this directory or its parents; pass --config")
}

func parseCommand(name string, argv []string) (command, error) {
	switch name {
	case "which-proc":
		if len(argv) != 2 {
			return command{}, usageError(name, "FILE LINE")
		}
		line, err := strconv.Atoi(argv[1])
		if err != nil || line < 1 {
			return command{}, errors.New("which-proc: LINE must be a positive integer")
		}
		return call("which_proc", "file", argv[0], "line", float64(line)), nil
	case "read-proc":
		return oneArg(name, "NAME", "read_proc", "name", argv)
	case "callers":
		fs, inProc := newFlags(name), ""
		fs.StringVar(&inProc, "in-proc", "", "limit local references to PROC")
		if err := fs.Parse(argv); err != nil {
			return command{}, err
		}
		if fs.NArg() != 1 {
			return command{}, usageError(name, "[--in-proc PROC] NAME")
		}
		return call("find_callers", "name", fs.Arg(0), "in_proc", inProc), nil
	case "data-refs":
		fs, inProc := newFlags(name), ""
		fs.StringVar(&inProc, "in-proc", "", "limit local references to PROC")
		if err := fs.Parse(argv); err != nil {
			return command{}, err
		}
		if fs.NArg() != 1 {
			return command{}, usageError(name, "[--in-proc PROC] NAME")
		}
		return call("find_data_refs", "name", fs.Arg(0), "in_proc", inProc), nil
	case "callees":
		return oneArg(name, "NAME", "find_callees", "name", argv)
	case "module":
		return oneArg(name, "FILE", "module_layout", "file", argv)
	case "address":
		return oneArg(name, "ADDR", "addr_to_location", "addr", argv)
	case "symbol":
		return oneArg(name, "NAME", "find_symbol", "name", argv)
	case "context":
		fs := newFlags(name)
		lines := fs.Int("caller-lines", 5, "surrounding lines per caller")
		if err := fs.Parse(argv); err != nil {
			return command{}, err
		}
		if fs.NArg() != 1 {
			return command{}, usageError(name, "[--caller-lines N] NAME")
		}
		return call("function_context", "name", fs.Arg(0), "caller_context_lines", float64(*lines)), nil
	case "rename":
		fs := newFlags(name)
		apply := fs.Bool("apply", false, "write edits (preview is the default)")
		docs := fs.Bool("docs", false, "also rename in configured Markdown docs")
		inProc := fs.String("in-proc", "", "scope a local rename to PROC")
		allLocals := fs.Bool("all-locals", false, "allow a local rename across PROCs")
		if err := fs.Parse(argv); err != nil {
			return command{}, err
		}
		if fs.NArg() != 2 {
			return command{}, usageError(name, "[OPTIONS] OLD NEW")
		}
		return call("rename_symbol",
			"old", fs.Arg(0), "new", fs.Arg(1), "dry_run", !*apply,
			"include_docs", *docs, "in_proc", *inProc,
			"allow_locals_across_procs", *allLocals), nil
	case "blockers":
		fs := newFlags(name)
		file := fs.String("file", "", "limit to a source file")
		confidence := fs.String("confidence", "", "definite, probable, or ambiguous")
		limit := fs.Int("limit", 200, "maximum results")
		if err := fs.Parse(argv); err != nil {
			return command{}, err
		}
		if fs.NArg() != 0 {
			return command{}, usageError(name, "[OPTIONS]")
		}
		return call("scan_relocation_blockers", "file", *file, "confidence", *confidence, "limit", float64(*limit)), nil
	case "data-refs-at":
		fs := newFlags(name)
		size := fs.Int("size", 1, "byte range size")
		if err := fs.Parse(argv); err != nil {
			return command{}, err
		}
		if fs.NArg() != 1 {
			return command{}, usageError(name, "[--size N] ADDR")
		}
		return call("data_refs_at", "addr", fs.Arg(0), "size", float64(*size)), nil
	case "smc-clusters":
		fs := newFlags(name)
		by := fs.String("by", "proximity", "proximity, writer-proc, reader-proc, writer-file, or reader-file")
		proc := fs.String("proc", "", "filter by PROC")
		file := fs.String("file", "", "filter by file")
		maxGap := fs.Int("max-gap", 16, "maximum address gap")
		minSize := fs.Int("min-size", 2, "minimum cluster size")
		limit := fs.Int("limit", 50, "maximum clusters")
		subGap := fs.Int("sub-line-gap", 25, "writer/reader subcluster line gap")
		if err := fs.Parse(argv); err != nil {
			return command{}, err
		}
		if fs.NArg() != 0 {
			return command{}, usageError(name, "[OPTIONS]")
		}
		return call("smc_clusters",
			"by", strings.ReplaceAll(*by, "-", "_"), "proc", *proc, "file", *file,
			"max_gap", float64(*maxGap), "min_size", float64(*minSize),
			"limit", float64(*limit), "sub_max_line_gap", float64(*subGap)), nil
	case "mirror-writes":
		fs := newFlags(name)
		maxGap := fs.Int("max-line-gap", 5, "maximum source-line gap")
		minSize := fs.Int("min-size", 2, "minimum group size")
		if err := fs.Parse(argv); err != nil {
			return command{}, err
		}
		if fs.NArg() != 1 {
			return command{}, usageError(name, "[OPTIONS] PROC")
		}
		return call("find_mirror_writes", "proc", fs.Arg(0), "max_line_gap", float64(*maxGap), "min_size", float64(*minSize)), nil
	case "smc-var":
		return oneArg(name, "NAME", "smc_var_info", "name", argv)
	case "unresolved":
		fs := newFlags(name)
		kind := fs.String("kind", "procs", "procs, data, or all")
		limit := fs.Int("limit", 50, "maximum results")
		if err := fs.Parse(argv); err != nil {
			return command{}, err
		}
		if fs.NArg() != 0 {
			return command{}, usageError(name, "[OPTIONS]")
		}
		return call("unresolved", "kind", *kind, "limit", float64(*limit)), nil
	default:
		return command{}, fmt.Errorf("unknown command %q; run 'asmtool help'", name)
	}
}

func runRenameBatch(ctx context.Context, engine *query.Tool, argv []string) error {
	fs := newFlags("rename-batch")
	apply := fs.Bool("apply", false, "write edits (preview is the default)")
	docs := fs.Bool("docs", false, "also rename in configured Markdown docs")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("rename-batch", "[--apply] [--docs] FILE")
	}
	var decoder *json.Decoder
	var file *os.File
	if fs.Arg(0) == "-" {
		decoder = json.NewDecoder(os.Stdin)
	} else {
		var err error
		file, err = os.Open(fs.Arg(0))
		if err != nil {
			return err
		}
		defer file.Close()
		decoder = json.NewDecoder(file)
	}
	decoder.DisallowUnknownFields()
	var specs []query.RenameSpec
	if err := decoder.Decode(&specs); err != nil {
		return fmt.Errorf("decode rename batch: %w", err)
	}
	out, err := engine.RenameBatch(ctx, specs, *apply, *docs)
	if err != nil {
		return err
	}
	return printJSON(out)
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func oneArg(commandName, synopsis, tool, key string, argv []string) (command, error) {
	if len(argv) != 1 {
		return command{}, usageError(commandName, synopsis)
	}
	return call(tool, key, argv[0]), nil
}

func call(tool string, pairs ...any) command {
	args := make(map[string]any, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		args[pairs[i].(string)] = pairs[i+1]
	}
	return command{tool: tool, args: args}
}

func usageError(command, synopsis string) error {
	return fmt.Errorf("usage: asmtool %s %s", command, synopsis)
}

func printJSON(value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage:
  asmtool [--config PATH] [--reindex] COMMAND [OPTIONS]

Commands:
  index                 Build or refresh the persistent index
  which-proc FILE LINE  Find the PROC containing a source line
  read-proc NAME        Read a complete PROC
  callers NAME          Find call and jump references
  data-refs NAME        Find non-control references
  callees NAME          Find outgoing calls and jumps
  module FILE           List a module's PROCs
  address ADDR          Map a CS offset to source
  symbol NAME           Find declarations
  context NAME          Gather naming context for a PROC
  rename OLD NEW        Preview or apply a safe symbol rename
  rename-batch FILE      Preview or apply independent JSON renames
  blockers              Scan for relocation blockers
  data-refs-at ADDR     Find references through address aliases
  smc-clusters          Group self-modifying-code slots
  mirror-writes PROC    Find repeated writes from one value
  smc-var NAME          Explain an SMC variable
  unresolved            List scaffolding names
  version               Print the version

Configuration is discovered from .asmtool.toml in the current directory or
its parents. Query results are emitted as JSON; diagnostics go to stderr.
`)
}
