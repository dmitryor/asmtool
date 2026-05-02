// Command jwasm-mcp is the MCP server entrypoint. It is launched by the
// agent's MCP client over stdio. Operation:
//
//  1. Read the project config (.jwasm-mcp.toml in cwd, or via -config).
//  2. Walk the configured source paths and parse every .inc/.asm file.
//  3. Run jwasm to produce a fresh listing; parse the symbol table.
//  4. Build the in-memory Index that ties source structure to addresses.
//  5. Serve MCP tools over stdio.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/server"

	"github.com/orlovsky/jwasm-mcp/internal/config"
	"github.com/orlovsky/jwasm-mcp/internal/index"
	"github.com/orlovsky/jwasm-mcp/internal/mcp"
	"github.com/orlovsky/jwasm-mcp/internal/watch"
)

func main() {
	cfgPath := flag.String("config", ".jwasm-mcp.toml", "path to project config")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}

	in := index.BuildInput{
		JwasmBin:    cfg.Jwasm,
		RootAsm:     cfg.Root,
		CacheDir:    cfg.CacheDir,
		SourcePaths: cfg.SourcePaths,
	}
	res := index.BuildFromInput(in)
	if res.Err != nil {
		fmt.Fprintln(os.Stderr, "index build:", res.Err)
		os.Exit(1)
	}
	if res.Run.Err != nil {
		// Continue with declaration-only index if jwasm failed; the agent
		// gets useful navigation queries even without addresses.
		fmt.Fprintln(os.Stderr, "warn: jwasm run failed:",
			res.Run.Err, res.Run.Stderr)
	}

	srv := mcp.New(cfg, res.Index)
	mcpServer := srv.Build()

	fmt.Fprintf(os.Stderr,
		"jwasm-mcp ready  files=%d  procs=%d  symbols=%d  cache=%s\n",
		res.NumFiles,
		len(res.Index.Procs),
		len(res.Index.Symbols),
		filepath.Base(cfg.CacheDir),
	)

	// Rebuild logic shared by the watcher (async, debounced) and write
	// tools like rename_symbol (sync, blocks the caller until the index
	// reflects the new source). Serialised by `buildMu`: if a rebuild is
	// in flight when another request arrives, we mark dirty and re-fire
	// when the current one finishes.
	var (
		buildMu  sync.Mutex
		building bool
		dirty    bool
	)
	doRebuild := func() error {
		res := index.BuildFromInput(in)
		if res.Err != nil {
			return res.Err
		}
		if res.Run.Err != nil {
			fmt.Fprintln(os.Stderr, "rebuild jwasm warn:",
				res.Run.Err, res.Run.Stderr)
		}
		srv.SetIndex(res.Index)
		fmt.Fprintf(os.Stderr,
			"reindexed  files=%d  procs=%d  symbols=%d\n",
			res.NumFiles, len(res.Index.Procs), len(res.Index.Symbols))
		return nil
	}
	rebuildSync := func() error {
		// If another rebuild is in flight, mark dirty and wait for our turn.
		buildMu.Lock()
		for building {
			dirty = true
			buildMu.Unlock()
			time.Sleep(50 * time.Millisecond)
			buildMu.Lock()
		}
		building = true
		buildMu.Unlock()
		var firstErr error
		for {
			if err := doRebuild(); err != nil && firstErr == nil {
				firstErr = err
			}
			buildMu.Lock()
			if !dirty {
				building = false
				buildMu.Unlock()
				return firstErr
			}
			dirty = false
			buildMu.Unlock()
		}
	}
	rebuildAsync := func() {
		// fire-and-forget for the watcher; coalesced by the same flag set.
		go func() { _ = rebuildSync() }()
	}

	srv.SetRebuild(rebuildSync)

	roots := append([]string{}, cfg.SourcePaths...)
	roots = append(roots, cfg.DocPaths...)
	w, err := watch.Start(watch.Options{
		Roots:    roots,
		OnChange: rebuildAsync,
		Logf: func(format string, args ...any) {
			// quiet by default; uncomment for debugging
			// fmt.Fprintf(os.Stderr, "watch: "+format+"\n", args...)
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "watch start failed:", err)
	} else {
		defer w.Close()
	}

	if err := server.ServeStdio(mcpServer); err != nil {
		fmt.Fprintln(os.Stderr, "stdio:", err)
		os.Exit(1)
	}
}
