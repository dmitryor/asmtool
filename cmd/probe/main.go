package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/orlovsky/jwasm-mcp/internal/index"
	"github.com/orlovsky/jwasm-mcp/internal/source"
)

func main() {
	var (
		dir       = flag.String("dir", "", "directory containing .inc files")
		showSym   = flag.String("symbol", "", "show ref details for this symbol")
		fullIndex = flag.Bool("index", false, "build full index with jwasm and report")
		rootAsm   = flag.String("root", "", "master .asm file (for -index)")
		jwasmBin  = flag.String("jwasm", "jwasm", "jwasm binary")
	)
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: probe -dir <dir> [-symbol NAME] [-index -root retal.asm]")
		os.Exit(2)
	}
	if *fullIndex {
		runFullIndex(*dir, *rootAsm, *jwasmBin)
		return
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	totals := struct {
		Procs, Labels, Refs                       int
		Export, Global, Local, Data, Equ, Macro, P int
	}{}
	refsBySym := map[string]int{}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".inc" && ext != ".asm" {
			continue
		}
		f, err := source.ParseFile(filepath.Join(*dir, e.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", e.Name(), err)
			continue
		}
		totals.Procs += len(f.Procs)
		totals.Labels += len(f.Labels)
		totals.Refs += len(f.Refs)
		for _, l := range f.Labels {
			switch l.Kind {
			case source.LabelExport:
				totals.Export++
			case source.LabelGlobal:
				totals.Global++
			case source.LabelLocal:
				totals.Local++
			case source.LabelData:
				totals.Data++
			case source.LabelEqu:
				totals.Equ++
			case source.LabelMacro:
				totals.Macro++
			case source.LabelProc:
				totals.P++
			}
		}
		for _, r := range f.Refs {
			refsBySym[r.Target]++
		}
		if *showSym != "" {
			for _, r := range f.Refs {
				if r.Target == *showSym {
					fmt.Printf("  %s:%d  [%s] in=%s  %s\n",
						filepath.Base(r.File), r.Line, r.Kind.String(), r.EnclosingProc, r.Text)
				}
			}
		}
	}
	fmt.Printf("totals: procs=%d labels=%d refs=%d\n", totals.Procs, totals.Labels, totals.Refs)
	fmt.Printf("label kinds: PROC=%d export(::)=%d global=%d local(@@)=%d data=%d EQU=%d macro=%d\n",
		totals.P, totals.Export, totals.Global, totals.Local, totals.Data, totals.Equ, totals.Macro)

	type kv struct {
		k string
		v int
	}
	var ks []kv
	for k, v := range refsBySym {
		ks = append(ks, kv{k, v})
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].v > ks[j].v })
	fmt.Println("top 15 referenced symbols:")
	for i, p := range ks {
		if i >= 15 {
			break
		}
		fmt.Printf("  %5d  %s\n", p.v, p.k)
	}
}

func runFullIndex(dir, root, jwasmBin string) {
	in := index.BuildInput{
		JwasmBin:    jwasmBin,
		RootAsm:     root,
		CacheDir:    filepath.Join(os.TempDir(), "jwasm-mcp-probe"),
		SourcePaths: []string{dir},
	}
	if err := os.MkdirAll(in.CacheDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	res := index.BuildFromInput(in)
	if res.Err != nil {
		fmt.Fprintln(os.Stderr, res.Err)
		os.Exit(1)
	}
	if res.Run.Err != nil {
		fmt.Fprintln(os.Stderr, "jwasm warn:", res.Run.Err, res.Run.Stderr)
	}
	idx := res.Index
	listingSyms := 0
	if res.Listing != nil {
		listingSyms = len(res.Listing.Symbols)
	}
	fmt.Printf("files=%d  procs=%d  symbols(unique)=%d  refs(unique-targets)=%d  listing-syms=%d\n",
		res.NumFiles, len(idx.Procs), len(idx.Symbols), len(idx.Refs), listingSyms)

	procWith := 0
	for _, p := range idx.Procs {
		if p.HasAddr {
			procWith++
		}
	}
	fmt.Printf("PROCs with resolved addresses: %d / %d\n", procWith, len(idx.Procs))

	for _, name := range []string{"Main", "PlotPixel", "RasterizePolygonFill", "Blit"} {
		ent, ok := idx.Procs[name]
		if !ok {
			fmt.Printf("  %-30s NOT FOUND\n", name)
			continue
		}
		callers := idx.FindCallers(name)
		callees := idx.FindCallees(name)
		fmt.Printf("  %-30s addr=%04x file=%s lines=%d..%d callers=%d callees=%d\n",
			name, ent.Addr, filepath.Base(ent.File), ent.StartLine, ent.EndLine,
			len(callers), len(callees))
	}

	for _, addr := range []uint32{0x0000, 0x022e, 0xa17c, 0xb048} {
		p := idx.AddrToProc(addr)
		name := "(none)"
		if p != nil {
			name = p.Name
		}
		fmt.Printf("  addr 0x%04x -> %s\n", addr, name)
	}
}

var _ = source.Label{}
