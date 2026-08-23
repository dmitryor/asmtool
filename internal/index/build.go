package index

import (
	"fmt"

	"github.com/dmitryor/asmtool/internal/jwasm"
	"github.com/dmitryor/asmtool/internal/source"
)

// BuildFromConfig is the orchestration entrypoint: it walks the configured
// source paths, parses every .inc/.asm file, runs jwasm to produce a fresh
// listing, parses the listing, and returns a populated Index.
//
// jwasmRun and listing are both optional -- pass empty/nil to skip address
// resolution (useful for offline tests or when jwasm isn't available). The
// resulting index will then have only declaration-site info, no addresses.
type BuildInput struct {
	JwasmBin    string
	RootAsm     string
	CacheDir    string
	SourcePaths []string
}

// BuildResult bundles the index with diagnostic output from the build.
type BuildResult struct {
	Index    *Index
	Listing  *jwasm.ListingFile
	Run      jwasm.RunResult
	NumFiles int
	Err      error
}

func BuildFromInput(in BuildInput) BuildResult {
	res := BuildResult{}
	files, err := ResolveSourceFiles(in.SourcePaths)
	if err != nil {
		res.Err = fmt.Errorf("walk source: %w", err)
		return res
	}
	res.NumFiles = len(files)
	var parsed []*source.File
	for _, p := range files {
		f, err := source.ParseFile(p)
		if err != nil {
			res.Err = fmt.Errorf("parse %s: %w", p, err)
			return res
		}
		parsed = append(parsed, f)
	}

	if in.JwasmBin != "" && in.RootAsm != "" {
		run := jwasm.Run(in.JwasmBin, in.RootAsm, in.CacheDir)
		res.Run = run
		if run.Err == nil {
			lf, err := jwasm.ParseListing(run.ListingPath)
			if err != nil {
				res.Err = fmt.Errorf("parse listing: %w", err)
				return res
			}
			res.Listing = lf
		}
	}

	res.Index = Build(parsed, res.Listing)
	return res
}
