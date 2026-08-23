// Package cache persists content-addressed parser/listing snapshots.
package cache

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/dmitryor/asmtool/internal/config"
	"github.com/dmitryor/asmtool/internal/index"
	"github.com/dmitryor/asmtool/internal/jwasm"
	"github.com/dmitryor/asmtool/internal/source"
)

const Schema = 1

type Snapshot struct {
	Schema      int                `json:"schema"`
	Fingerprint string             `json:"fingerprint"`
	Files       []*source.File     `json:"files"`
	Listing     *jwasm.ListingFile `json:"listing,omitempty"`
}

type Manifest struct {
	Schema      int       `json:"schema"`
	Fingerprint string    `json:"fingerprint"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Result struct {
	Index       *index.Index
	Fingerprint string
	Hit         bool
	NumFiles    int
	Run         jwasm.RunResult
	Snapshot    string
	Listing     string
}

func Open(cfg *config.Config, force bool) (Result, error) {
	paths, err := index.ResolveSourceFiles(cfg.SourcePaths)
	if err != nil {
		return Result{}, fmt.Errorf("walk source: %w", err)
	}
	fingerprint, err := fingerprint(cfg, paths)
	if err != nil {
		return Result{}, err
	}
	indexDir := filepath.Join(cfg.CacheDir, "indexes")
	listingDir := filepath.Join(cfg.CacheDir, "listings")
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(listingDir, 0o755); err != nil {
		return Result{}, err
	}
	snapshotPath := filepath.Join(indexDir, fingerprint+".json.gz")
	listingPath := filepath.Join(listingDir, fingerprint+".lst")
	exePath := filepath.Join(listingDir, fingerprint+".exe")
	if !force {
		if snap, err := load(snapshotPath, fingerprint); err == nil {
			manifest := Manifest{Schema: Schema, Fingerprint: fingerprint, UpdatedAt: time.Now().UTC()}
			if err := writeJSONAtomic(filepath.Join(cfg.CacheDir, "manifest.json"), manifest); err != nil {
				return Result{}, err
			}
			return Result{
				Index: index.Build(snap.Files, snap.Listing), Fingerprint: fingerprint,
				Hit: true, NumFiles: len(snap.Files), Snapshot: snapshotPath, Listing: listingPath,
			}, nil
		}
	}

	files := make([]*source.File, 0, len(paths))
	for _, path := range paths {
		f, err := source.ParseFile(path)
		if err != nil {
			return Result{}, fmt.Errorf("parse %s: %w", path, err)
		}
		files = append(files, f)
	}
	run := jwasm.RunTo(cfg.Jwasm, cfg.Root, listingPath, exePath)
	var listing *jwasm.ListingFile
	if run.Err == nil {
		listing, err = jwasm.ParseListing(listingPath)
		if err != nil {
			return Result{}, fmt.Errorf("parse listing: %w", err)
		}
	} else {
		return Result{
			Index: index.Build(files, nil), Fingerprint: fingerprint, NumFiles: len(files),
			Run: run, Snapshot: snapshotPath, Listing: listingPath,
		}, nil
	}
	snap := Snapshot{Schema: Schema, Fingerprint: fingerprint, Files: files, Listing: listing}
	if err := save(snapshotPath, &snap); err != nil {
		return Result{}, err
	}
	manifest := Manifest{Schema: Schema, Fingerprint: fingerprint, UpdatedAt: time.Now().UTC()}
	if err := writeJSONAtomic(filepath.Join(cfg.CacheDir, "manifest.json"), manifest); err != nil {
		return Result{}, err
	}
	return Result{
		Index: index.Build(files, listing), Fingerprint: fingerprint, NumFiles: len(files),
		Run: run, Snapshot: snapshotPath, Listing: listingPath,
	}, nil
}

func fingerprint(cfg *config.Config, paths []string) (string, error) {
	h := sha256.New()
	io.WriteString(h, fmt.Sprintf("asmtool-schema:%d\n", Schema))
	inputs := append([]string{cfg.Path, cfg.Root}, paths...)
	if bin, err := exec.LookPath(cfg.Jwasm); err == nil {
		inputs = append(inputs, bin)
	} else {
		io.WriteString(h, "jwasm:"+cfg.Jwasm+"\n")
	}
	sort.Strings(inputs)
	inputs = unique(inputs)
	for _, path := range inputs {
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return "", fmt.Errorf("fingerprint %s: %w", abs, err)
		}
		io.WriteString(h, abs)
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	io.WriteString(h, "INCLUDE="+os.Getenv("INCLUDE"))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func unique(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := items[:1]
	for _, item := range items[1:] {
		if item != out[len(out)-1] {
			out = append(out, item)
		}
	}
	return out
}

func load(path, fingerprint string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var snap Snapshot
	if err := json.NewDecoder(zr).Decode(&snap); err != nil {
		return nil, err
	}
	if snap.Schema != Schema || snap.Fingerprint != fingerprint {
		return nil, fmt.Errorf("incompatible snapshot")
	}
	return &snap, nil
}

func save(path string, snap *Snapshot) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".index-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	zw := gzip.NewWriter(tmp)
	err = json.NewEncoder(zw).Encode(snap)
	if closeErr := zw.Close(); err == nil {
		err = closeErr
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func writeJSONAtomic(path string, value any) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".manifest-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
