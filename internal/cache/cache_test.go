package cache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dmitryor/asmtool/internal/config"
)

func TestFingerprintTracksSourceContent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".asmtool.toml")
	sourcePath := filepath.Join(dir, "main.asm")
	if err := os.WriteFile(configPath, []byte("root = \"main.asm\"\nsource_paths = [\".\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("Start:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Path: configPath, Root: sourcePath, SourcePaths: []string{dir}, Jwasm: executable,
	}
	first, err := fingerprint(cfg, []string{sourcePath})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("Other:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := fingerprint(cfg, []string{sourcePath})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("source content change did not change fingerprint")
	}
	if err := os.WriteFile(sourcePath, []byte("Start:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	third, err := fingerprint(cfg, []string{sourcePath})
	if err != nil {
		t.Fatal(err)
	}
	if first != third {
		t.Fatal("restoring source content did not restore fingerprint")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json.gz")
	want := &Snapshot{Schema: Schema, Fingerprint: "abc"}
	if err := save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := load(path, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != want.Schema || got.Fingerprint != want.Fingerprint {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	if _, err := load(path, "different"); err == nil {
		t.Fatal("load accepted a mismatched fingerprint")
	}
}
