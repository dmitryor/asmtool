package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Root        string   `toml:"root"`
	SourcePaths []string `toml:"source_paths"`
	DocPaths    []string `toml:"doc_paths"`
	Jwasm       string   `toml:"jwasm"`
	Verify      string   `toml:"verify"`
	CacheDir    string   `toml:"cache_dir"`
	ProjectRoot string   `toml:"-"`
}

func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if _, err := toml.DecodeFile(abs, c); err != nil {
		return nil, fmt.Errorf("read %s: %w", abs, err)
	}
	c.ProjectRoot = filepath.Dir(abs)
	if c.Jwasm == "" {
		c.Jwasm = "jwasm"
	}
	if c.CacheDir == "" {
		c.CacheDir = ".jwasm-mcp-cache"
	}
	if !filepath.IsAbs(c.CacheDir) {
		c.CacheDir = filepath.Join(c.ProjectRoot, c.CacheDir)
	}
	if err := os.MkdirAll(c.CacheDir, 0o755); err != nil {
		return nil, err
	}
	if c.Root == "" {
		return nil, fmt.Errorf("config missing 'root' (path to master .asm file)")
	}
	if !filepath.IsAbs(c.Root) {
		c.Root = filepath.Join(c.ProjectRoot, c.Root)
	}
	for i, p := range c.SourcePaths {
		if !filepath.IsAbs(p) {
			c.SourcePaths[i] = filepath.Join(c.ProjectRoot, p)
		}
	}
	for i, p := range c.DocPaths {
		if !filepath.IsAbs(p) {
			c.DocPaths[i] = filepath.Join(c.ProjectRoot, p)
		}
	}
	return c, nil
}
