package jwasm

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
)

type RunResult struct {
	ListingPath string
	ExePath     string
	Stdout      string
	Stderr      string
	Err         error
}

// Run invokes jwasm with -mz, listing, and binary output enabled.
// rootAsm is the path to the master .asm file. cacheDir is where
// the listing and executable are written. The cwd of the subprocess
// is set to the directory containing rootAsm so that relative INCLUDE
// directives resolve identically to a manual invocation.
func Run(jwasmBin, rootAsm, cacheDir string) RunResult {
	rootBase := filepath.Base(rootAsm)
	stem := rootBase[:len(rootBase)-len(filepath.Ext(rootBase))]
	lst := filepath.Join(cacheDir, stem+".lst")
	exe := filepath.Join(cacheDir, stem+".exe")
	return RunTo(jwasmBin, rootAsm, lst, exe)
}

// RunTo invokes JWasm and writes its listing and executable to explicit paths.
func RunTo(jwasmBin, rootAsm, lst, exe string) RunResult {
	rootDir := filepath.Dir(rootAsm)
	rootBase := filepath.Base(rootAsm)
	cmd := exec.Command(jwasmBin,
		"-mz", "-nologo",
		"-Fl="+lst,
		"-Fo="+exe,
		rootBase,
	)
	cmd.Dir = rootDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return RunResult{
		ListingPath: lst,
		ExePath:     exe,
		Stdout:      stdout.String(),
		Stderr:      stderr.String(),
		Err:         err,
	}
}

// FormatRunError gives a one-line human description of a failed run.
func FormatRunError(r RunResult) string {
	if r.Err == nil {
		return ""
	}
	return fmt.Sprintf("jwasm failed: %v\nstdout:\n%s\nstderr:\n%s", r.Err, r.Stdout, r.Stderr)
}
