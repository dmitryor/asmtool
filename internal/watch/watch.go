// Package watch monitors source files for changes and triggers an index
// rebuild. The agent's "code in mind" experience depends on the index
// staying consistent with the source after any edit (whether the agent
// edited via rename_symbol or the user edited externally).
//
// Strategy: fsnotify watches every directory under source_paths. When a
// .inc/.asm file changes, we debounce for a short window (multiple writes
// often arrive in bursts -- editor saves, atomic-write renames, etc.)
// then trigger a full rebuild via the supplied callback. The callback is
// expected to atomically swap the index when done.
package watch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher monitors a set of source directories and reports relevant change
// events. It runs in its own goroutine; call Close to stop.
type Watcher struct {
	mu        sync.Mutex
	w         *fsnotify.Watcher
	debounce  time.Duration
	pending   bool
	timer     *time.Timer
	onChange  func()
	logf      func(format string, args ...any)
	closeChan chan struct{}
}

// Options for the watcher.
type Options struct {
	// Roots are the directories to watch (recursively).
	Roots []string
	// Debounce is how long to wait after a change before firing OnChange.
	// Multiple changes within this window are coalesced. Default 500ms.
	Debounce time.Duration
	// OnChange is called (in a separate goroutine) once per debounce window
	// when a relevant file change has occurred. Must be safe to call
	// concurrently with itself; the watcher serializes its invocations.
	OnChange func()
	// Logf, if non-nil, receives diagnostic messages.
	Logf func(format string, args ...any)
}

// Start begins watching the configured roots and returns a stoppable Watcher.
func Start(opts Options) (*Watcher, error) {
	if opts.OnChange == nil {
		return nil, fmt.Errorf("watch: OnChange must be set")
	}
	deb := opts.Debounce
	if deb <= 0 {
		deb = 500 * time.Millisecond
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		w:         fsw,
		debounce:  deb,
		onChange:  opts.OnChange,
		logf:      logf,
		closeChan: make(chan struct{}),
	}

	for _, root := range opts.Roots {
		if err := addRecursive(fsw, root); err != nil {
			fsw.Close()
			return nil, err
		}
	}

	go w.run()
	return w, nil
}

// addRecursive walks `root` and registers every directory with the
// fsnotify watcher. fsnotify on linux requires explicit per-directory
// watches; recursion is the caller's responsibility.
func addRecursive(fsw *fsnotify.Watcher, root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fsw.Add(path)
		}
		return nil
	})
}

func (w *Watcher) run() {
	for {
		select {
		case ev, ok := <-w.w.Events:
			if !ok {
				return
			}
			if !relevantEvent(ev) {
				continue
			}
			w.logf("watch: %s -> %s", ev.Op, ev.Name)
			w.scheduleFire()
		case err, ok := <-w.w.Errors:
			if !ok {
				return
			}
			w.logf("watch error: %v", err)
		case <-w.closeChan:
			return
		}
	}
}

// relevantEvent filters fsnotify events down to changes we care about:
// writes/creates/renames/removes on .inc, .asm, or .toml files.
func relevantEvent(ev fsnotify.Event) bool {
	if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
		return false
	}
	ext := strings.ToLower(filepath.Ext(ev.Name))
	switch ext {
	case ".inc", ".asm", ".toml":
		return true
	}
	return false
}

func (w *Watcher) scheduleFire() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timer != nil {
		w.timer.Stop()
	}
	w.timer = time.AfterFunc(w.debounce, func() {
		w.mu.Lock()
		w.pending = false
		w.mu.Unlock()
		w.onChange()
	})
	w.pending = true
}

// Close stops the watcher.
func (w *Watcher) Close() error {
	close(w.closeChan)
	w.mu.Lock()
	if w.timer != nil {
		w.timer.Stop()
	}
	w.mu.Unlock()
	return w.w.Close()
}
