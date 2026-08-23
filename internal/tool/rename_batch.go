package tool

import (
	"context"
	"fmt"

	"github.com/dmitryor/asmtool/internal/rename"
)

type RenameSpec struct {
	Old                    string `json:"old"`
	New                    string `json:"new"`
	InProc                 string `json:"in_proc,omitempty"`
	AllowLocalsAcrossProcs bool   `json:"allow_locals_across_procs,omitempty"`
}

type RenameBatchItem struct {
	Old          string        `json:"old"`
	New          string        `json:"new"`
	IsLocal      bool          `json:"is_local"`
	InProc       string        `json:"in_proc,omitempty"`
	FilesTouched int           `json:"files_touched"`
	EditCount    int           `json:"edit_count"`
	Edits        []rename.Edit `json:"edits,omitempty"`
}

// RenameBatch plans independent renames together and applies their combined
// edits with one final index rebuild.
func (s *Tool) RenameBatch(_ context.Context, specs []RenameSpec, apply, includeDocs bool) (any, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("rename batch is empty")
	}
	olds := map[string]bool{}
	news := map[string]bool{}
	for i, spec := range specs {
		if spec.Old == "" || spec.New == "" {
			return nil, fmt.Errorf("rename %d: old and new are required", i+1)
		}
		if olds[spec.Old] || news[spec.New] {
			return nil, fmt.Errorf("rename %d: duplicate old or new name", i+1)
		}
		olds[spec.Old], news[spec.New] = true, true
	}
	for name := range news {
		if olds[name] {
			return nil, fmt.Errorf("batch renames must be independent; %q is both an old and new name", name)
		}
	}

	plans := make([]*rename.Plan, 0, len(specs))
	items := make([]RenameBatchItem, 0, len(specs))
	for _, spec := range specs {
		plan, err := rename.PlanRename(s.Index(), spec.Old, spec.New, rename.Options{
			InProc:                 spec.InProc,
			IncludeDocs:            includeDocs,
			AllowLocalsAcrossProcs: spec.AllowLocalsAcrossProcs,
			DocPaths:               s.cfg.DocPaths,
		})
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
		item := RenameBatchItem{
			Old: plan.OldName, New: plan.NewName, IsLocal: plan.IsLocal,
			InProc: plan.InProc, FilesTouched: plan.FilesTouched, EditCount: len(plan.Edits),
		}
		if !apply {
			item.Edits = plan.Edits
		}
		items = append(items, item)
	}
	combined := rename.CombinePlans(plans...)
	if apply {
		if err := rename.Apply(combined); err != nil {
			return nil, fmt.Errorf("apply: %w", err)
		}
		fn := s.rebuildFn()
		if fn == nil {
			return nil, fmt.Errorf("apply succeeded but no index rebuild callback is configured")
		}
		if err := fn(); err != nil {
			return nil, fmt.Errorf("apply succeeded but index rebuild failed: %w", err)
		}
	}
	return map[string]any{
		"dry_run":             !apply,
		"rename_count":        len(items),
		"files_touched":       combined.FilesTouched,
		"edit_count":          len(combined.Edits),
		"index_fully_rebuilt": apply,
		"renames":             items,
	}, nil
}
