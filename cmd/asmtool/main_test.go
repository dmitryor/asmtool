package main

import "testing"

func TestRenameDefaultsToPreview(t *testing.T) {
	got, err := parseCommand("rename", []string{"Old", "New"})
	if err != nil {
		t.Fatal(err)
	}
	if dryRun, ok := got.args["dry_run"].(bool); !ok || !dryRun {
		t.Fatalf("dry_run = %#v, want true", got.args["dry_run"])
	}
}

func TestRenameApplyIsExplicit(t *testing.T) {
	got, err := parseCommand("rename", []string{"--apply", "Old", "New"})
	if err != nil {
		t.Fatal(err)
	}
	if dryRun, ok := got.args["dry_run"].(bool); !ok || dryRun {
		t.Fatalf("dry_run = %#v, want false", got.args["dry_run"])
	}
}

func TestSmcClusterFlagUsesInternalSpelling(t *testing.T) {
	got, err := parseCommand("smc-clusters", []string{"--by", "writer-proc"})
	if err != nil {
		t.Fatal(err)
	}
	if got.args["by"] != "writer_proc" {
		t.Fatalf("by = %#v, want writer_proc", got.args["by"])
	}
}
