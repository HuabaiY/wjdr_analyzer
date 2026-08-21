package main

import (
	"os"
	"path/filepath"
	"testing"
)

func captureFixtureDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("WJDR_CAPTURE_FIXTURE")
	if dir == "" {
		t.Skip("set WJDR_CAPTURE_FIXTURE to run capture audit tests")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("resolve capture fixture: %v", err)
	}
	if _, err := os.Stat(filepath.Join(abs, "index.jsonl")); err != nil {
		t.Fatalf("capture fixture is invalid: %v", err)
	}
	return abs
}
