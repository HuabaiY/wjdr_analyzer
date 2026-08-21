//go:build !windows

package main

import "fmt"

func runDesktop(_ *Analyzer) error { return fmt.Errorf("桌面窗口当前仅支持 Windows") }
