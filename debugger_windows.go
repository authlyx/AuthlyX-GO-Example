//go:build windows

package main

import (
	"os"
	"strings"
	"syscall"
)

func checkDebugger() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
	ret, _, _ := isDebuggerPresent.Call()
	if ret != 0 {
		os.Exit(1)
	}

	exactVars := []string{"GOFLAGS", "GORACE"}
	for _, v := range exactVars {
		if os.Getenv(v) != "" {
			os.Exit(1)
		}
	}

	dlvPrefixes := []string{"DLV_", "DELVE_"}
	for _, env := range os.Environ() {
		for _, prefix := range dlvPrefixes {
			if strings.HasPrefix(env, prefix) {
				os.Exit(1)
			}
		}
	}
}
