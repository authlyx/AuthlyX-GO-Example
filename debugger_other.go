//go:build !windows

package main

import "os"

func checkDebugger() {
	debugVars := []string{"GOFLAGS", "GORACE"}
	for _, v := range debugVars {
		if os.Getenv(v) != "" {
			os.Exit(1)
		}
	}
}
