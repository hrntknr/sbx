//go:build !darwin && !linux

package main

import (
	"fmt"
	"os"

	"github.com/hrntknr/sbx/internal/config"
)

func run(_ []config.Rule, _ func(string) string, _ bool, _ []string) {
	fmt.Fprintln(os.Stderr, "sbx: only darwin and linux are supported")
	os.Exit(1)
}
