//go:build !darwin && !linux

package cli

import (
	"fmt"

	"github.com/hrntknr/sbx/internal/config"
)

func run(_ []config.Rule, _ func(string) string, _ []string, _ bool, _ []string) (int, error) {
	return 0, fmt.Errorf("only darwin and linux are supported")
}
