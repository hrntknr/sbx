//go:build linux

package main

import (
	"fmt"
	"strings"

	"github.com/hrntknr/sbx/internal/bubblewrap"
	"github.com/hrntknr/sbx/internal/config"
)

func run(rules []config.Rule, expand func(string) string, env []string, dump bool, args []string) (int, error) {
	bargs, err := bubblewrap.Build(rules, expand)
	if err != nil {
		return 0, err
	}
	if dump {
		fmt.Println(strings.Join(append([]string{"bwrap"}, bargs...), " "))
		return 0, nil
	}
	return bubblewrap.Run(bargs, args, env)
}
