//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/hrntknr/sbx/internal/bubblewrap"
	"github.com/hrntknr/sbx/internal/config"
)

func run(rules []config.Rule, expand func(string) string, env []string, dump bool, args []string) {
	bargs, err := bubblewrap.Build(rules, expand)
	if err != nil {
		fail(err)
	}
	if dump {
		fmt.Println(strings.Join(append([]string{"bwrap"}, bargs...), " "))
		return
	}
	code, err := bubblewrap.Run(bargs, args, env)
	if err != nil {
		fail(err)
	}
	os.Exit(code)
}
