//go:build darwin

package main

import (
	"fmt"
	"os"

	"github.com/hrntknr/sbx/internal/config"
	"github.com/hrntknr/sbx/internal/seatbelt"
)

func run(rules []config.Rule, expand func(string) string, dump bool, args []string) {
	profile, err := seatbelt.Build(rules, expand)
	if err != nil {
		fail(err)
	}
	if dump {
		fmt.Print(profile)
		return
	}
	code, err := seatbelt.Run(profile, args)
	if err != nil {
		fail(err)
	}
	os.Exit(code)
}
