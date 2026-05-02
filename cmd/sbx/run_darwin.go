//go:build darwin

package main

import (
	"fmt"

	"github.com/hrntknr/sbx/internal/config"
	"github.com/hrntknr/sbx/internal/seatbelt"
)

func run(rules []config.Rule, expand func(string) string, env []string, dump bool, args []string) (int, error) {
	profile, err := seatbelt.Build(rules, expand)
	if err != nil {
		return 0, err
	}
	if dump {
		fmt.Print(profile)
		return 0, nil
	}
	return seatbelt.Run(profile, args, env)
}
