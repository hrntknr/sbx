package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hrntknr/sbx/internal/config"
)

func main() {
	var configPath string
	var profile string
	var dump bool
	flag.StringVar(&configPath, "c", "", "config file path (default: ./sbx.yaml or ~/.sbx.yaml)")
	flag.StringVar(&profile, "profile", "", "profile name (default: default)")
	flag.BoolVar(&dump, "dump", false, "print the generated sandbox spec and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: sbx [-c config] [--profile profile] [-dump] <command> [args...]")
	}
	flag.Parse()
	args := flag.Args()
	var err error
	args, profile, err = commandProfile(args, profile)
	if err != nil {
		fail(err)
	}

	if !dump && len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	rules, err := config.LoadProfile(configPath, profile)
	if err != nil {
		fail(err)
	}
	expand := config.Expander()
	run(rules, expand, dump, args)
}

func commandProfile(args []string, profile string) ([]string, string, error) {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--sbx-profile":
			if i+1 >= len(args) {
				return nil, "", fmt.Errorf("--sbx-profile requires a value")
			}
			profile = args[i+1]
			i++
		case strings.HasPrefix(arg, "--sbx-profile="):
			profile = strings.TrimPrefix(arg, "--sbx-profile=")
		default:
			out = append(out, arg)
		}
	}
	return out, profile, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sbx:", err)
	os.Exit(1)
}
