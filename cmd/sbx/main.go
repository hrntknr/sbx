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
	if args, err = commandOptions(args, flag.CommandLine); err != nil {
		fail(err)
	}

	if !dump && len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	selected, err := config.LoadSelectedProfile(configPath, profile)
	if err != nil {
		fail(err)
	}
	expand := config.Expander(selected.Env)
	env := config.EnvList(selected.Env, expand)
	run(selected.Rules, expand, env, dump, args)
}

func commandOptions(args []string, flags *flag.FlagSet) ([]string, error) {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--sbx-") {
			out = append(out, arg)
			continue
		}

		name, value, hasValue := strings.Cut(strings.TrimPrefix(arg, "--sbx-"), "=")
		if name == "" {
			return nil, fmt.Errorf("%s requires an option name", arg)
		}
		f := flags.Lookup(name)
		if f == nil {
			return nil, fmt.Errorf("unknown sbx option %q", name)
		}
		if !hasValue {
			if isBoolFlag(f.Value) {
				value = "true"
			} else {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("--sbx-%s requires a value", name)
				}
				value = args[i+1]
				i++
			}
		}
		if err := flags.Set(name, value); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func isBoolFlag(v flag.Value) bool {
	bv, ok := v.(interface {
		IsBoolFlag() bool
	})
	return ok && bv.IsBoolFlag()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sbx:", err)
	os.Exit(1)
}
