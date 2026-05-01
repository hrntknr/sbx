package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/hrntknr/sbx/internal/bubblewrap"
	"github.com/hrntknr/sbx/internal/config"
	"github.com/hrntknr/sbx/internal/seatbelt"
)

func main() {
	var configPath string
	var dump bool
	flag.StringVar(&configPath, "c", "", "config file path (default: ./sbx.yaml or ~/.sbx.yaml)")
	flag.BoolVar(&dump, "dump", false, "print the generated sandbox spec and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: sbx [-c config] [-dump] <command> [args...]")
	}
	flag.Parse()
	args := flag.Args()

	if !dump && len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	rules, err := config.Load(configPath)
	if err != nil {
		fail(err)
	}
	expand := config.Expander()

	switch runtime.GOOS {
	case "darwin":
		runDarwin(rules, expand, dump, args)
	case "linux":
		runLinux(rules, expand, dump, args)
	default:
		fmt.Fprintln(os.Stderr, "sbx: only darwin and linux are supported")
		os.Exit(1)
	}
}

func runDarwin(rules []config.Rule, expand func(string) string, dump bool, args []string) {
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

func runLinux(rules []config.Rule, expand func(string) string, dump bool, args []string) {
	bargs, err := bubblewrap.Build(rules, expand)
	if err != nil {
		fail(err)
	}
	if dump {
		fmt.Println(strings.Join(append([]string{"bwrap"}, bargs...), " "))
		return
	}
	code, err := bubblewrap.Run(bargs, args)
	if err != nil {
		fail(err)
	}
	os.Exit(code)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sbx:", err)
	os.Exit(1)
}
