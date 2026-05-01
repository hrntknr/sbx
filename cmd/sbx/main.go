package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hrntknr/sbx/internal/config"
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
	run(rules, expand, dump, args)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sbx:", err)
	os.Exit(1)
}
