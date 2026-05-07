package main

import (
	"os"

	"github.com/hrntknr/sbx/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
