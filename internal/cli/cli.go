package cli

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"

	"github.com/hrntknr/sbx/internal/config"
	"github.com/hrntknr/sbx/internal/k8s"
)

type opts struct {
	Config     string   `name:"config" short:"C" help:"config file path (default: ./sbx.yaml or ~/.sbx.yaml)" placeholder:"PATH"`
	Profile    string   `name:"profile" help:"profile name (default: default)" placeholder:"NAME"`
	CommandStr string   `name:"command" short:"c" help:"command string to run inside the sandbox" placeholder:"CMD"`
	Dump       bool     `name:"dump" hidden:"" help:"print the generated sandbox spec and exit"`
	K8s        *bool    `name:"k8s" negatable:"" help:"enable/disable k8s proxy (overrides profile)"`
	K8sConfig  *string  `name:"k8s-config" help:"override k8s.config (kubeconfig path)" placeholder:"PATH"`
	K8sContext []string `name:"k8s-context" help:"override k8s.context (comma-separated, repeatable)" placeholder:"CTX" sep:","`
	K8sMode    *string  `name:"k8s-mode" help:"override k8s.mode (rw|ro)" placeholder:"MODE"`
	Command    []string `arg:"" optional:"" passthrough:"" help:"command to run inside the sandbox"`
}

func Run(rawArgs []string) int {
	var c opts
	parser := kong.Must(&c,
		kong.Name("sbx"),
		kong.Description("Run a command inside a configurable sandbox."),
		kong.UsageOnError(),
	)
	if _, err := parser.Parse(normalizeArgs(rawArgs, parser)); err != nil {
		return failCode(err)
	}

	if !c.Dump && len(c.Command) == 0 && c.CommandStr == "" {
		fmt.Fprintln(os.Stderr, "sbx: missing command")
		return 2
	}
	if c.CommandStr != "" && len(c.Command) == 0 {
		c.Command = []string{"/bin/sh", "-c", c.CommandStr}
	}

	selected, err := config.LoadSelectedProfile(c.Config, c.Profile)
	if err != nil {
		return failCode(err)
	}
	applyCLIOverrides(&selected, &c)

	expand := config.Expander(selected.Env)

	if selected.K8s != nil && !c.Dump {
		cfg := selected.K8s.Config
		if cfg != "" {
			cfg = expand(cfg)
		}
		mode, err := k8s.ParseMode(selected.K8s.Mode)
		if err != nil {
			return failCode(err)
		}
		proxy, err := k8s.Start(cfg, selected.K8s.Contexts, mode)
		if err != nil {
			return failCode(fmt.Errorf("k8s proxy: %w", err))
		}
		if proxy != nil {
			defer proxy.Stop()
			if selected.Env == nil {
				selected.Env = map[string]string{}
			}
			selected.Env["KUBECONFIG"] = proxy.Path
			selected.Rules = append([]config.Rule{
				{Action: "allow", Mode: "r", Path: proxy.Dir},
			}, selected.Rules...)
		}
	}

	env := config.EnvList(selected.Env, expand)
	code, err := run(selected.Rules, expand, env, c.Dump, c.Command)
	if err != nil {
		return failCode(err)
	}
	return code
}

// applyCLIOverrides patches the loaded profile in place with CLI flag values.
// --no-k8s clears K8s entirely; any other --k8s-* flag (or --k8s) initializes
// K8s when absent and overrides the corresponding field when explicitly set.
func applyCLIOverrides(p *config.Profile, c *opts) {
	if c.K8s != nil && !*c.K8s {
		p.K8s = nil
		return
	}
	enable := (c.K8s != nil && *c.K8s) || c.K8sConfig != nil || len(c.K8sContext) > 0 || c.K8sMode != nil
	if p.K8s == nil && enable {
		p.K8s = &config.K8sProfile{}
	}
	if p.K8s == nil {
		return
	}
	if c.K8sConfig != nil {
		p.K8s.Config = *c.K8sConfig
	}
	if len(c.K8sContext) > 0 {
		p.K8s.Contexts = c.K8sContext
	}
	if c.K8sMode != nil {
		p.K8s.Mode = *c.K8sMode
	}
}

func failCode(err error) int {
	fmt.Fprintln(os.Stderr, "sbx:", err)
	return 1
}
