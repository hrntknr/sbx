package cli

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"

	"github.com/hrntknr/sbx/internal/config"
	"github.com/hrntknr/sbx/internal/dockerproxy"
	"github.com/hrntknr/sbx/internal/k8s"
	"github.com/hrntknr/sbx/internal/sshproxy"
)

type opts struct {
	Config  string   `name:"config" short:"c" help:"config file path (default: ./sbx.yaml or ~/.sbx.yaml)" placeholder:"PATH"`
	Profile string   `name:"profile" help:"profile name (default: default)" placeholder:"NAME"`
	Dump    bool     `name:"dump" hidden:"" help:"print the generated sandbox spec and exit"`
	K8s     *bool    `name:"k8s" negatable:"" help:"enable/disable k8s proxy (overrides profile)"`
	SSH     *bool    `name:"ssh" negatable:"" help:"enable/disable the ssh proxy (overrides profile)"`
	Docker  *bool    `name:"docker" negatable:"" help:"enable/disable the docker proxy (overrides profile)"`
	Command []string `arg:"" optional:"" passthrough:"" help:"command to run inside the sandbox"`
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

	if !c.Dump && len(c.Command) == 0 {
		fmt.Fprintln(os.Stderr, "sbx: missing command")
		return 2
	}

	selected, err := config.LoadSelectedProfile(c.Config, c.Profile)
	if err != nil {
		return failCode(err)
	}
	applyCLIOverrides(&selected, &c)

	expand := config.Expander(selected.Env)

	if selected.K8s != nil && !c.Dump {
		rules, err := k8sRules(selected.K8s.Rules)
		if err != nil {
			return failCode(err)
		}
		proxy, err := k8s.Start(rules)
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
	if selected.SSH != nil && !c.Dump {
		proxy, err := sshproxy.Start(sshproxy.Options{Rules: selected.SSH.Rules})
		if err != nil {
			return failCode(fmt.Errorf("ssh proxy: %w", err))
		}
		defer proxy.Stop()
		if selected.Env == nil {
			selected.Env = map[string]string{}
		}
		selected.Env["PATH"] = proxy.BinDir + string(os.PathListSeparator) + os.Getenv("PATH")
		selected.Env["SSH_AUTH_SOCK"] = ""
		selected.Rules = append([]config.Rule{{Action: "allow", Mode: "r", Path: proxy.Dir}}, selected.Rules...)
	}
	if selected.Docker != nil && !c.Dump {
		rules, err := dockerproxy.RulesFromConfig(selected.Docker.Rules)
		if err != nil {
			return failCode(err)
		}
		proxy, err := dockerproxy.Start(rules)
		if err != nil {
			return failCode(fmt.Errorf("docker proxy: %w", err))
		}
		if proxy != nil {
			defer proxy.Stop()
			if selected.Env == nil {
				selected.Env = map[string]string{}
			}
			selected.Env["DOCKER_CONFIG"] = proxy.Dir
			selected.Env["DOCKER_HOST"] = ""
			selected.Env["DOCKER_CONTEXT"] = ""
			selected.Rules = append([]config.Rule{{Action: "allow", Mode: "rw", Path: proxy.Dir}}, selected.Rules...)
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
	} else {
		enable := c.K8s != nil && *c.K8s
		if p.K8s == nil && enable {
			p.K8s = &config.K8sProfile{}
		}
	}

	if c.SSH != nil && !*c.SSH {
		p.SSH = nil
	} else {
		sshEnable := c.SSH != nil && *c.SSH
		if p.SSH == nil && sshEnable {
			p.SSH = &config.SSHProfile{}
		}
	}

	if c.Docker != nil && !*c.Docker {
		p.Docker = nil
	} else {
		dockerEnable := c.Docker != nil && *c.Docker
		if p.Docker == nil && dockerEnable {
			p.Docker = &config.DockerProfile{}
		}
	}
}

func k8sRules(rules []config.K8sRule) ([]k8s.Rule, error) {
	out := make([]k8s.Rule, len(rules))
	for i, rule := range rules {
		mode, err := k8s.ParseMode(rule.Mode)
		if err != nil {
			return nil, err
		}
		out[i] = k8s.Rule{Action: rule.Action, Mode: mode, Pattern: rule.Pattern}
	}
	return out, nil
}

func failCode(err error) int {
	fmt.Fprintln(os.Stderr, "sbx:", err)
	return 1
}
