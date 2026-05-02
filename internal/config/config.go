package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// Rule is a parsed sandbox access rule.
type Rule struct {
	Action string
	Mode   string
	Path   string
}

// Profile is a single resolved profile with parsed rules.
type Profile struct {
	Name  string
	Rules []Rule
	Env   map[string]string
	K8s   *K8sProfile
}

// K8sProfile enables a kubectl proxy alongside the sandbox. Presence of the
// profile means enabled; nil means disabled. Namespace is inherited from
// each source context and is not configurable.
//
// Contexts may be literal context names or globs (path.Match syntax: `*`,
// `?`, `[...]`). Each resolved context gets its own entry in the generated
// kubeconfig, served through a single localhost proxy. Empty list means
// "expose every context in the source kubeconfig", current-context first.
//
// Mode controls request filtering at the proxy:
//   - "rw" (default): no filtering, the sandbox can mutate cluster state.
//   - "ro":           POST/PUT/PATCH/DELETE are rejected at the proxy.
type K8sProfile struct {
	Config   string
	Contexts []string
	Mode     string
}

// UnmarshalYAML accepts:
//
//	k8s: true              -> empty profile (defaults)
//	k8s: { ... }           -> mapping with config/context/mode
//
// `k8s: false` is rejected; omit the field to disable.
func (k *K8sProfile) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var v bool
		if err := node.Decode(&v); err != nil {
			return fmt.Errorf("k8s: must be `true` or a mapping (got %q)", node.Value)
		}
		if !v {
			return fmt.Errorf("k8s: false is not supported; omit the field to disable")
		}
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("k8s: must be `true` or a mapping")
	}
	var raw struct {
		Config  string        `yaml:"config"`
		Context scalarOrSlice `yaml:"context"`
		Mode    string        `yaml:"mode"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	k.Config, k.Contexts, k.Mode = raw.Config, raw.Context, raw.Mode
	return nil
}

// scalarOrSlice decodes a YAML scalar or sequence into []string.
type scalarOrSlice []string

func (s *scalarOrSlice) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var v string
		if err := node.Decode(&v); err != nil {
			return err
		}
		*s = []string{v}
		return nil
	}
	return node.Decode((*[]string)(s))
}

type rawProfile struct {
	Name  string            `yaml:"name"`
	Rules []string          `yaml:"rules"`
	Env   map[string]string `yaml:"env"`
	K8s   *K8sProfile       `yaml:"k8s"`
}

// LoadProfile is a convenience wrapper that returns only the parsed rules of
// the selected profile.
func LoadProfile(path, profile string) ([]Rule, error) {
	p, err := LoadSelectedProfile(path, profile)
	if err != nil {
		return nil, err
	}
	return p.Rules, nil
}

// LoadSelectedProfile reads path, finds the profile by name (defaults to
// "default" when profile is ""), and returns it with rules already parsed.
// When path is "" and no default config file exists, an empty Profile is
// returned without error.
func LoadSelectedProfile(path, profile string) (Profile, error) {
	if path == "" {
		path = defaultPath()
	}
	if path == "" {
		return Profile{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	if profile == "" {
		profile = "default"
	}
	raw, err := selectProfile(data, profile)
	if err != nil {
		return Profile{}, err
	}
	rules := make([]Rule, len(raw.Rules))
	for i, l := range raw.Rules {
		r, err := Parse(l)
		if err != nil {
			return Profile{}, fmt.Errorf("%s line %d: %w", path, i+1, err)
		}
		rules[i] = r
	}
	return Profile{Name: profile, Rules: rules, Env: raw.Env, K8s: raw.K8s}, nil
}

// selectProfile decodes data as a stream of YAML documents, returning the
// first one whose `name` matches profile (or "default" if `name` is
// omitted). Documents that are entirely empty are skipped.
func selectProfile(data []byte, profile string) (rawProfile, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var p rawProfile
		err := dec.Decode(&p)
		if err == io.EOF {
			break
		}
		if err != nil {
			return rawProfile{}, err
		}
		if p.Name == "" && len(p.Rules) == 0 && len(p.Env) == 0 && p.K8s == nil {
			continue
		}
		name := p.Name
		if name == "" {
			name = "default"
		}
		if name == profile {
			return p, nil
		}
	}
	return rawProfile{}, fmt.Errorf("profile %q not found", profile)
}

func defaultPath() string {
	for _, p := range []string{"sbx.yaml", filepath.Join(os.Getenv("HOME"), ".sbx.yaml")} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Parse parses "ACTION(MODE, PATH)" e.g. "allow(rw, /foo)".
func Parse(s string) (Rule, error) {
	s = strings.TrimSpace(s)
	open := strings.IndexByte(s, '(')
	if open <= 0 || !strings.HasSuffix(s, ")") {
		return Rule{}, fmt.Errorf("invalid rule %q (expected ACTION(MODE, PATH))", s)
	}
	inner := s[open+1 : len(s)-1]
	comma := strings.Index(inner, ",")
	if comma < 0 {
		return Rule{}, fmt.Errorf("invalid rule %q (missing comma)", s)
	}
	return Rule{
		Action: strings.ToLower(strings.TrimSpace(s[:open])),
		Mode:   strings.ToLower(strings.TrimSpace(inner[:comma])),
		Path:   strings.TrimSpace(inner[comma+1:]),
	}, nil
}

// ParseMode parses "r" / "w" / "rw" into read/write bools.
func ParseMode(s string) (read, write bool, err error) {
	switch s {
	case "rw":
		return true, true, nil
	case "r":
		return true, false, nil
	case "w":
		return false, true, nil
	}
	return false, false, fmt.Errorf("invalid mode %q (must be r, w, or rw)", s)
}

// EnvList overlays env (with values expanded) onto os.Environ() and returns
// it as a "KEY=VALUE" slice.
func EnvList(env map[string]string, expand func(string) string) []string {
	overrides := make(map[string]string, len(env))
	for k, v := range env {
		overrides[k] = expand(v)
	}
	out := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			if value, exists := overrides[key]; exists {
				out = append(out, key+"="+value)
				delete(overrides, key)
				continue
			}
		}
		out = append(out, entry)
	}
	keys := make([]string, 0, len(overrides))
	for k := range overrides {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+overrides[k])
	}
	return out
}

// Expander returns a function that expands ${VAR} and ~ in a string. VARs
// are looked up in the supplied env maps (later maps override earlier),
// then in built-ins WORK_DIR/TMP_DIR/HOME, then in os.Environ.
func Expander(env ...map[string]string) func(string) string {
	cwd, _ := os.Getwd()
	tmp := os.TempDir()
	home, _ := os.UserHomeDir()
	vars := map[string]string{"WORK_DIR": cwd, "TMP_DIR": tmp, "HOME": home}
	for _, e := range env {
		for k, v := range e {
			vars[k] = v
		}
	}
	var resolve func(string, map[string]bool) string
	resolve = func(k string, seen map[string]bool) string {
		if seen[k] {
			return ""
		}
		if v, ok := vars[k]; ok {
			seen[k] = true
			return os.Expand(v, func(name string) string {
				return resolve(name, seen)
			})
		}
		return os.Getenv(k)
	}
	return func(s string) string {
		if s == "~" || strings.HasPrefix(s, "~/") {
			s = home + s[1:]
		}
		return os.Expand(s, func(k string) string {
			return resolve(k, map[string]bool{})
		})
	}
}
