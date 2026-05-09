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
	Name   string
	Rules  []Rule
	Env    map[string]string
	K8s    *K8sProfile
	SSH    *SSHProfile
	Docker *DockerProfile
}

// K8sProfile enables a kubectl proxy alongside the sandbox. Presence of the
// profile means enabled; nil means disabled. Namespace is inherited from each
// source context and is not configurable. Empty Rules means expose every
// context read/write, current-context first.
type K8sProfile struct {
	Rules []K8sRule
}

// K8sRule controls which source kubeconfig contexts are exposed through the
// proxy. Pattern uses path.Match syntax: `*`, `?`, `[...]`. Mode is "rw" or
// "r" and is applied to allowed contexts; deny rules ignore Mode.
type K8sRule struct {
	Action  string
	Mode    string
	Pattern string
}

// DockerProfile enables a Docker API proxy alongside the sandbox. Presence of
// the profile means enabled; nil means disabled. Empty Rules means expose every
// supported Docker context read/write, current-context first.
type DockerProfile struct {
	Rules []DockerRule
}

// DockerRule controls which source Docker contexts are exposed through the
// proxy. Pattern uses path.Match syntax. Mode is "rw" or "r" and is applied to
// allowed contexts; deny rules ignore Mode.
type DockerRule struct {
	Action  string
	Mode    string
	Pattern string
}

// SSHRule controls which resolved SSH destination hosts are exposed through
// the SSH proxy. Pattern uses path.Match syntax: `*`, `?`, `[...]`.
type SSHRule struct {
	Action  string
	Pattern string
}

// SSHProfile enables an SSH MITM proxy alongside the sandbox. Presence of the
// profile means enabled; nil means disabled. Empty Rules means expose every
// destination host, matching k8s' empty context list behavior.
type SSHProfile struct {
	Rules []SSHRule
}

// UnmarshalYAML accepts:
//
//	ssh: true              -> empty profile (defaults)
//	ssh: [ ... ]           -> rule list
//
// `ssh: false` is rejected; omit the field to disable.
func (s *SSHProfile) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var v bool
		if err := node.Decode(&v); err != nil {
			return fmt.Errorf("ssh: must be `true` or a mapping (got %q)", node.Value)
		}
		if !v {
			return fmt.Errorf("ssh: false is not supported; omit the field to disable")
		}
		return nil
	}
	if node.Kind == yaml.SequenceNode {
		return s.decodeRules(node)
	}
	return fmt.Errorf("ssh: must be `true` or a rule list")
}

func (s *SSHProfile) decodeRules(node *yaml.Node) error {
	var raw scalarOrSlice
	if err := node.Decode(&raw); err != nil {
		return err
	}
	rules := make([]SSHRule, len(raw))
	for i, l := range raw {
		r, err := ParseSSHRule(l)
		if err != nil {
			return fmt.Errorf("ssh.rules line %d: %w", i+1, err)
		}
		rules[i] = r
	}
	s.Rules = rules
	return nil
}

// UnmarshalYAML accepts:
//
//	k8s: true              -> empty profile (defaults)
//	k8s: [ ... ]           -> rule list
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
	if node.Kind == yaml.SequenceNode {
		return k.decodeRules(node)
	}
	return fmt.Errorf("k8s: must be `true` or a rule list")
}

func (k *K8sProfile) decodeRules(node *yaml.Node) error {
	var raw scalarOrSlice
	if err := node.Decode(&raw); err != nil {
		return err
	}
	rules := make([]K8sRule, len(raw))
	for i, l := range raw {
		r, err := ParseK8sRule(l)
		if err != nil {
			return fmt.Errorf("k8s.rules line %d: %w", i+1, err)
		}
		rules[i] = r
	}
	k.Rules = rules
	return nil
}

// UnmarshalYAML accepts:
//
//	docker: true              -> empty profile (defaults)
//	docker: [ ... ]           -> rule list
//
// `docker: false` is rejected; omit the field to disable.
func (d *DockerProfile) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var v bool
		if err := node.Decode(&v); err != nil {
			return fmt.Errorf("docker: must be `true` or a rule list (got %q)", node.Value)
		}
		if !v {
			return fmt.Errorf("docker: false is not supported; omit the field to disable")
		}
		return nil
	}
	if node.Kind == yaml.SequenceNode {
		return d.decodeRules(node)
	}
	return fmt.Errorf("docker: must be `true` or a rule list")
}

func (d *DockerProfile) decodeRules(node *yaml.Node) error {
	var raw scalarOrSlice
	if err := node.Decode(&raw); err != nil {
		return err
	}
	rules := make([]DockerRule, len(raw))
	for i, l := range raw {
		r, err := ParseDockerRule(l)
		if err != nil {
			return fmt.Errorf("docker.rules line %d: %w", i+1, err)
		}
		rules[i] = r
	}
	d.Rules = rules
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
	Name   string            `yaml:"name"`
	Rules  []string          `yaml:"rules"`
	Env    map[string]string `yaml:"env"`
	K8s    *K8sProfile       `yaml:"k8s"`
	SSH    *SSHProfile       `yaml:"ssh"`
	Docker *DockerProfile    `yaml:"docker"`
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
// When path is "" and no default config file exists, the built-in default
// profile is returned (allow rw on cwd/tmp, allow r on /, k8s enabled).
func LoadSelectedProfile(path, profile string) (Profile, error) {
	if profile == "" {
		profile = "default"
	}
	if path == "" {
		path = defaultPath()
	}
	if path == "" {
		if profile != "default" {
			return Profile{}, fmt.Errorf("profile %q not found", profile)
		}
		return defaultProfile(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
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
	return Profile{Name: profile, Rules: rules, Env: raw.Env, K8s: raw.K8s, SSH: raw.SSH, Docker: raw.Docker}, nil
}

// defaultProfile is used when no config file is present.
func defaultProfile() Profile {
	return Profile{
		Name: "default",
		K8s:  &K8sProfile{},
		Rules: []Rule{
			{Action: "allow", Mode: "rw", Path: "${WORK_DIR}"},
			{Action: "allow", Mode: "rw", Path: "~/.claude"},
			{Action: "allow", Mode: "rw", Path: "~/.claude.json"},
			{Action: "allow", Mode: "rw", Path: "~/.codex"},
			{Action: "deny", Mode: "rw", Path: "~/.ssh"},
			{Action: "deny", Mode: "rw", Path: "~/.docker"},
			{Action: "deny", Mode: "rw", Path: "/var/run/docker.sock"},
			{Action: "deny", Mode: "rw", Path: "~/.kube/config"},
			{Action: "allow", Mode: "r", Path: "/"},
		},
	}
}

// ImplicitTmpPaths returns canonical temp directories the sandbox always
// allows read/write on, regardless of user rules: the system /tmp (which on
// macOS is a symlink to /private/tmp) and os.TempDir() (the per-user temp
// dir, e.g. /var/folders/.../T or whatever $TMPDIR points to). Symlinks are
// resolved; duplicates are removed.
func ImplicitTmpPaths() []string {
	raw := []string{"/tmp", os.TempDir()}
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimRight(p, "/")
		if p == "" {
			continue
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
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
		if p.Name == "" && len(p.Rules) == 0 && len(p.Env) == 0 && p.K8s == nil && p.SSH == nil && p.Docker == nil {
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

// ParseDockerRule parses "ACTION(MODE, PATTERN)" e.g. "allow(r, prod-*)".
func ParseDockerRule(s string) (DockerRule, error) {
	r, err := parseContextRule("docker", s)
	if err != nil {
		return DockerRule{}, err
	}
	return DockerRule(r), nil
}

// ParseK8sRule parses "ACTION(MODE, PATTERN)" e.g. "allow(r, prod-*)".
func ParseK8sRule(s string) (K8sRule, error) {
	r, err := parseContextRule("k8s", s)
	if err != nil {
		return K8sRule{}, err
	}
	return K8sRule(r), nil
}

func parseContextRule(kind, s string) (DockerRule, error) {
	s = strings.TrimSpace(s)
	open := strings.IndexByte(s, '(')
	if open <= 0 || !strings.HasSuffix(s, ")") {
		return DockerRule{}, fmt.Errorf("invalid %s rule %q (expected ACTION(MODE, PATTERN))", kind, s)
	}
	action := strings.ToLower(strings.TrimSpace(s[:open]))
	if action != "allow" && action != "deny" {
		return DockerRule{}, fmt.Errorf("invalid action %q (must be allow or deny)", action)
	}
	inner := s[open+1 : len(s)-1]
	comma := strings.Index(inner, ",")
	if comma < 0 {
		return DockerRule{}, fmt.Errorf("invalid %s rule %q (missing comma)", kind, s)
	}
	mode := strings.ToLower(strings.TrimSpace(inner[:comma]))
	if mode != "rw" && mode != "r" {
		return DockerRule{}, fmt.Errorf("invalid %s mode %q (must be rw or r)", kind, mode)
	}
	pattern := strings.TrimSpace(inner[comma+1:])
	if pattern == "" {
		return DockerRule{}, fmt.Errorf("invalid %s rule %q (empty pattern)", kind, s)
	}
	return DockerRule{Action: action, Mode: mode, Pattern: pattern}, nil
}

// ParseSSHRule parses "ACTION(PATTERN)" e.g. "allow(github.com)".
func ParseSSHRule(s string) (SSHRule, error) {
	s = strings.TrimSpace(s)
	open := strings.IndexByte(s, '(')
	if open <= 0 || !strings.HasSuffix(s, ")") {
		return SSHRule{}, fmt.Errorf("invalid ssh rule %q (expected ACTION(PATTERN))", s)
	}
	action := strings.ToLower(strings.TrimSpace(s[:open]))
	if action != "allow" && action != "deny" {
		return SSHRule{}, fmt.Errorf("invalid action %q (must be allow or deny)", action)
	}
	pattern := strings.TrimSpace(s[open+1 : len(s)-1])
	if pattern == "" {
		return SSHRule{}, fmt.Errorf("invalid ssh rule %q (empty pattern)", s)
	}
	return SSHRule{Action: action, Pattern: pattern}, nil
}

func defaultPath() string {
	for _, p := range []string{".sbx.yaml", filepath.Join(os.Getenv("HOME"), ".sbx.yaml")} {
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
// then in built-ins WORK_DIR/HOME, then in os.Environ.
func Expander(env ...map[string]string) func(string) string {
	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	vars := map[string]string{"WORK_DIR": cwd, "HOME": home}
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
