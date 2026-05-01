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

type Rule struct {
	Action string
	Mode   string
	Path   string
}

type Profile struct {
	Name  string
	Rules []Rule
	Env   map[string]string
}

type profileConfig struct {
	Name  string            `yaml:"name"`
	Rules []string          `yaml:"rules"`
	Env   map[string]string `yaml:"env"`
}

func Load(path string) ([]Rule, error) {
	return LoadProfile(path, "")
}

func LoadProfile(path, profile string) ([]Rule, error) {
	p, err := LoadSelectedProfile(path, profile)
	if err != nil {
		return nil, err
	}
	return p.Rules, nil
}

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
	p, err := loadProfile(data, profile)
	if err != nil {
		return Profile{}, err
	}
	rules := make([]Rule, len(p.Rules))
	for i, l := range p.Rules {
		r, err := Parse(l)
		if err != nil {
			return Profile{}, fmt.Errorf("%s line %d: %w", path, i+1, err)
		}
		rules[i] = r
	}
	return Profile{Name: p.Name, Rules: rules, Env: p.Env}, nil
}

func loadProfile(data []byte, profile string) (profileConfig, error) {
	if profile == "" {
		profile = "default"
	}
	docs, err := documentNodes(data)
	if err != nil {
		return profileConfig{}, err
	}
	if len(docs) > 1 {
		return documentProfileLines(docs, profile)
	}
	if len(docs) == 0 {
		return profileConfig{Name: profile}, nil
	}
	return nodeLines(docs[0], profile)
}

func documentNodes(data []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []*yaml.Node
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(doc.Content) == 0 {
			continue
		}
		docs = append(docs, doc.Content[0])
	}
	return docs, nil
}

func documentProfileLines(docs []*yaml.Node, profile string) (profileConfig, error) {
	for _, doc := range docs {
		if !isProfileNode(doc) {
			return profileConfig{}, fmt.Errorf("invalid multi-document config (expected profile documents)")
		}
		p, err := singleProfile(doc, profile)
		if err == nil {
			return p, nil
		}
	}
	return profileConfig{}, fmt.Errorf("profile %q not found", profile)
}

func nodeLines(node *yaml.Node, profile string) (profileConfig, error) {
	switch node.Kind {
	case yaml.SequenceNode:
		if isProfileList(node) {
			return listProfile(node, profile)
		}
		if profile != "default" {
			return profileConfig{}, fmt.Errorf("profile %q not found", profile)
		}
		lines, err := decodeLines(node)
		return profileConfig{Name: profile, Rules: lines}, err
	case yaml.MappingNode:
		if isProfileNode(node) {
			return singleProfile(node, profile)
		}
		profiles, err := profilesNode(node)
		if err != nil {
			return profileConfig{}, err
		}
		lines, ok := profiles[profile]
		if !ok {
			return profileConfig{}, fmt.Errorf("profile %q not found", profile)
		}
		return profileConfig{Name: profile, Rules: lines}, nil
	default:
		return profileConfig{}, fmt.Errorf("invalid config format (expected rule list or profiles map)")
	}
}

func isProfileList(node *yaml.Node) bool {
	return len(node.Content) > 0 && node.Content[0].Kind == yaml.MappingNode
}

func isProfileNode(node *yaml.Node) bool {
	hasName := false
	hasRules := false
	for i := 0; i+1 < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "name":
			hasName = true
		case "rules":
			hasRules = true
		}
	}
	return hasName && hasRules
}

func singleProfile(node *yaml.Node, profile string) (profileConfig, error) {
	var p profileConfig
	if err := node.Decode(&p); err != nil {
		return profileConfig{}, err
	}
	if p.Name != profile {
		return profileConfig{}, fmt.Errorf("profile %q not found", profile)
	}
	return p, nil
}

func listProfile(node *yaml.Node, profile string) (profileConfig, error) {
	var profiles []profileConfig
	if err := node.Decode(&profiles); err != nil {
		return profileConfig{}, err
	}
	for _, p := range profiles {
		if p.Name == profile {
			return p, nil
		}
	}
	return profileConfig{}, fmt.Errorf("profile %q not found", profile)
}

func profilesNode(node *yaml.Node) (map[string][]string, error) {
	var profilesNode *yaml.Node
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == "profiles" {
			profilesNode = node.Content[i+1]
			break
		}
	}
	if profilesNode == nil {
		profilesNode = node
	}
	if profilesNode.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("invalid profiles config (expected map)")
	}
	profiles := make(map[string][]string)
	for i := 0; i+1 < len(profilesNode.Content); i += 2 {
		name := profilesNode.Content[i].Value
		lines, err := decodeLines(profilesNode.Content[i+1])
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		profiles[name] = lines
	}
	return profiles, nil
}

func decodeLines(node *yaml.Node) ([]string, error) {
	var lines []string
	if err := node.Decode(&lines); err != nil {
		return nil, err
	}
	return lines, nil
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
