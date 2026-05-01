package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

type Rule struct {
	Action string
	Mode   string
	Path   string
}

func Load(path string) ([]Rule, error) {
	if path == "" {
		path = defaultPath()
	}
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	if err := yaml.Unmarshal(data, &lines); err != nil {
		return nil, err
	}
	rules := make([]Rule, len(lines))
	for i, l := range lines {
		r, err := Parse(l)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, i+1, err)
		}
		rules[i] = r
	}
	return rules, nil
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

func Expander() func(string) string {
	cwd, _ := os.Getwd()
	tmp := os.TempDir()
	home, _ := os.UserHomeDir()
	vars := map[string]string{"WORK_DIR": cwd, "TMP_DIR": tmp, "HOME": home}
	return func(s string) string {
		if s == "~" || strings.HasPrefix(s, "~/") {
			s = home + s[1:]
		}
		return os.Expand(s, func(k string) string {
			if v, ok := vars[k]; ok {
				return v
			}
			return os.Getenv(k)
		})
	}
}
