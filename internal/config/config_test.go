package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Rule
	}{
		{"allow(rw, /foo)", Rule{"allow", "rw", "/foo"}},
		{"deny(w, /etc)", Rule{"deny", "w", "/etc"}},
		{"  allow ( r , /usr ) ", Rule{"allow", "r", "/usr"}},
		{"allow(rw, ${WORK_DIR})", Rule{"allow", "rw", "${WORK_DIR}"}},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"allow rw /foo", "allow(rw)", "allow(rw, /foo", "(rw, /foo)"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q): expected error", in)
		}
	}
}

func TestParseMode(t *testing.T) {
	cases := []struct {
		in          string
		read, write bool
		expectError bool
	}{
		{"rw", true, true, false},
		{"r", true, false, false},
		{"w", false, true, false},
		{"ro", false, false, true},
		{"", false, false, true},
	}
	for _, c := range cases {
		r, w, err := ParseMode(c.in)
		if c.expectError != (err != nil) || r != c.read || w != c.write {
			t.Errorf("ParseMode(%q) = (%v,%v,%v), want (%v,%v,err=%v)",
				c.in, r, w, err, c.read, c.write, c.expectError)
		}
	}
}

func TestParseK8sRule(t *testing.T) {
	cases := []struct {
		in   string
		want K8sRule
	}{
		{"allow(rw, dev)", K8sRule{"allow", "rw", "dev"}},
		{"allow(r, prod-*)", K8sRule{"allow", "r", "prod-*"}},
		{"deny(rw, *)", K8sRule{"deny", "rw", "*"}},
	}
	for _, c := range cases {
		got, err := ParseK8sRule(c.in)
		if err != nil {
			t.Errorf("ParseK8sRule(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseK8sRule(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseK8sRuleErrors(t *testing.T) {
	for _, in := range []string{"allow(dev)", "allow(ro, dev)", "reject(rw, *)", "allow(r,)"} {
		if _, err := ParseK8sRule(in); err == nil {
			t.Errorf("ParseK8sRule(%q): expected error", in)
		}
	}
}

func TestParseSSHRule(t *testing.T) {
	cases := []struct {
		in   string
		want SSHRule
	}{
		{"allow(github.com)", SSHRule{"allow", "github.com"}},
		{"deny(*.internal)", SSHRule{"deny", "*.internal"}},
		{"  allow ( prod-[12] ) ", SSHRule{"allow", "prod-[12]"}},
	}
	for _, c := range cases {
		got, err := ParseSSHRule(c.in)
		if err != nil {
			t.Errorf("ParseSSHRule(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseSSHRule(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseSSHRuleErrors(t *testing.T) {
	for _, in := range []string{"allow github.com", "allow()", "reject(*)"} {
		if _, err := ParseSSHRule(in); err == nil {
			t.Errorf("ParseSSHRule(%q): expected error", in)
		}
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sbx.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSingleProfile(t *testing.T) {
	path := writeConfig(t, `
name: default
rules:
  - allow(rw, ${WORK_DIR})
  - allow(r, /)
`)
	got, err := LoadProfile(path, "")
	if err != nil {
		t.Fatalf("LoadProfile default: %v", err)
	}
	if len(got) != 2 || got[0] != (Rule{"allow", "rw", "${WORK_DIR}"}) || got[1] != (Rule{"allow", "r", "/"}) {
		t.Fatalf("LoadProfile default = %+v", got)
	}
	if _, err := LoadProfile(path, "locked"); err == nil {
		t.Fatal("LoadProfile locked: expected error")
	}
}

func TestLoadProfileWithoutName(t *testing.T) {
	path := writeConfig(t, `
rules:
  - allow(rw, ${WORK_DIR})
`)
	got, err := LoadProfile(path, "")
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	if len(got) != 1 || got[0] != (Rule{"allow", "rw", "${WORK_DIR}"}) {
		t.Fatalf("LoadProfile = %+v", got)
	}
}

func TestLoadProfileMultiDocument(t *testing.T) {
	path := writeConfig(t, `
name: default
env:
  SBX_MODE: default
  CACHE_DIR: ${WORK_DIR}/cache
rules:
  - allow(rw, ${WORK_DIR})
---
name: test
env:
  SBX_MODE: test
rules:
  - deny(rw, ~/.*)
`)
	got, err := LoadProfile(path, "")
	if err != nil {
		t.Fatalf("LoadProfile default: %v", err)
	}
	if len(got) != 1 || got[0] != (Rule{"allow", "rw", "${WORK_DIR}"}) {
		t.Fatalf("LoadProfile default = %+v", got)
	}

	got, err = LoadProfile(path, "test")
	if err != nil {
		t.Fatalf("LoadProfile test: %v", err)
	}
	if len(got) != 1 || got[0] != (Rule{"deny", "rw", "~/.*"}) {
		t.Fatalf("LoadProfile test = %+v", got)
	}

	p, err := LoadSelectedProfile(path, "test")
	if err != nil {
		t.Fatalf("LoadSelectedProfile test: %v", err)
	}
	if p.Env["SBX_MODE"] != "test" {
		t.Fatalf("SBX_MODE = %q, want test", p.Env["SBX_MODE"])
	}
}

func TestLoadProfileK8sBool(t *testing.T) {
	path := writeConfig(t, `
name: k8s
k8s: true
rules:
  - allow(rw, ${WORK_DIR})
`)
	p, err := LoadSelectedProfile(path, "k8s")
	if err != nil {
		t.Fatalf("LoadSelectedProfile: %v", err)
	}
	if p.K8s == nil {
		t.Fatalf("K8s should be enabled")
	}
	if len(p.K8s.Rules) != 0 {
		t.Fatalf("K8s defaults wrong: %+v", p.K8s)
	}
}

func TestLoadProfileK8sFalseRejected(t *testing.T) {
	path := writeConfig(t, `
name: k8s
k8s: false
rules:
  - allow(rw, ${WORK_DIR})
`)
	if _, err := LoadSelectedProfile(path, "k8s"); err == nil {
		t.Fatal("expected error for k8s: false")
	}
}

func TestLoadProfileK8sMapping(t *testing.T) {
	path := writeConfig(t, `
name: k8s
k8s:
  rules:
    - allow(r, my-ctx)
    - deny(rw, *)
rules:
  - allow(rw, ${WORK_DIR})
`)
	p, err := LoadSelectedProfile(path, "k8s")
	if err != nil {
		t.Fatalf("LoadSelectedProfile: %v", err)
	}
	if p.K8s == nil {
		t.Fatalf("K8s should be enabled")
	}
	want := []K8sRule{{"allow", "r", "my-ctx"}, {"deny", "rw", "*"}}
	if len(p.K8s.Rules) != len(want) {
		t.Fatalf("K8s.Rules = %+v", p.K8s.Rules)
	}
	for i := range want {
		if p.K8s.Rules[i] != want[i] {
			t.Fatalf("K8s.Rules[%d] = %+v, want %+v", i, p.K8s.Rules[i], want[i])
		}
	}
}

func TestLoadProfileK8sAbsent(t *testing.T) {
	path := writeConfig(t, `
name: default
rules:
  - allow(rw, ${WORK_DIR})
`)
	p, err := LoadSelectedProfile(path, "default")
	if err != nil {
		t.Fatalf("LoadSelectedProfile: %v", err)
	}
	if p.K8s != nil {
		t.Fatalf("K8s should be nil: %+v", p.K8s)
	}
}

func TestLoadProfileSSHBool(t *testing.T) {
	path := writeConfig(t, `
name: ssh
ssh: true
rules:
  - allow(rw, ${WORK_DIR})
`)
	p, err := LoadSelectedProfile(path, "ssh")
	if err != nil {
		t.Fatalf("LoadSelectedProfile: %v", err)
	}
	if p.SSH == nil {
		t.Fatalf("SSH should be enabled")
	}
	if len(p.SSH.Rules) != 0 {
		t.Fatalf("SSH defaults wrong: %+v", p.SSH)
	}
}

func TestLoadProfileSSHFalseRejected(t *testing.T) {
	path := writeConfig(t, `
name: ssh
ssh: false
rules:
  - allow(rw, ${WORK_DIR})
`)
	if _, err := LoadSelectedProfile(path, "ssh"); err == nil {
		t.Fatal("expected error for ssh: false")
	}
}

func TestLoadProfileSSHMapping(t *testing.T) {
	path := writeConfig(t, `
name: ssh
ssh:
  rules:
    - allow(github.com)
    - deny(*.internal)
rules:
  - allow(rw, ${WORK_DIR})
`)
	p, err := LoadSelectedProfile(path, "ssh")
	if err != nil {
		t.Fatalf("LoadSelectedProfile: %v", err)
	}
	if p.SSH == nil {
		t.Fatalf("SSH should be enabled")
	}
	want := []SSHRule{{"allow", "github.com"}, {"deny", "*.internal"}}
	if len(p.SSH.Rules) != len(want) {
		t.Fatalf("SSH.Rules = %+v", p.SSH.Rules)
	}
	for i := range want {
		if p.SSH.Rules[i] != want[i] {
			t.Fatalf("SSH.Rules[%d] = %+v, want %+v", i, p.SSH.Rules[i], want[i])
		}
	}
}

func TestLoadSelectedProfileFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", dir)

	p, err := LoadSelectedProfile("", "")
	if err != nil {
		t.Fatalf("LoadSelectedProfile: %v", err)
	}
	if p.Name != "default" {
		t.Fatalf("Name = %q, want default", p.Name)
	}
	if p.K8s == nil {
		t.Fatal("K8s should be enabled")
	}
	want := []Rule{
		{Action: "allow", Mode: "rw", Path: "${WORK_DIR}"},
		{Action: "allow", Mode: "rw", Path: "~/.claude"},
		{Action: "allow", Mode: "rw", Path: "~/.claude.json"},
		{Action: "allow", Mode: "rw", Path: "~/.codex"},
		{Action: "deny", Mode: "rw", Path: "~/.kube/config"},
		{Action: "allow", Mode: "r", Path: "/"},
	}
	if len(p.Rules) != len(want) {
		t.Fatalf("Rules = %+v, want %+v", p.Rules, want)
	}
	for i := range want {
		if p.Rules[i] != want[i] {
			t.Fatalf("Rules[%d] = %+v, want %+v", i, p.Rules[i], want[i])
		}
	}

	if _, err := LoadSelectedProfile("", "missing"); err == nil {
		t.Fatal("expected error for non-default profile when no config file exists")
	}
}

func TestExpanderUsesProfileEnv(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{"CACHE_DIR": dir, "NESTED": "${CACHE_DIR}/nested"}
	expand := Expander(env)

	if got := expand("${CACHE_DIR}/file"); got != dir+"/file" {
		t.Fatalf("expand CACHE_DIR = %q, want %q", got, dir+"/file")
	}
	if got := expand("${NESTED}/file"); got != dir+"/nested/file" {
		t.Fatalf("expand NESTED = %q, want %q", got, dir+"/nested/file")
	}
}

func TestEnvListAddsExpandedProfileEnv(t *testing.T) {
	t.Setenv("CACHE_DIR", "/old")
	dir := t.TempDir()
	env := map[string]string{"CACHE_DIR": dir, "NESTED": "${CACHE_DIR}/nested"}
	expand := Expander(env)
	got := EnvList(env, expand)

	values := map[string]string{}
	counts := map[string]int{}
	for _, entry := range got {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
			counts[key]++
		}
	}
	if values["CACHE_DIR"] != dir {
		t.Fatalf("CACHE_DIR = %q, want %q", values["CACHE_DIR"], dir)
	}
	if counts["CACHE_DIR"] != 1 {
		t.Fatalf("CACHE_DIR count = %d, want 1", counts["CACHE_DIR"])
	}
	if values["NESTED"] != dir+"/nested" {
		t.Fatalf("NESTED = %q, want %q", values["NESTED"], dir+"/nested")
	}
}
