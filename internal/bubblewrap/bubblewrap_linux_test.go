//go:build linux

package bubblewrap

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/hrntknr/sbx/internal/config"
)

func TestBuild(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "sub")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	rules := []config.Rule{
		{Action: "allow", Mode: "rw", Path: dir},
		{Action: "deny", Mode: "rw", Path: subDir},
		{Action: "deny", Mode: "rw", Path: file},
		{Action: "allow", Mode: "r", Path: "/"},
	}
	got, err := Build(rules, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}

	// Order: user rules reversed (first-match-wins), implicit tmp binds,
	// user tmp rules re-emitted so explicit denies still override the
	// implicit allow, then baseArgs.
	want := []string{
		"--ro-bind-try", "/", "/",
		"--ro-bind", "/dev/null", file,
		"--tmpfs", subDir,
		"--bind-try", dir, dir,
	}
	for _, p := range config.ImplicitTmpPaths() {
		want = append(want, "--bind-try", p, p)
	}
	want = append(want,
		"--ro-bind", "/dev/null", file,
		"--tmpfs", subDir,
		"--bind-try", dir, dir,
		"--proc", "/proc",
		"--dev", "/dev",
		"--die-with-parent",
	)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\ngot:  %v\nwant: %v", got, want)
	}
}

func TestBuildImplicitTmpAfterBroadRoot(t *testing.T) {
	rules := []config.Rule{{Action: "allow", Mode: "r", Path: "/"}}
	got, err := Build(rules, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	rootIdx := -1
	for i := 0; i+2 < len(got); i++ {
		if got[i] == "--ro-bind-try" && got[i+1] == "/" && got[i+2] == "/" {
			rootIdx = i
			break
		}
	}
	if rootIdx == -1 {
		t.Fatal("missing --ro-bind-try / /")
	}
	for _, p := range config.ImplicitTmpPaths() {
		idx := -1
		for i := rootIdx + 3; i+2 < len(got); i++ {
			if got[i] == "--bind-try" && got[i+1] == p && got[i+2] == p {
				idx = i
				break
			}
		}
		if idx == -1 {
			t.Errorf("implicit tmp bind for %q must appear after --ro-bind-try / / (got %v)", p, got)
		}
	}
}

func TestBuildExplicitTmpDenyOverridesImplicit(t *testing.T) {
	rules := []config.Rule{
		{Action: "deny", Mode: "rw", Path: "/tmp"},
		{Action: "allow", Mode: "r", Path: "/"},
	}
	got, err := Build(rules, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	// Find the LAST mount targeting /tmp; explicit deny should win.
	lastTmpAction := ""
	for i := 0; i+1 < len(got); i++ {
		switch got[i] {
		case "--tmpfs":
			if got[i+1] == "/tmp" {
				lastTmpAction = "deny"
			}
		case "--bind-try":
			if i+2 < len(got) && got[i+1] == "/tmp" && got[i+2] == "/tmp" {
				lastTmpAction = "allow"
			}
		}
	}
	if lastTmpAction != "deny" {
		t.Errorf("last mount on /tmp should be the user deny, got %q (args=%v)", lastTmpAction, got)
	}
}

func TestBuildErrors(t *testing.T) {
	cases := []config.Rule{
		{Action: "allow", Mode: "exec", Path: "/foo"},
		{Action: "permit", Mode: "rw", Path: "/foo"},
		{Action: "allow", Mode: "rw", Path: ""},
	}
	for _, r := range cases {
		if _, err := Build([]config.Rule{r}, func(s string) string { return s }); err == nil {
			t.Errorf("Build(%+v): expected error", r)
		}
	}
}

func TestMountArgs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		action      string
		read, write bool
		path        string
		want        []string
	}{
		{"allow rw", "allow", true, true, "/x", []string{"--bind-try", "/x", "/x"}},
		{"allow r", "allow", true, false, "/x", []string{"--ro-bind-try", "/x", "/x"}},
		{"allow w", "allow", false, true, "/x", []string{"--bind-try", "/x", "/x"}},
		{"deny dir", "deny", true, true, dir, []string{"--tmpfs", dir}},
		{"deny file", "deny", true, true, file, []string{"--ro-bind", "/dev/null", file}},
		{"deny missing", "deny", true, true, "/no/such/path", []string{"--ro-bind", "/dev/null", "/no/such/path"}},
	}
	for _, c := range cases {
		got := mountArgs(c.action, c.read, c.write, c.path)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestExpandPaths(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{".a", ".b", "c"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got := expandPaths(filepath.Join(dir, ".*"))
	sort.Strings(got)
	want := []string{filepath.Join(dir, ".a"), filepath.Join(dir, ".b")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("glob: got %v, want %v", got, want)
	}

	if got := expandPaths("/no/such/glob/*"); got != nil {
		t.Errorf("nonmatching glob: got %v, want nil", got)
	}

	if got := expandPaths("/plain/path"); !reflect.DeepEqual(got, []string{"/plain/path"}) {
		t.Errorf("plain path: got %v", got)
	}
}
