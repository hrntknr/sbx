package seatbelt

import (
	"strings"
	"testing"

	"github.com/hrntknr/sbx/internal/config"
)

func TestPathFilter(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/", ""},
		{"/foo", `(subpath "/foo")`},
		{"/foo/", `(subpath "/foo")`},
		{"/foo/*", `(regex #"^/foo/[^/]*(/.*)?$")`},
		{"/foo/**", `(regex #"^/foo/.*(/.*)?$")`},
		{"/foo/{a,b}", `(regex #"^/foo/(a|b)(/.*)?$")`},
	}
	for _, c := range cases {
		if got := pathFilter(c.in); got != c.want {
			t.Errorf("pathFilter(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGlobToRegex(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/foo", `^/foo(/.*)?$`},
		{"/foo/*", `^/foo/[^/]*(/.*)?$`},
		{"/foo/**", `^/foo/.*(/.*)?$`},
		{"/foo/*/bar", `^/foo/[^/]*/bar(/.*)?$`},
		{"/foo.bar", `^/foo[.]bar(/.*)?$`},
		{"/foo/{a,b}", `^/foo/(a|b)(/.*)?$`},
		{"/foo/[a-z]", `^/foo/[a-z](/.*)?$`},
	}
	for _, c := range cases {
		if got := globToRegex(c.in); got != c.want {
			t.Errorf("globToRegex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuild(t *testing.T) {
	rules := []config.Rule{
		{Action: "allow", Mode: "rw", Path: "/work"},
		{Action: "deny", Mode: "rw", Path: "/secret"},
		{Action: "allow", Mode: "r", Path: "/"},
	}
	got, err := Build(rules, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, baseProfile) {
		t.Fatal("missing base profile")
	}
	// user rules should be emitted in reverse (last-match-wins for seatbelt).
	want := `(allow file-read-data)
(deny file-read-data (subpath "/secret"))
(deny file-write* (subpath "/secret"))
(allow file-read-data (subpath "/work"))
(allow file-write* (subpath "/work"))
`
	if user := strings.TrimPrefix(got, baseProfile); user != want {
		t.Errorf("user rules mismatch\n--- got ---\n%s\n--- want ---\n%s", user, want)
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
