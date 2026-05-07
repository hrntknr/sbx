package k8s

import (
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestExpandContexts(t *testing.T) {
	available := []string{"dev", "prod-1", "prod-2", "stage"}
	cases := []struct {
		name     string
		patterns []string
		want     []string
		wantErr  bool
	}{
		{"literal", []string{"dev"}, []string{"dev"}, false},
		{"literal multiple", []string{"prod-1", "dev"}, []string{"prod-1", "dev"}, false},
		{"glob star", []string{"prod-*"}, []string{"prod-1", "prod-2"}, false},
		{"glob question", []string{"prod-?"}, []string{"prod-1", "prod-2"}, false},
		{"glob class", []string{"prod-[12]"}, []string{"prod-1", "prod-2"}, false},
		{"mixed", []string{"dev", "prod-*"}, []string{"dev", "prod-1", "prod-2"}, false},
		{"dedup", []string{"dev", "*"}, []string{"dev", "prod-1", "prod-2", "stage"}, false},
		{"unknown literal", []string{"missing"}, nil, true},
		{"glob no match", []string{"qa-*"}, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := expandContexts(c.patterns, available)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("expandContexts(%v) = %v, want %v", c.patterns, got, c.want)
			}
		})
	}
}

func TestResolveRules(t *testing.T) {
	available := []string{"dev", "prod-1", "prod-2", "stage"}
	rules := []Rule{
		{Action: "allow", Mode: ModeReadOnly, Pattern: "prod-*"},
		{Action: "allow", Mode: ModeReadWrite, Pattern: "dev"},
		{Action: "deny", Mode: ModeReadWrite, Pattern: "*"},
	}
	got, err := resolveRules(rules, available, "dev")
	if err != nil {
		t.Fatalf("resolveRules: %v", err)
	}
	want := []resolvedContext{{"dev", ModeReadWrite}, {"prod-1", ModeReadOnly}, {"prod-2", ModeReadOnly}}
	if !slices.Equal(got, want) {
		t.Fatalf("resolveRules = %+v, want %+v", got, want)
	}
}

func TestResolveRulesErrorsWhenAllowMatchesNothing(t *testing.T) {
	_, err := resolveRules([]Rule{{Action: "allow", Mode: ModeReadOnly, Pattern: "missing-*"}}, []string{"dev"}, "")
	if err == nil {
		t.Fatal("expected missing allow pattern to fail")
	}
}

func TestResolveRulesErrorsWhenNothingAllowed(t *testing.T) {
	_, err := resolveRules([]Rule{{Action: "deny", Mode: ModeReadWrite, Pattern: "*"}}, []string{"dev"}, "")
	if err == nil {
		t.Fatal("expected all-deny rules to fail")
	}
}

func TestBuildKubeconfig(t *testing.T) {
	got := buildKubeconfig("127.0.0.1:12345", []proxyEntry{{name: "sbx"}})
	for _, want := range []string{
		"server: http://127.0.0.1:12345/contexts/sbx",
		"current-context: sbx",
		"- name: sbx",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("buildKubeconfig missing %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "namespace:") {
		t.Errorf("buildKubeconfig should omit namespace when empty\n%s", got)
	}
}

func TestBuildKubeconfigMulti(t *testing.T) {
	got := buildKubeconfig("127.0.0.1:8000", []proxyEntry{
		{name: "dev", namespace: "dev-ns"},
		{name: "prod"},
	})
	for _, want := range []string{
		"server: http://127.0.0.1:8000/contexts/dev",
		"server: http://127.0.0.1:8000/contexts/prod",
		"namespace: dev-ns",
		"current-context: dev",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("buildKubeconfig missing %q\n%s", want, got)
		}
	}
}

func TestBuildKubeconfigEscapesContextNameInURL(t *testing.T) {
	const name = "arn:aws:eks:us-east-1:123:cluster/foo"
	got := buildKubeconfig("127.0.0.1:8000", []proxyEntry{{name: name}})
	const wantServer = "server: http://127.0.0.1:8000/contexts/arn:aws:eks:us-east-1:123:cluster%2Ffoo"
	if !strings.Contains(got, wantServer) {
		t.Errorf("buildKubeconfig should percent-escape context name in URL, want %q\n%s", wantServer, got)
	}
}

func TestRouterRoutesEscapedContextName(t *testing.T) {
	const name = "arn:aws:eks:us-east-1:123:cluster/foo"
	var gotPath string
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	})
	rt := &router{handlers: map[string]http.Handler{name: h}}
	req := httptest.NewRequest("GET", "/contexts/arn:aws:eks:us-east-1:123:cluster%2Ffoo/api/v1/pods", nil)
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if gotPath != "/api/v1/pods" {
		t.Errorf("upstream path = %q, want /api/v1/pods", gotPath)
	}
}

func TestStartEmptyKubeconfigSkips(t *testing.T) {
	path := writeEmptyKubeconfig(t)

	t.Setenv("KUBECONFIG", path)
	proxy, err := Start(nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if proxy != nil {
		proxy.Stop()
		t.Fatal("expected nil proxy when kubeconfig has no contexts")
	}
}

func TestStartEmptyKubeconfigButContextRequestedErrors(t *testing.T) {
	path := writeEmptyKubeconfig(t)

	t.Setenv("KUBECONFIG", path)
	if _, err := Start([]Rule{{Action: "allow", Mode: ModeReadWrite, Pattern: "missing"}}); err == nil {
		t.Fatal("expected error when contexts are requested but kubeconfig is empty")
	}
}

func writeEmptyKubeconfig(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/config"
	if err := os.WriteFile(path, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseMode(t *testing.T) {
	cases := []struct {
		in      string
		want    Mode
		wantErr bool
	}{
		{"", ModeReadWrite, false},
		{"rw", ModeReadWrite, false},
		{"RW", ModeReadWrite, false},
		{"r", ModeReadOnly, false},
		{"R", ModeReadOnly, false},
		{"ro", 0, true},
		{"readonly", 0, true},
	}
	for _, c := range cases {
		got, err := ParseMode(c.in)
		if c.wantErr != (err != nil) {
			t.Errorf("ParseMode(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("ParseMode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestMoveToFront(t *testing.T) {
	cases := []struct {
		in     []string
		target string
		want   []string
	}{
		{[]string{"a", "b", "c"}, "b", []string{"b", "a", "c"}},
		{[]string{"a", "b", "c"}, "a", []string{"a", "b", "c"}},
		{[]string{"a", "b", "c"}, "c", []string{"c", "a", "b"}},
		{[]string{"a", "b", "c"}, "x", []string{"a", "b", "c"}},
		{[]string{}, "x", []string{}},
	}
	for _, c := range cases {
		got := moveToFront(c.in, c.target)
		if len(got) != len(c.want) {
			t.Errorf("moveToFront(%v, %q) = %v, want %v", c.in, c.target, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("moveToFront(%v, %q) = %v, want %v", c.in, c.target, got, c.want)
				break
			}
		}
	}
}

func TestSubresourceBlocked(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/api/v1/namespaces/x/pods/y/exec", true},
		{"/api/v1/namespaces/x/pods/y/attach", true},
		{"/api/v1/namespaces/x/pods/y/portforward", true},
		{"/api/v1/namespaces/x/pods/y/log", false},
		{"/api/v1/namespaces/x/pods/y", false},
	}
	for _, c := range cases {
		if got := subresourceBlocked(c.path); got != c.want {
			t.Errorf("subresourceBlocked(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestReadOnlyMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := readOnlyMiddleware(next)

	cases := []struct {
		method string
		path   string
		want   int
	}{
		{"GET", "/api/v1/pods", http.StatusOK},
		{"POST", "/api/v1/pods", http.StatusForbidden},
		{"DELETE", "/api/v1/pods", http.StatusForbidden},
		{"GET", "/api/v1/namespaces/x/pods/y/exec", http.StatusForbidden},
		{"GET", "/api/v1/namespaces/x/pods/y/log", http.StatusOK},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s %s -> %d, want %d", c.method, c.path, rec.Code, c.want)
		}
	}
}
