package dockerproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveEmptyRulesExposeUnixContextsCurrentFirst(t *testing.T) {
	sources := []SourceContext{
		{Name: "prod", Host: "unix:///tmp/prod.sock"},
		{Name: "remote", Host: "tcp://example.com:2376"},
		{Name: "dev", Host: "unix:///tmp/dev.sock"},
	}
	got, err := Resolve(sources, "prod", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 3 || got[0].Name != "prod" || got[1].Name != "dev" || got[2].Name != "remote" {
		t.Fatalf("resolved order = %+v, want prod, dev, remote", got)
	}
	for _, ctx := range got {
		if ctx.Mode != ModeReadWrite {
			t.Fatalf("%s mode = %v, want rw", ctx.Name, ctx.Mode)
		}
	}
}

func TestResolveFirstMatchWins(t *testing.T) {
	sources := []SourceContext{
		{Name: "prod", Host: "unix:///tmp/prod.sock"},
		{Name: "dev", Host: "unix:///tmp/dev.sock"},
	}
	rules := []Rule{
		{Action: "allow", Mode: ModeReadOnly, Pattern: "*"},
		{Action: "deny", Mode: ModeReadWrite, Pattern: "prod"},
	}
	got, err := Resolve(sources, "", rules)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 2 || got[1].Name != "prod" || got[1].Mode != ModeReadOnly {
		t.Fatalf("first-match result = %+v", got)
	}
}

func TestResolveRejectsReadOnlyTCPContext(t *testing.T) {
	sources := []SourceContext{{Name: "remote", Host: "tcp://example.com:2375"}}
	_, err := Resolve(sources, "", []Rule{{Action: "allow", Mode: ModeReadOnly, Pattern: "remote"}})
	if err == nil {
		t.Fatal("expected read-only tcp context to be rejected")
	}
}

func TestStartWithContextsDenyAllFailsClosed(t *testing.T) {
	proxy, err := StartWithContexts([]SourceContext{{Name: "dev", Host: "unix:///tmp/dev.sock"}}, "dev", []Rule{{Action: "deny", Mode: ModeReadWrite, Pattern: "*"}})
	if err != nil {
		t.Fatalf("StartWithContexts: %v", err)
	}
	defer proxy.Stop()
	if proxy.Dir == "" {
		t.Fatal("disabled proxy should still provide an empty DOCKER_CONFIG dir")
	}
}

func TestStartWithContextsUsesShortSocketPaths(t *testing.T) {
	proxy, err := StartWithContexts([]SourceContext{{Name: "dev", Host: "unix:///tmp/dev.sock"}}, "dev", nil)
	if err != nil {
		t.Fatalf("StartWithContexts: %v", err)
	}
	defer proxy.Stop()

	data, err := os.ReadFile(filepath.Join(proxy.Dir, "contexts", "meta", contextID("dev"), "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta metaFile
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatal(err)
	}
	sock := strings.TrimPrefix(meta.Endpoints["docker"].Host, "unix://")
	if len(sock) >= 100 {
		t.Fatalf("socket path length = %d, want less than 100: %s", len(sock), sock)
	}
}

func TestLoadContextsAndWriteDockerConfig(t *testing.T) {
	dockerDir := t.TempDir()
	writeJSON(t, filepath.Join(dockerDir, "config.json"), dockerConfig{CurrentContext: "dev"})
	writeJSON(t, filepath.Join(dockerDir, "contexts", "meta", "one", "meta.json"), metaFile{
		Name:      "dev",
		Metadata:  map[string]string{},
		Endpoints: map[string]endpoint{"docker": {Host: "unix:///tmp/dev.sock"}},
	})
	writeJSON(t, filepath.Join(dockerDir, "contexts", "meta", "two", "meta.json"), metaFile{
		Name:      "remote",
		Metadata:  map[string]string{},
		Endpoints: map[string]endpoint{"docker": {Host: "tcp://example.com:2376"}},
	})
	writeJSON(t, filepath.Join(dockerDir, "contexts", "meta", "tls", "meta.json"), metaFile{
		Name:      "tls-remote",
		Metadata:  map[string]string{},
		Endpoints: map[string]endpoint{"docker": {Host: "tcp://example.com:2376"}},
	})
	if err := os.MkdirAll(filepath.Join(dockerDir, "contexts", "tls", "tls", "docker"), 0o700); err != nil {
		t.Fatal(err)
	}

	sources, current, err := LoadContexts(dockerDir)
	if err != nil {
		t.Fatalf("LoadContexts: %v", err)
	}
	if current != "dev" {
		t.Fatalf("current = %q, want dev", current)
	}
	resolved, err := Resolve(sources, current, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resolved) != 3 || resolved[0].Name != "dev" || resolved[1].Name != "default" || resolved[2].Name != "remote" {
		t.Fatalf("resolved = %+v, want dev, default, and remote", resolved)
	}
	for i := range resolved {
		resolved[i].Sock = filepath.Join(t.TempDir(), resolved[i].Name+".sock")
	}
	outDir := t.TempDir()
	if err := WriteDockerConfig(outDir, resolved); err != nil {
		t.Fatalf("WriteDockerConfig: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg dockerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.CurrentContext != "dev" {
		t.Fatalf("generated current = %q, want dev", cfg.CurrentContext)
	}
	metaPath := filepath.Join(outDir, "contexts", "meta", contextID("dev"), "meta.json")
	data, err = os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	var meta metaFile
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Endpoints["docker"].Host != "unix://"+resolved[0].Sock {
		t.Fatalf("generated host = %q, want proxy sock", meta.Endpoints["docker"].Host)
	}
	defaultMetaPath := filepath.Join(outDir, "contexts", "meta", contextID("sbx-default"), "meta.json")
	data, err = os.ReadFile(defaultMetaPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Name != "sbx-default" {
		t.Fatalf("default context alias = %q, want sbx-default", meta.Name)
	}
}

func TestLoadContextsSynthesizesDefaultHost(t *testing.T) {
	dockerDir := t.TempDir()
	sources, current, err := LoadContexts(dockerDir)
	if err != nil {
		t.Fatalf("LoadContexts: %v", err)
	}
	if current != "default" {
		t.Fatalf("current = %q, want default", current)
	}
	if len(sources) != 1 || sources[0] != (SourceContext{Name: "default", Host: "unix:///var/run/docker.sock"}) {
		t.Fatalf("sources = %+v, want synthesized default", sources)
	}
}

func TestLoadContextsUsesExplicitDockerHostAsDefault(t *testing.T) {
	dockerDir := t.TempDir()
	t.Setenv("DOCKER_HOST", "unix:///tmp/docker.sock")
	sources, _, err := LoadContexts(dockerDir)
	if err != nil {
		t.Fatalf("LoadContexts: %v", err)
	}
	if len(sources) != 1 || sources[0] != (SourceContext{Name: "default", Host: "unix:///tmp/docker.sock"}) {
		t.Fatalf("sources = %+v, want explicit default from DOCKER_HOST", sources)
	}
}

func TestLoadContextsSkipsTLSDefaultHost(t *testing.T) {
	dockerDir := t.TempDir()
	t.Setenv("DOCKER_HOST", "tcp://example.com:2376")
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	sources, _, err := LoadContexts(dockerDir)
	if err != nil {
		t.Fatalf("LoadContexts: %v", err)
	}
	for _, src := range sources {
		if src.Name == "default" {
			t.Fatalf("default TLS context should be skipped: %+v", sources)
		}
	}
}

func TestProxyTarget(t *testing.T) {
	for _, tc := range []struct {
		host       string
		wantProto  string
		wantAddr   string
		wantScheme string
		wantHost   string
	}{
		{"unix:///tmp/docker.sock", "unix", "/tmp/docker.sock", "http", "docker"},
		{"tcp://127.0.0.1:2375", "tcp", "127.0.0.1:2375", "http", "127.0.0.1:2375"},
		{"http://127.0.0.1:2375", "tcp", "127.0.0.1:2375", "http", "127.0.0.1:2375"},
	} {
		proto, addr, target, err := proxyTarget(tc.host)
		if err != nil {
			t.Fatalf("proxyTarget(%q): %v", tc.host, err)
		}
		if proto != tc.wantProto || addr != tc.wantAddr || target.Scheme != tc.wantScheme || target.Host != tc.wantHost {
			t.Fatalf("proxyTarget(%q) = (%q, %q, %s), want (%q, %q, %s://%s)", tc.host, proto, addr, target, tc.wantProto, tc.wantAddr, tc.wantScheme, tc.wantHost)
		}
	}
	if supportedHost("https://example.com:2376") {
		t.Fatal("https should be unsupported until TLS material handling is implemented")
	}
}

func TestWriteDockerConfigAliasesCurrentDefault(t *testing.T) {
	outDir := t.TempDir()
	resolved := []resolvedContext{{SourceContext: SourceContext{Name: "default", Host: "unix:///tmp/docker.sock"}, Sock: filepath.Join(t.TempDir(), "default.sock")}}
	if err := WriteDockerConfig(outDir, resolved); err != nil {
		t.Fatalf("WriteDockerConfig: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg dockerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.CurrentContext != "sbx-default" {
		t.Fatalf("current context = %q, want sbx-default", cfg.CurrentContext)
	}
}

func TestWriteDockerConfigAvoidsDefaultAliasCollision(t *testing.T) {
	outDir := t.TempDir()
	resolved := []resolvedContext{
		{SourceContext: SourceContext{Name: "default", Host: "unix:///tmp/docker.sock"}, Sock: filepath.Join(t.TempDir(), "default.sock")},
		{SourceContext: SourceContext{Name: "sbx-default", Host: "unix:///tmp/other.sock"}, Sock: filepath.Join(t.TempDir(), "other.sock")},
	}
	if err := WriteDockerConfig(outDir, resolved); err != nil {
		t.Fatalf("WriteDockerConfig: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "contexts", "meta", contextID("sbx-default"), "meta.json")); err != nil {
		t.Fatal(err)
	}
	alias := "sbx-default-" + contextID("sbx-default")[:12]
	if _, err := os.Stat(filepath.Join(outDir, "contexts", "meta", contextID(alias), "meta.json")); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlyMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := ReadOnlyMiddleware(next)

	for _, tc := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/v1.44/containers/json", http.StatusNoContent},
		{http.MethodHead, "/_ping", http.StatusNoContent},
		{http.MethodPost, "/v1.44/containers/create", http.StatusForbidden},
		{http.MethodGet, "/v1.44/containers/id/archive", http.StatusForbidden},
		{http.MethodGet, "/v1.44/images/id/export", http.StatusForbidden},
		{http.MethodGet, "/v1.44/images/id/get", http.StatusForbidden},
		{http.MethodGet, "/v1.44/images/get", http.StatusForbidden},
		{http.MethodGet, "/v1.44/containers/id/attach/ws", http.StatusForbidden},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Fatalf("%s %s = %d, want %d", tc.method, tc.path, rr.Code, tc.want)
		}
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
