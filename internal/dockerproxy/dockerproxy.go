package dockerproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/docker/go-connections/sockets"

	"github.com/hrntknr/sbx/internal/config"
)

type Mode int

const (
	ModeReadWrite Mode = iota
	ModeReadOnly
)

type Rule struct {
	Action  string
	Mode    Mode
	Pattern string
}

type SourceContext struct {
	Name string
	Host string
}

type Proxy struct {
	Dir string

	servers   []*http.Server
	listeners []net.Listener
}

type resolvedContext struct {
	SourceContext
	Mode         Mode
	Sock         string
	NameInConfig string
}

type dockerConfig struct {
	CurrentContext string                     `json:"currentContext,omitempty"`
	Auths          map[string]json.RawMessage `json:"auths,omitempty"`
	CredsStore     string                     `json:"credsStore,omitempty"`
	CredHelpers    map[string]string          `json:"credHelpers,omitempty"`
}

type metaFile struct {
	Name      string              `json:"Name"`
	Metadata  map[string]string   `json:"Metadata"`
	Endpoints map[string]endpoint `json:"Endpoints"`
}

type endpoint struct {
	Host          string `json:"Host"`
	SkipTLSVerify bool   `json:"SkipTLSVerify,omitempty"`
}

func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(s) {
	case "", "rw":
		return ModeReadWrite, nil
	case "r":
		return ModeReadOnly, nil
	}
	return 0, fmt.Errorf("invalid docker mode %q (must be rw or r)", s)
}

func Start(rules []Rule) (*Proxy, error) {
	sources, current, sourceConfig, err := loadContexts("")
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return disabledProxy()
	}
	return startWithContexts(sources, current, rules, sourceConfig)
}

func LoadContexts(dockerDir string) ([]SourceContext, string, error) {
	sources, current, _, err := loadContexts(dockerDir)
	return sources, current, err
}

func loadContexts(dockerDir string) ([]SourceContext, string, dockerConfig, error) {
	if dockerDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, "", dockerConfig{}, err
		}
		dockerDir = filepath.Join(home, ".docker")
	}
	current := "default"
	var cfg dockerConfig
	if data, err := os.ReadFile(filepath.Join(dockerDir, "config.json")); err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, "", dockerConfig{}, fmt.Errorf("load docker config: %w", err)
		}
		if cfg.CurrentContext != "" {
			current = cfg.CurrentContext
		}
	} else if !os.IsNotExist(err) {
		return nil, "", dockerConfig{}, err
	}

	var contexts []SourceContext
	defaultHost := "unix:///var/run/docker.sock"
	if host := os.Getenv("DOCKER_HOST"); host != "" {
		defaultHost = host
	}
	if !defaultHostUsesTLS(defaultHost) {
		contexts = append(contexts, SourceContext{Name: "default", Host: defaultHost})
	}
	metaRoot := filepath.Join(dockerDir, "contexts", "meta")
	entries, err := os.ReadDir(metaRoot)
	if err != nil && !os.IsNotExist(err) {
		return nil, "", dockerConfig{}, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(metaRoot, e.Name(), "meta.json"))
		if err != nil {
			return nil, "", dockerConfig{}, err
		}
		var meta metaFile
		if err := json.Unmarshal(data, &meta); err != nil {
			return nil, "", dockerConfig{}, fmt.Errorf("load docker context %s: %w", e.Name(), err)
		}
		if ep, ok := meta.Endpoints["docker"]; ok && meta.Name != "" && !ep.SkipTLSVerify && !hasTLSMaterial(dockerDir, e.Name()) {
			contexts = append(contexts, SourceContext{Name: meta.Name, Host: ep.Host})
		}
	}
	if envContext := os.Getenv("DOCKER_CONTEXT"); envContext != "" {
		current = envContext
	}
	sort.Slice(contexts, func(i, j int) bool { return contexts[i].Name < contexts[j].Name })
	return contexts, current, cfg, nil
}

func StartWithContexts(sources []SourceContext, current string, rules []Rule) (*Proxy, error) {
	return startWithContexts(sources, current, rules, dockerConfig{})
}

func startWithContexts(sources []SourceContext, current string, rules []Rule, sourceConfig dockerConfig) (*Proxy, error) {
	resolved, err := Resolve(sources, current, rules)
	if err != nil {
		return nil, err
	}
	if len(resolved) == 0 {
		return disabledProxy()
	}
	dir, err := os.MkdirTemp("", "sbx-docker-")
	if err != nil {
		return nil, err
	}
	p := &Proxy{Dir: dir}
	if err := p.start(resolved, sourceConfig); err != nil {
		p.Stop()
		return nil, err
	}
	return p, nil
}

func disabledProxy() (*Proxy, error) {
	dir, err := os.MkdirTemp("", "sbx-docker-")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}\n"), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &Proxy{Dir: dir}, nil
}

func Resolve(sources []SourceContext, current string, rules []Rule) ([]resolvedContext, error) {
	available := make([]SourceContext, 0, len(sources))
	for _, src := range sources {
		if supportedHost(src.Host) {
			available = append(available, src)
		}
	}
	sort.Slice(available, func(i, j int) bool { return available[i].Name < available[j].Name })
	available = moveToFront(available, current)

	var out []resolvedContext
	if len(rules) == 0 {
		for _, src := range available {
			out = append(out, resolvedContext{SourceContext: src, Mode: ModeReadWrite})
		}
		return out, nil
	}
	for _, src := range available {
		for _, rule := range rules {
			ok, err := path.Match(rule.Pattern, src.Name)
			if err != nil {
				return nil, fmt.Errorf("invalid docker context pattern %q: %w", rule.Pattern, err)
			}
			if !ok {
				continue
			}
			if rule.Action == "allow" {
				if !modeSupportedForHost(src.Host, rule.Mode) {
					return nil, fmt.Errorf("docker context %q uses %q, which only supports rw mode", src.Name, src.Host)
				}
				out = append(out, resolvedContext{SourceContext: src, Mode: rule.Mode})
			}
			break
		}
	}
	return out, nil
}

func (p *Proxy) start(resolved []resolvedContext, sourceConfig dockerConfig) error {
	sockDir := filepath.Join(p.Dir, "sockets")
	if err := os.Mkdir(sockDir, 0o700); err != nil {
		return err
	}
	assignConfigNames(resolved)
	for i := range resolved {
		resolved[i].Sock = filepath.Join(sockDir, fmt.Sprintf("%d.sock", i))
		if err := p.startOne(resolved[i]); err != nil {
			return err
		}
	}
	return writeDockerConfig(p.Dir, resolved, sourceConfig)
}

func (p *Proxy) startOne(ctx resolvedContext) error {
	listener, err := net.Listen("unix", ctx.Sock)
	if err != nil {
		return err
	}
	h, err := reverseProxy(ctx.Host)
	if err != nil {
		_ = listener.Close()
		return err
	}
	if ctx.Mode == ModeReadOnly {
		h = readOnlyMiddleware(h)
	}
	server := &http.Server{Handler: h}
	p.listeners = append(p.listeners, listener)
	p.servers = append(p.servers, server)
	go func() { _ = server.Serve(listener) }()
	return nil
}

func WriteDockerConfig(dir string, resolved []resolvedContext) error {
	return writeDockerConfig(dir, resolved, dockerConfig{})
}

func writeDockerConfig(dir string, resolved []resolvedContext, sourceConfig dockerConfig) error {
	assignConfigNames(resolved)
	cfg := dockerConfig{
		CurrentContext: resolved[0].NameInConfig,
		Auths:          sourceConfig.Auths,
		CredsStore:     sourceConfig.CredsStore,
		CredHelpers:    sourceConfig.CredHelpers,
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), append(data, '\n'), 0o600); err != nil {
		return err
	}
	for _, ctx := range resolved {
		metaDir := filepath.Join(dir, "contexts", "meta", contextID(ctx.NameInConfig))
		if err := os.MkdirAll(metaDir, 0o700); err != nil {
			return err
		}
		meta := metaFile{
			Name:      ctx.NameInConfig,
			Metadata:  map[string]string{},
			Endpoints: map[string]endpoint{"docker": {Host: "unix://" + ctx.Sock}},
		}
		data, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(metaDir, "meta.json"), append(data, '\n'), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func reverseProxy(host string) (http.Handler, error) {
	proto, addr, target, err := proxyTarget(host)
	if err != nil {
		return nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	tr := &http.Transport{}
	if err := sockets.ConfigureTransport(tr, proto, addr); err != nil {
		return nil, err
	}
	rp.Transport = tr
	return rp, nil
}

func proxyTarget(host string) (proto, addr string, target *url.URL, err error) {
	u, err := url.Parse(host)
	if err != nil {
		return "", "", nil, fmt.Errorf("parse docker host %q: %w", host, err)
	}
	switch u.Scheme {
	case "unix":
		if u.Path == "" {
			return "", "", nil, fmt.Errorf("invalid docker unix host %q", host)
		}
		return "unix", u.Path, &url.URL{Scheme: "http", Host: "docker"}, nil
	case "tcp":
		if u.Host == "" {
			return "", "", nil, fmt.Errorf("invalid docker tcp host %q", host)
		}
		return "tcp", u.Host, &url.URL{Scheme: "http", Host: u.Host}, nil
	case "http":
		if u.Host == "" {
			return "", "", nil, fmt.Errorf("invalid docker http host %q", host)
		}
		return "tcp", u.Host, &url.URL{Scheme: "http", Host: u.Host}, nil
	}
	return "", "", nil, fmt.Errorf("unsupported docker host %q", host)
}

func supportedHost(host string) bool {
	_, _, _, err := proxyTarget(host)
	return err == nil
}

func modeSupportedForHost(host string, mode Mode) bool {
	if mode == ModeReadWrite {
		return true
	}
	return strings.HasPrefix(host, "unix://")
}

func ReadOnlyMiddleware(next http.Handler) http.Handler { return readOnlyMiddleware(next) }

func readOnlyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed in read-only mode", http.StatusForbidden)
			return
		}
		if dangerousReadPath(r.URL.Path) {
			http.Error(w, "endpoint not allowed in read-only mode", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func dangerousReadPath(p string) bool {
	parts := pathParts(p)
	for _, part := range parts {
		if part == "archive" || part == "export" || part == "attach" || part == "exec" {
			return true
		}
	}
	if len(parts) >= 2 && parts[0] == "images" && (parts[1] == "get" || parts[len(parts)-1] == "get") {
		return true
	}
	return false
}

func pathParts(p string) []string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) > 0 && strings.HasPrefix(parts[0], "v") {
		parts = parts[1:]
	}
	return parts
}

func (p *Proxy) Stop() {
	if p == nil {
		return
	}
	for _, server := range p.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = server.Shutdown(ctx)
		cancel()
	}
	for _, listener := range p.listeners {
		_ = listener.Close()
	}
	if p.Dir != "" {
		_ = os.RemoveAll(p.Dir)
		p.Dir = ""
	}
}

func configName(name string) string {
	if name == "default" {
		return "sbx-default"
	}
	return name
}

func assignConfigNames(resolved []resolvedContext) {
	used := map[string]bool{}
	for i := range resolved {
		base := configName(resolved[i].Name)
		name := base
		if used[name] {
			name = base + "-" + contextID(resolved[i].Name)[:12]
		}
		for used[name] {
			name += "-x"
		}
		resolved[i].NameInConfig = name
		used[name] = true
	}
}

func hasTLSMaterial(dockerDir, id string) bool {
	entries, err := os.ReadDir(filepath.Join(dockerDir, "contexts", "tls", id))
	return err == nil && len(entries) > 0
}

func defaultHostUsesTLS(host string) bool {
	if strings.HasPrefix(host, "unix://") {
		return false
	}
	return os.Getenv("DOCKER_TLS_VERIFY") != "" || os.Getenv("DOCKER_CERT_PATH") != ""
}

func contextID(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

func moveToFront(list []SourceContext, target string) []SourceContext {
	idx := -1
	for i, s := range list {
		if s.Name == target {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return list
	}
	out := make([]SourceContext, 0, len(list))
	out = append(out, list[idx])
	out = append(out, list[:idx]...)
	out = append(out, list[idx+1:]...)
	return out
}

func RulesFromConfig(rules []config.DockerRule) ([]Rule, error) {
	out := make([]Rule, len(rules))
	for i, rule := range rules {
		mode, err := ParseMode(rule.Mode)
		if err != nil {
			return nil, err
		}
		out[i] = Rule{Action: rule.Action, Mode: mode, Pattern: rule.Pattern}
	}
	return out, nil
}
