package k8s

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	utilproxy "k8s.io/apimachinery/pkg/util/proxy"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/transport"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// Proxy is an in-process HTTP server that fronts one or more upstream
// Kubernetes API servers, plus a kubeconfig pointing at it.
type Proxy struct {
	server   *http.Server
	listener net.Listener
	Dir      string
	Path     string
}

type proxyEntry struct {
	name      string
	namespace string
}

// Rule controls which source kubeconfig contexts are exposed. Pattern uses
// path.Match syntax. Mode is applied only to allowed contexts.
type Rule struct {
	Action  string
	Mode    Mode
	Pattern string
}

type resolvedContext struct {
	name string
	mode Mode
}

// Mode controls request filtering applied at the embedded server.
type Mode int

const (
	ModeReadWrite Mode = iota
	ModeReadOnly
)

// ParseMode parses "rw" / "r" (case-insensitive). Empty is ReadWrite.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(s) {
	case "", "rw":
		return ModeReadWrite, nil
	case "r":
		return ModeReadOnly, nil
	}
	return 0, fmt.Errorf("invalid k8s mode %q (must be rw or r)", s)
}

// Start binds a single localhost port and serves a path-prefix-routed proxy
// for the contexts allowed by rules. Rules are first-match-wins; an empty rule
// list exposes every context read/write, with kubectl's current-context first.
// If no kubeconfig is found and no rules were explicitly requested, Start
// returns (nil, nil) so callers can skip the proxy entirely.
func Start(rules []Rule) (*Proxy, error) {
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	raw, err := loading.Load()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	if len(raw.Contexts) == 0 {
		if len(rules) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("no contexts found in kubeconfig")
	}

	available := make([]string, 0, len(raw.Contexts))
	for name := range raw.Contexts {
		available = append(available, name)
	}
	sort.Strings(available)

	var resolved []resolvedContext
	if len(rules) == 0 {
		resolved = make([]resolvedContext, 0, len(available))
		ordered := available
		if cur := raw.CurrentContext; cur != "" {
			ordered = moveToFront(ordered, cur)
		}
		for _, name := range ordered {
			resolved = append(resolved, resolvedContext{name: name, mode: ModeReadWrite})
		}
	} else {
		resolved, err = resolveRules(rules, available, raw.CurrentContext)
		if err != nil {
			return nil, err
		}
	}

	handlers := map[string]http.Handler{}
	var entries []proxyEntry
	for _, r := range resolved {
		ctx := raw.Contexts[r.name]
		cfg, err := clientcmd.NewNonInteractiveClientConfig(*raw, r.name, &clientcmd.ConfigOverrides{}, loading).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("context %q: %w", r.name, err)
		}
		h, err := contextHandler(cfg)
		if err != nil {
			return nil, fmt.Errorf("context %q: %w", r.name, err)
		}
		if r.mode == ModeReadOnly {
			h = readOnlyMiddleware(h)
		}
		handlers[r.name] = h
		entries = append(entries, proxyEntry{name: r.name, namespace: ctx.Namespace})
	}
	router := &router{handlers: handlers}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	addr := listener.Addr().String()
	server := &http.Server{Handler: router}
	go func() { _ = server.Serve(listener) }()

	dir, err := os.MkdirTemp("", "sbx-kubeconfig-")
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	cfgPath := filepath.Join(dir, "config")
	if err := os.WriteFile(cfgPath, []byte(buildKubeconfig(addr, entries)), 0o600); err != nil {
		_ = listener.Close()
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &Proxy{server: server, listener: listener, Dir: dir, Path: cfgPath}, nil
}

// expandContexts resolves each pattern against the available kubeconfig
// context names. Patterns may be exact names or globs (path.Match syntax).
// Within a single glob, matches are returned alphabetically; across patterns,
// input order is preserved with duplicates dropped (first occurrence wins).
// Returns an error when a literal name is unknown or a glob matches nothing.
func expandContexts(patterns, available []string) ([]string, error) {
	seen := make(map[string]struct{}, len(patterns))
	var out []string
	add := func(name string) {
		if _, dup := seen[name]; dup {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	for _, pattern := range patterns {
		if !isGlobPattern(pattern) {
			if !contains(available, pattern) {
				return nil, fmt.Errorf("context %q not found in kubeconfig", pattern)
			}
			add(pattern)
			continue
		}
		var matched []string
		for _, name := range available {
			ok, err := path.Match(pattern, name)
			if err != nil {
				return nil, fmt.Errorf("invalid context pattern %q: %w", pattern, err)
			}
			if ok {
				matched = append(matched, name)
			}
		}
		if len(matched) == 0 {
			return nil, fmt.Errorf("no contexts matched pattern %q", pattern)
		}
		sort.Strings(matched)
		for _, name := range matched {
			add(name)
		}
	}
	return out, nil
}

func resolveRules(rules []Rule, available []string, current string) ([]resolvedContext, error) {
	ordered := available
	if current != "" {
		ordered = moveToFront(ordered, current)
	}
	matchedRules := make([]bool, len(rules))
	var out []resolvedContext
	for _, name := range ordered {
		for i, rule := range rules {
			ok, err := path.Match(rule.Pattern, name)
			if err != nil {
				return nil, fmt.Errorf("invalid context pattern %q: %w", rule.Pattern, err)
			}
			if !ok {
				continue
			}
			matchedRules[i] = true
			if rule.Action == "allow" {
				out = append(out, resolvedContext{name: name, mode: rule.Mode})
			}
			break
		}
	}
	for i, rule := range rules {
		if rule.Action == "allow" && !matchedRules[i] {
			return nil, fmt.Errorf("no contexts matched pattern %q", rule.Pattern)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no contexts allowed by k8s rules")
	}
	return out, nil
}

func isGlobPattern(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// contextHandler builds an UpgradeAwareHandler — same proxy implementation
// kubectl proxy uses — so log streaming, exec/attach (SPDY/websocket upgrade),
// and port-forward all pass through.
func contextHandler(cfg *rest.Config) (http.Handler, error) {
	target, err := url.Parse(cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}
	// UpgradeAwareHandler issues a 301 to req.Path+"/" when Location.Path is
	// empty, which breaks our path-prefix routing (the client follows the
	// redirect back to /<rest>/ instead of /contexts/<name>/<rest>/).
	if target.Path == "" {
		target.Path = "/"
	}
	rt, err := rest.TransportFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	upgrade, err := upgradeTransport(cfg)
	if err != nil {
		return nil, fmt.Errorf("upgrade transport: %w", err)
	}
	h := utilproxy.NewUpgradeAwareHandler(target, rt, false, false, errResponder{})
	h.UpgradeTransport = upgrade
	h.UseRequestLocation = true
	h.UseLocationHost = true
	return h, nil
}

func upgradeTransport(cfg *rest.Config) (utilproxy.UpgradeRequestRoundTripper, error) {
	tc, err := cfg.TransportConfig()
	if err != nil {
		return nil, err
	}
	tlsConfig, err := transport.TLSConfigFor(tc)
	if err != nil {
		return nil, err
	}
	rt := utilnet.SetOldTransportDefaults(&http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	})
	authed, err := transport.HTTPWrappersForConfig(tc, utilproxy.MirrorRequest)
	if err != nil {
		return nil, err
	}
	return utilproxy.NewUpgradeRequestRoundTripper(rt, authed), nil
}

func buildKubeconfig(addr string, entries []proxyEntry) string {
	var b strings.Builder
	b.WriteString("apiVersion: v1\n")
	b.WriteString("kind: Config\n")
	b.WriteString("clusters:\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "- name: %s\n", e.name)
		b.WriteString("  cluster:\n")
		fmt.Fprintf(&b, "    server: http://%s/contexts/%s\n", addr, url.PathEscape(e.name))
	}
	b.WriteString("contexts:\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "- name: %s\n", e.name)
		b.WriteString("  context:\n")
		fmt.Fprintf(&b, "    cluster: %s\n", e.name)
		if e.namespace != "" {
			fmt.Fprintf(&b, "    namespace: %s\n", e.namespace)
		}
	}
	fmt.Fprintf(&b, "current-context: %s\n", entries[0].name)
	return b.String()
}

// Stop shuts down the embedded server and removes the temporary kubeconfig.
// Idempotent.
func (p *Proxy) Stop() {
	if p == nil {
		return
	}
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = p.server.Shutdown(ctx)
		p.server = nil
	}
	if p.listener != nil {
		_ = p.listener.Close()
		p.listener = nil
	}
	if p.Dir != "" {
		_ = os.RemoveAll(p.Dir)
		p.Dir = ""
	}
}

// router dispatches /contexts/<name>/<rest> to the matching upstream handler,
// stripping the context prefix so the upstream sees just the API path.
type router struct {
	handlers map[string]http.Handler
}

func (r *router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	const root = "/contexts/"
	// Read from the encoded form so escaped slashes inside context names
	// (e.g. AWS EKS ARN ".../cluster/foo") aren't mistaken for separators.
	rawPath := req.URL.RawPath
	if rawPath == "" {
		rawPath = req.URL.Path
	}
	if !strings.HasPrefix(rawPath, root) {
		http.NotFound(w, req)
		return
	}
	rest := rawPath[len(root):]
	var encName, encTail string
	if slash := strings.Index(rest, "/"); slash < 0 {
		encName = rest
		encTail = "/"
	} else {
		encName = rest[:slash]
		encTail = rest[slash:]
	}
	name, err := url.PathUnescape(encName)
	if err != nil {
		http.NotFound(w, req)
		return
	}
	h, ok := r.handlers[name]
	if !ok {
		http.NotFound(w, req)
		return
	}
	tail, err := url.PathUnescape(encTail)
	if err != nil {
		http.NotFound(w, req)
		return
	}
	r2 := req.Clone(req.Context())
	r2.URL.Path = tail
	r2.URL.RawPath = ""
	if encTail != tail {
		r2.URL.RawPath = encTail
	}
	h.ServeHTTP(w, r2)
}

type errResponder struct{}

func (errResponder) Error(w http.ResponseWriter, _ *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusBadGateway)
}

func readOnlyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			http.Error(w, "method not allowed in read-only mode", http.StatusForbidden)
			return
		}
		// Block subresource paths that perform mutations even via GET upgrades.
		if subresourceBlocked(r.URL.Path) {
			http.Error(w, "subresource not allowed in read-only mode", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func subresourceBlocked(p string) bool {
	for _, suf := range []string{"/exec", "/attach", "/portforward", "/proxy"} {
		if strings.HasSuffix(p, suf) || strings.Contains(p, suf+"/") {
			return true
		}
	}
	return false
}

func moveToFront(list []string, target string) []string {
	idx := -1
	for i, s := range list {
		if s == target {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return list
	}
	out := make([]string, 0, len(list))
	out = append(out, target)
	out = append(out, list[:idx]...)
	out = append(out, list[idx+1:]...)
	return out
}
