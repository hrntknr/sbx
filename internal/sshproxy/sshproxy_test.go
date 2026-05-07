package sshproxy

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrntknr/sbx/internal/config"
)

func TestHostAllowed(t *testing.T) {
	rules := []config.SSHRule{
		{Action: "deny", Pattern: "blocked.example.com"},
		{Action: "allow", Pattern: "*.example.com"},
	}
	cases := []struct {
		host string
		want bool
	}{
		{"blocked.example.com", false},
		{"prod.example.com", true},
		{"example.net", false},
	}
	for _, c := range cases {
		if got := hostAllowed(c.host, rules); got != c.want {
			t.Errorf("hostAllowed(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestHostAllowedEmptyRulesAllowsAll(t *testing.T) {
	if !hostAllowed("anything.example.com", nil) {
		t.Fatal("empty host rules should allow all hosts")
	}
}

func TestParseSSHConfigOutput(t *testing.T) {
	got := parseSSHConfigOutput("user deploy\nhostname prod.example.com\nport 2222\n")
	if got["user"] != "deploy" || got["hostname"] != "prod.example.com" || got["port"] != "2222" {
		t.Fatalf("parseSSHConfigOutput = %+v", got)
	}
}

func TestWriteInjectedFiles(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{
		Dir:      dir,
		BinDir:   binDir,
		listener: listener,
		realSSH:  "/usr/bin/ssh",
		sentinel: "nobody",
		port:     port,
	}
	if err := p.writeInjectedFiles(); err != nil {
		t.Fatal(err)
	}
	sshConfig, err := os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"HostName 127.0.0.1",
		"User nobody",
		"Port " + port,
		"SetEnv SBX_SSH_TARGET=%n SBX_SSH_PORT=%p",
		"PreferredAuthentications none",
		"LogLevel ERROR",
		"UserKnownHostsFile /dev/null",
	} {
		if !strings.Contains(string(sshConfig), want) {
			t.Errorf("ssh config missing %q\n%s", want, sshConfig)
		}
	}
	sshScript, err := os.ReadFile(filepath.Join(binDir, "ssh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"exec '/usr/bin/ssh' -F '", "' -p '", "\"$@\""} {
		if !strings.Contains(string(sshScript), want) {
			t.Errorf("ssh script missing %q\n%s", want, sshScript)
		}
	}
	if strings.Contains(string(sshConfig), "ProxyCommand") || strings.Contains(string(sshScript), "__sbx-ssh-connect") {
		t.Errorf("injected files should not depend on sbx helper\nconfig:\n%s\nscript:\n%s", sshConfig, sshScript)
	}
}

func TestInjectedSSHWrapperForcesProxyPort(t *testing.T) {
	dir := t.TempDir()
	fakeSSH := filepath.Join(dir, "real-ssh")
	argsPath := filepath.Join(dir, "args")
	if err := os.WriteFile(fakeSSH, []byte("#!/bin/sh\nfor arg do printf '<%s>\\n' \"$arg\"; done > "+shellQuote(argsPath)+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := &Proxy{Dir: dir, BinDir: filepath.Join(dir, "bin"), realSSH: fakeSSH, sentinel: "nobody", port: "41521"}
	if err := os.Mkdir(p.BinDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := p.writeInjectedFiles(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(p.BinDir, "ssh"), "-l", "git", "-p", "2222", "github.com")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(args)
	for _, want := range []string{"<-F>", "<" + filepath.Join(dir, "config") + ">", "<-p>", "<41521>", "<-l>", "<git>", "<github.com>"} {
		if !strings.Contains(got, want) {
			t.Errorf("wrapper args missing %q\n%s", want, got)
		}
	}
	if strings.Index(got, "<41521>") > strings.Index(got, "<2222>") {
		t.Errorf("proxy port should be passed before user port so OpenSSH keeps proxy connection\n%s", got)
	}
}

func TestSSHConfigQuote(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"plain", "plain"},
		{"", `""`},
		{"with space", `"with space"`},
		{"tab\there", "\"tab\there\""},
		{`a"b`, `"a\"b"`},
		{`a\b`, `"a\\b"`},
	}
	for _, c := range cases {
		if got := sshConfigQuote(c.in); got != c.out {
			t.Errorf("sshConfigQuote(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

func TestStopClosesActiveConn(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not available")
	}
	p, err := Start(Options{})
	if err != nil {
		t.Fatal(err)
	}
	addr := p.listener.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		p.Stop()
		t.Fatal(err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		n := len(p.conns)
		p.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	done := make(chan struct{})
	go func() { p.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return — likely hanging on active conn")
	}
}
