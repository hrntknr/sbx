package sshproxy

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	for _, want := range []string{"exec '/usr/bin/ssh' -F '", "\"$@\""} {
		if !strings.Contains(string(sshScript), want) {
			t.Errorf("ssh script missing %q\n%s", want, sshScript)
		}
	}
	if strings.Contains(string(sshConfig), "ProxyCommand") || strings.Contains(string(sshScript), "__sbx-ssh-connect") || strings.Contains(string(sshScript), "SBX_SSH_TARGET") {
		t.Errorf("injected files should not depend on sbx helper\nconfig:\n%s\nscript:\n%s", sshConfig, sshScript)
	}
}
