package sshproxy

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"

	"github.com/hrntknr/sbx/internal/config"
)

const sentinelUser = "nobody"

// Options controls the SSH proxy exposed to the sandbox.
type Options struct {
	Rules []config.SSHRule
}

// Proxy is an in-process SSH MITM server plus injected ssh command/config.
type Proxy struct {
	Dir    string
	BinDir string

	listener net.Listener
	server   *ssh.ServerConfig
	done     chan struct{}
	wg       sync.WaitGroup
	realSSH  string
	rules    []config.SSHRule
	sentinel string
	port     string

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	cmds   map[*exec.Cmd]struct{}
}

type resolvedTarget struct {
	HostName string
	Port     string
	User     string
}

type ptyRequest struct {
	term string
	rows uint32
	cols uint32
}

// Start starts the proxy and writes the injected ssh command/config tree.
func Start(opts Options) (*Proxy, error) {
	realSSH, err := exec.LookPath("ssh")
	if err != nil {
		return nil, fmt.Errorf("find ssh: %w", err)
	}
	dir, err := os.MkdirTemp("", "sbx-ssh-")
	if err != nil {
		return nil, err
	}
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		_ = os.RemoveAll(dir)
		return nil, err
	}
	sentinel := sentinelUser
	server, err := serverConfig()
	if err != nil {
		_ = listener.Close()
		_ = os.RemoveAll(dir)
		return nil, err
	}
	p := &Proxy{
		Dir:      dir,
		BinDir:   binDir,
		listener: listener,
		server:   server,
		done:     make(chan struct{}),
		realSSH:  realSSH,
		rules:    opts.Rules,
		sentinel: sentinel,
		port:     port,
		conns:    map[net.Conn]struct{}{},
		cmds:     map[*exec.Cmd]struct{}{},
	}
	if err := p.writeInjectedFiles(); err != nil {
		p.Stop()
		return nil, err
	}
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

func serverConfig() (*ssh.ServerConfig, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	return cfg, nil
}

func (p *Proxy) trackConn(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *Proxy) untrackConn(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func (p *Proxy) trackCmd(c *exec.Cmd) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.cmds[c] = struct{}{}
	return true
}

func (p *Proxy) untrackCmd(c *exec.Cmd) {
	p.mu.Lock()
	delete(p.cmds, c)
	p.mu.Unlock()
}

func (p *Proxy) writeInjectedFiles() error {
	configPath := filepath.Join(p.Dir, "config")
	sshConfig := fmt.Sprintf(`Host *
  HostName 127.0.0.1
  User %s
  Port %s
  SetEnv SBX_SSH_TARGET=%%n SBX_SSH_PORT=%%p
  PreferredAuthentications none
  PubkeyAuthentication no
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  StrictHostKeyChecking no
  LogLevel ERROR
  UserKnownHostsFile /dev/null
  GlobalKnownHostsFile /dev/null
`, p.sentinel, p.port)
	if err := os.WriteFile(configPath, []byte(sshConfig), 0o600); err != nil {
		return err
	}
	sshPath := filepath.Join(p.BinDir, "ssh")
	sshScript := fmt.Sprintf(`#!/bin/sh
exec %s -F %s -p %s "$@"
`, shellQuote(p.realSSH), shellQuote(configPath), shellQuote(p.port))
	return os.WriteFile(sshPath, []byte(sshScript), 0o700)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// sshConfigQuote quotes a value for use in an OpenSSH SetEnv directive,
// which is parsed via argv_split (whitespace-separated, double-quote aware).
// Empty strings, whitespace, double quotes, and backslashes require quoting.
func sshConfigQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String()
}

func (p *Proxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.done:
				return
			default:
				continue
			}
		}
		if !p.trackConn(conn) {
			_ = conn.Close()
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.untrackConn(conn)
			p.handleConn(conn)
		}()
	}
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()
	serverConn, chans, reqs, err := ssh.NewServerConn(conn, p.server)
	if err != nil {
		return
	}
	defer serverConn.Close()
	innerUser := serverConn.User()
	explicitUser := innerUser != "" && innerUser != p.sentinel
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go p.handleSession(channel, requests, innerUser, explicitUser)
	}
}

func (p *Proxy) resolve(host, port, innerUser string, explicitUser, explicitPort bool) (resolvedTarget, error) {
	args := []string{"-G"}
	if explicitUser {
		args = append(args, "-l", innerUser)
	}
	if explicitPort {
		args = append(args, "-p", port)
	}
	args = append(args, host)
	cmd := exec.Command(p.realSSH, args...)
	out, err := cmd.Output()
	if err != nil {
		return resolvedTarget{}, err
	}
	values := parseSSHConfigOutput(string(out))
	userName := values["user"]
	if explicitUser {
		userName = innerUser
	}
	if userName == "" {
		if u, err := user.Current(); err == nil {
			userName = u.Username
		}
	}
	hostName := values["hostname"]
	if hostName == "" {
		hostName = host
	}
	portValue := values["port"]
	if explicitPort {
		portValue = port
	}
	if portValue == "" {
		portValue = "22"
	}
	return resolvedTarget{HostName: hostName, Port: portValue, User: userName}, nil
}

func parseSSHConfigOutput(out string) map[string]string {
	values := map[string]string{}
	s := bufio.NewScanner(strings.NewReader(out))
	for s.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(s.Text()), " ")
		if ok {
			values[strings.ToLower(key)] = strings.TrimSpace(value)
		}
	}
	return values
}

func hostAllowed(host string, rules []config.SSHRule) bool {
	if len(rules) == 0 {
		return true
	}
	host = strings.ToLower(host)
	for _, r := range rules {
		ok, err := path.Match(strings.ToLower(r.Pattern), host)
		if err == nil && ok {
			return r.Action == "allow"
		}
	}
	return false
}

func (p *Proxy) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, innerUser string, explicitUser bool) {
	defer channel.Close()
	var ptyReq *ptyRequest
	var started bool
	env := map[string]string{}
	for req := range requests {
		switch req.Type {
		case "pty-req":
			payload, err := parsePTYRequest(req.Payload)
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			ptyReq = &payload
			req.Reply(true, nil)
		case "env":
			var payload struct{ Name, Value string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				req.Reply(false, nil)
				continue
			}
			env[payload.Name] = payload.Value
			req.Reply(true, nil)
		case "window-change":
			rows, cols, err := parseWindowChange(req.Payload)
			if err == nil && ptyReq != nil {
				ptyReq.rows = rows
				ptyReq.cols = cols
			}
			req.Reply(err == nil, nil)
		case "signal":
			req.Reply(true, nil)
		case "exec":
			command, err := parseStringPayload(req.Payload)
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			host, explicitPort, target, err := p.targetFromEnv(env, innerUser, explicitUser)
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			started = true
			p.runOuterSSH(channel, host, command, "", filteredEnv(env), ptyReq, explicitUser, explicitPort, target, requests)
			return
		case "shell":
			host, explicitPort, target, err := p.targetFromEnv(env, innerUser, explicitUser)
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			started = true
			p.runOuterSSH(channel, host, "", "", filteredEnv(env), ptyReq, explicitUser, explicitPort, target, requests)
			return
		case "subsystem":
			subsystem, err := parseStringPayload(req.Payload)
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			host, explicitPort, target, err := p.targetFromEnv(env, innerUser, explicitUser)
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			started = true
			p.runOuterSSH(channel, host, "", subsystem, filteredEnv(env), ptyReq, explicitUser, explicitPort, target, requests)
			return
		default:
			req.Reply(false, nil)
		}
	}
	if !started {
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))
	}
}

func parseStringPayload(payload []byte) (string, error) {
	if len(payload) < 4 {
		return "", errors.New("short payload")
	}
	n := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if n < 0 || len(payload) < 4+n {
		return "", errors.New("short string payload")
	}
	return string(payload[4 : 4+n]), nil
}

func parsePTYRequest(payload []byte) (ptyRequest, error) {
	term, rest, err := parseStringPrefix(payload)
	if err != nil {
		return ptyRequest{}, err
	}
	cols, rest, err := parseUint32Prefix(rest)
	if err != nil {
		return ptyRequest{}, err
	}
	rows, _, err := parseUint32Prefix(rest)
	if err != nil {
		return ptyRequest{}, err
	}
	return ptyRequest{term: term, rows: rows, cols: cols}, nil
}

func parseWindowChange(payload []byte) (uint32, uint32, error) {
	cols, rest, err := parseUint32Prefix(payload)
	if err != nil {
		return 0, 0, err
	}
	rows, _, err := parseUint32Prefix(rest)
	if err != nil {
		return 0, 0, err
	}
	return rows, cols, nil
}

func parseStringPrefix(payload []byte) (string, []byte, error) {
	if len(payload) < 4 {
		return "", nil, errors.New("short payload")
	}
	n := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if n < 0 || len(payload) < 4+n {
		return "", nil, errors.New("short string payload")
	}
	return string(payload[4 : 4+n]), payload[4+n:], nil
}

func parseUint32Prefix(payload []byte) (uint32, []byte, error) {
	if len(payload) < 4 {
		return 0, nil, errors.New("short uint32 payload")
	}
	v := uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
	return v, payload[4:], nil
}

func (p *Proxy) targetFromEnv(env map[string]string, innerUser string, explicitUser bool) (string, bool, resolvedTarget, error) {
	host := env["SBX_SSH_TARGET"]
	if host == "" {
		return "", false, resolvedTarget{}, errors.New("missing SBX_SSH_TARGET")
	}
	port := env["SBX_SSH_PORT"]
	explicitPort := port != "" && port != p.port
	target, err := p.resolve(host, port, innerUser, explicitUser, explicitPort)
	if err != nil {
		return "", false, resolvedTarget{}, err
	}
	if !hostAllowed(target.HostName, p.rules) {
		return "", false, resolvedTarget{}, fmt.Errorf("ssh host %q is not allowed", target.HostName)
	}
	return host, explicitPort, target, nil
}

func filteredEnv(env map[string]string) map[string]string {
	out := make(map[string]string, len(env))
	for k, v := range env {
		if strings.HasPrefix(k, "SBX_SSH_") {
			continue
		}
		out[k] = v
	}
	return out
}

func (p *Proxy) runOuterSSH(channel ssh.Channel, host, remoteCommand, subsystem string, env map[string]string, ptyReq *ptyRequest, explicitUser, explicitPort bool, target resolvedTarget, requests <-chan *ssh.Request) {
	args := []string{"-o", "BatchMode=yes"}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := env[k]
		args = append(args, "-o", "SetEnv="+k+"="+sshConfigQuote(v))
	}
	if ptyReq != nil {
		args = append(args, "-tt")
	} else {
		args = append(args, "-T")
	}
	if subsystem != "" {
		args = append(args, "-s")
	}
	if explicitUser {
		args = append(args, "-l", target.User)
	}
	if explicitPort {
		args = append(args, "-p", target.Port)
	}
	args = append(args, host)
	if subsystem != "" {
		args = append(args, subsystem)
	} else if remoteCommand != "" {
		args = append(args, remoteCommand)
	}
	cmd := exec.Command(p.realSSH, args...)
	if ptyReq != nil {
		p.runOuterSSHWithPTY(channel, cmd, ptyReq, requests)
		return
	}
	go discardSessionRequests(requests)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		sendExit(channel, 1)
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sendExit(channel, 1)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		sendExit(channel, 1)
		return
	}
	if !p.trackCmd(cmd) {
		sendExit(channel, 1)
		return
	}
	if err := cmd.Start(); err != nil {
		p.untrackCmd(cmd)
		sendExit(channel, 1)
		return
	}
	go func() { _, _ = io.Copy(stdin, channel); _ = stdin.Close() }()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(channel, stdout) }()
	go func() { defer wg.Done(); _, _ = io.Copy(channel.Stderr(), stderr) }()
	err = cmd.Wait()
	p.untrackCmd(cmd)
	_ = stdin.Close()
	wg.Wait()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	sendExit(channel, code)
}

func (p *Proxy) runOuterSSHWithPTY(channel ssh.Channel, cmd *exec.Cmd, ptyReq *ptyRequest, requests <-chan *ssh.Request) {
	cmd.Env = append(os.Environ(), "TERM="+ptyReq.term)
	if !p.trackCmd(cmd) {
		sendExit(channel, 1)
		return
	}
	ptyFile, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(ptyReq.rows), Cols: uint16(ptyReq.cols)})
	if err != nil {
		p.untrackCmd(cmd)
		sendExit(channel, 1)
		return
	}
	go handlePTYSessionRequests(requests, ptyFile)
	go func() { _, _ = io.Copy(ptyFile, channel) }()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = io.Copy(channel, ptyFile) }()
	err = cmd.Wait()
	p.untrackCmd(cmd)
	wg.Wait()
	_ = ptyFile.Close()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	sendExit(channel, code)
}

func handlePTYSessionRequests(requests <-chan *ssh.Request, ptyFile *os.File) {
	for req := range requests {
		switch req.Type {
		case "window-change":
			rows, cols, err := parseWindowChange(req.Payload)
			if err == nil {
				err = pty.Setsize(ptyFile, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
			}
			req.Reply(err == nil, nil)
		case "signal":
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

func discardSessionRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "window-change", "signal":
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

func sendExit(channel ssh.Channel, code int) {
	channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: uint32(code)}))
}

// Stop shuts down the embedded server and removes the injected files.
func (p *Proxy) Stop() {
	if p == nil {
		return
	}
	select {
	case <-p.done:
	default:
		close(p.done)
	}
	p.mu.Lock()
	p.closed = true
	if p.listener != nil {
		_ = p.listener.Close()
		p.listener = nil
	}
	for c := range p.conns {
		_ = c.Close()
	}
	for c := range p.cmds {
		if c.Process != nil {
			_ = c.Process.Kill()
		}
	}
	p.mu.Unlock()
	p.wg.Wait()
	if p.Dir != "" {
		_ = os.RemoveAll(p.Dir)
		p.Dir = ""
	}
}
