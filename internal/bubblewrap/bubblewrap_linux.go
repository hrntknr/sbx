//go:build linux

package bubblewrap

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hrntknr/sbx/internal/config"
	"github.com/hrntknr/sbx/internal/runner"
)

// baseArgs is appended AFTER user rules so the fresh procfs/devfs override
// anything the user happened to bind at /proc or /dev (e.g. via allow(r, /)).
// Matches seatbelt's baseline: no namespace isolation beyond what bwrap
// requires, network/IPC/PIDs visible from the host.
func baseArgs() []string {
	return []string{
		"--proc", "/proc",
		"--dev", "/dev",
		"--die-with-parent",
	}
}

func Build(rules []config.Rule, expand func(string) string) ([]string, error) {
	var args []string
	// first-match-wins → reverse so the highest-precedence rule's mount is
	// applied LAST (bwrap is last-mount-wins for overlapping paths).
	for i := len(rules) - 1; i >= 0; i-- {
		a, err := emitRule(rules[i], expand)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		args = append(args, a...)
	}
	// Implicit tmp binds go AFTER user rules so broad mounts (e.g.
	// `--ro-bind-try / /` from `allow(r, /)`) don't shadow tmp under
	// last-mount-wins. User rules that touch tmp are then re-emitted so
	// explicit allow/deny on tmp paths still beats the implicit allow,
	// matching the seatbelt last-match-wins semantics.
	tmpPaths := config.ImplicitTmpPaths()
	for _, p := range tmpPaths {
		args = append(args, "--bind-try", p, p)
	}
	for i := len(rules) - 1; i >= 0; i-- {
		if !ruleTouchesTmp(rules[i], expand, tmpPaths) {
			continue
		}
		a, err := emitRule(rules[i], expand)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		args = append(args, a...)
	}
	args = append(args, baseArgs()...)
	return args, nil
}

// ruleTouchesTmp reports whether r's expanded path is exactly one of the
// implicit tmp paths or a descendant of one.
func ruleTouchesTmp(r config.Rule, expand func(string) string, tmpPaths []string) bool {
	p := strings.TrimRight(expand(r.Path), "/")
	if p == "" {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	for _, t := range tmpPaths {
		if p == t || strings.HasPrefix(p, t+"/") {
			return true
		}
	}
	return false
}

func emitRule(r config.Rule, expand func(string) string) ([]string, error) {
	if r.Action != "allow" && r.Action != "deny" {
		return nil, fmt.Errorf("invalid action %q (must be allow or deny)", r.Action)
	}
	read, write, err := config.ParseMode(r.Mode)
	if err != nil {
		return nil, err
	}
	expanded := expand(r.Path)
	if expanded == "" {
		return nil, fmt.Errorf("path %q expanded to empty", r.Path)
	}
	var args []string
	for _, p := range expandPaths(expanded) {
		args = append(args, mountArgs(r.Action, read, write, p)...)
	}
	return args, nil
}

// mountArgs maps a single rule (one expanded path) to bwrap arguments.
//
//	allow rw  → --bind-try (writable bind)
//	allow r   → --ro-bind-try (read-only bind)
//	allow w   → --bind-try (bwrap has no write-only mount)
//	deny dir  → --tmpfs (replace with empty tmpfs)
//	deny file → --ro-bind /dev/null (replace with empty file)
func mountArgs(action string, read, write bool, p string) []string {
	if action == "deny" {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return []string{"--tmpfs", p}
		}
		return []string{"--ro-bind", "/dev/null", p}
	}
	if write {
		return []string{"--bind-try", p, p}
	}
	if read {
		return []string{"--ro-bind-try", p, p}
	}
	return nil
}

// expandPaths performs host-side glob expansion using filepath.Glob
// (`*`, `?`, `[abc]`). `**` and `{a,b}` patterns are NOT expanded.
func expandPaths(p string) []string {
	if !strings.ContainsAny(p, "*?[") {
		return []string{p}
	}
	m, err := filepath.Glob(p)
	if err != nil {
		return nil
	}
	return m
}

// Run invokes bwrap with the given args and command. Returns the child's
// exit code. A non-nil error means bwrap could not be started.
func Run(bwrapArgs, cmd, env []string) (int, error) {
	full := append(append([]string{}, bwrapArgs...), "--")
	full = append(full, cmd...)
	c := exec.Command("bwrap", full...)
	c.Env = env
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return runner.Run(c)
}
