//go:build darwin

package seatbelt

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hrntknr/sbx/internal/config"
	"github.com/hrntknr/sbx/internal/runner"
)

// non-file ops + file metadata/xattr are always permitted so stat-heavy tools
// (find, ls -l, IDEs, build systems' XDG lookups) work under (deny default).
// User read/write rules govern only file content (file-read-data / file-write*).
const baseProfile = `(version 1)
(deny default)
(allow network*)
(allow process*)
(allow signal)
(allow mach-lookup)
(allow sysctl-read)
(allow iokit-open)
(allow ipc-posix*)
(allow file-ioctl)
(allow system-fsctl)
(allow file-read-metadata)
(allow file-read-xattr)
(allow file-write-data
    (literal "/dev/null")
    (literal "/dev/zero")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (literal "/dev/tty")
    (literal "/dev/stdout")
    (literal "/dev/stderr")
    (literal "/dev/dtracehelper"))
`

func Build(rules []config.Rule, expand func(string) string) (string, error) {
	var b strings.Builder
	b.WriteString(baseProfile)
	// first-match-wins → reverse to seatbelt's last-match-wins
	for i := len(rules) - 1; i >= 0; i-- {
		if err := emitRule(&b, rules[i], expand); err != nil {
			return "", fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return b.String(), nil
}

func emitRule(b *strings.Builder, r config.Rule, expand func(string) string) error {
	if r.Action != "allow" && r.Action != "deny" {
		return fmt.Errorf("invalid action %q (must be allow or deny)", r.Action)
	}
	read, write, err := config.ParseMode(r.Mode)
	if err != nil {
		return err
	}
	expanded := expand(r.Path)
	if expanded == "" {
		return fmt.Errorf("path %q expanded to empty", r.Path)
	}
	filter := pathFilter(expanded)
	if filter != "" {
		filter = " " + filter
	}
	if read {
		fmt.Fprintf(b, "(%s file-read-data%s)\n", r.Action, filter)
	}
	if write {
		fmt.Fprintf(b, "(%s file-write*%s)\n", r.Action, filter)
	}
	return nil
}

// pathFilter returns the seatbelt filter clause for a path:
//   - glob (`*?[{` present) → (regex #"...")
//   - plain → (subpath "...") with symlinks resolved (canonical form)
//   - "/" → "" (no filter, matches all paths)
func pathFilter(p string) string {
	if strings.ContainsAny(p, "*?[{") {
		return fmt.Sprintf("(regex #%q)", globToRegex(p))
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return fmt.Sprintf("(subpath %q)", p)
}

// globToRegex translates a shell-style glob to a regex anchored to also
// match descendants. Regex meta chars are escaped via `[c]` form because
// seatbelt's `#"..."` literal treats backslashes raw.
//
// Supports: `*` `**` `?` `[abc]` `{a,b}`.
func globToRegex(s string) string {
	const meta = ".+(){}[]|^$"
	esc := func(c byte) string {
		if strings.IndexByte(meta, c) >= 0 {
			return "[" + string(c) + "]"
		}
		return string(c)
	}
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '*' && i+1 < len(s) && s[i+1] == '*':
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		case c == '[':
			if end := strings.IndexByte(s[i+1:], ']'); end >= 0 {
				b.WriteString(s[i : i+end+2])
				i += end + 1
				continue
			}
			b.WriteString(esc(c))
		case c == '{':
			if end := strings.IndexByte(s[i+1:], '}'); end >= 0 {
				parts := strings.Split(s[i+1:i+1+end], ",")
				for j, p := range parts {
					var sb strings.Builder
					for k := 0; k < len(p); k++ {
						sb.WriteString(esc(p[k]))
					}
					parts[j] = sb.String()
				}
				b.WriteString("(" + strings.Join(parts, "|") + ")")
				i += end + 1
				continue
			}
			b.WriteString(esc(c))
		default:
			b.WriteString(esc(c))
		}
	}
	b.WriteString("(/.*)?$")
	return b.String()
}

// Run executes the given command under sandbox-exec with the profile.
// Returns the child's exit code (or 0). Non-nil error means the child
// could not be started.
func Run(profile string, args, env []string) (int, error) {
	cmd := exec.Command("sandbox-exec", append([]string{"-p", profile}, args...)...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return runner.Run(cmd)
}
