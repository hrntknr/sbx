package cli

import (
	"strings"

	"github.com/alecthomas/kong"
)

type splitArgs struct {
	sbx  []string
	rest []string
}

func (a splitArgs) normalized() []string {
	out := make([]string, 0, len(a.sbx)+len(a.rest))
	out = append(out, a.sbx...)
	out = append(out, a.rest...)
	return out
}

func normalizeArgs(rawArgs []string, parser *kong.Kong) []string {
	return splitSbxPrefixed(rawArgs, parser).normalized()
}

// splitSbxPrefixed pulls --sbx-foo flags out of rawArgs, strips the --sbx-
// prefix, and keeps all other args in their original order. The returned sbx
// slice can be prepended before the rest so kong sees those options even when
// the user wrote them after the command.
func splitSbxPrefixed(rawArgs []string, parser *kong.Kong) splitArgs {
	takesValue := sbxFlagsTakeValue(parser)
	out := splitArgs{
		sbx:  make([]string, 0, len(rawArgs)),
		rest: make([]string, 0, len(rawArgs)),
	}
	const prefix = "--sbx-"
	for i := 0; i < len(rawArgs); i++ {
		a := rawArgs[i]
		if !strings.HasPrefix(a, prefix) || len(a) == len(prefix) {
			out.rest = append(out.rest, a)
			continue
		}
		body := a[len(prefix):]
		if strings.Contains(body, "=") {
			out.sbx = append(out.sbx, "--"+body)
			continue
		}
		flag := "--" + body
		out.sbx = append(out.sbx, flag)
		if takesValue[flag] && i+1 < len(rawArgs) {
			out.sbx = append(out.sbx, rawArgs[i+1])
			i++
		}
	}
	return out
}

func sbxFlagsTakeValue(parser *kong.Kong) map[string]bool {
	m := map[string]bool{}
	for _, f := range parser.Model.Node.Flags {
		needsValue := !f.IsBool() && !f.IsCounter()
		m["--"+f.Name] = needsValue
		for _, alias := range f.Aliases {
			m["--"+alias] = needsValue
		}
		if f.Tag == nil || f.Tag.Negatable == "" {
			continue
		}
		negatedName := f.Tag.Negatable
		if negatedName == "_" {
			negatedName = "no-" + f.Name
		}
		m["--"+negatedName] = false
	}
	return m
}
