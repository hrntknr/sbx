package cli

import (
	"slices"
	"testing"

	"github.com/alecthomas/kong"

	"github.com/hrntknr/sbx/internal/config"
)

func newParser(t *testing.T) *kong.Kong {
	t.Helper()
	return kong.Must(&opts{}, kong.Name("sbx"))
}

func TestNormalizeArgsNoMatches(t *testing.T) {
	in := []string{"--profile", "foo", "mycmd", "--bar", "baz"}
	got := normalizeArgs(in, newParser(t))
	if !slices.Equal(got, in) {
		t.Errorf("got %v, want %v", got, in)
	}
}

func TestSplitSbxPrefixedAfterCommand(t *testing.T) {
	in := []string{"mycmd", "--bar", "--sbx-k8s", "--baz"}
	got := splitSbxPrefixed(in, newParser(t))
	if !slices.Equal(got.sbx, []string{"--k8s"}) {
		t.Errorf("sbx = %v, want [--k8s]", got.sbx)
	}
	if !slices.Equal(got.rest, []string{"mycmd", "--bar", "--baz"}) {
		t.Errorf("rest = %v, want [mycmd --bar --baz]", got.rest)
	}
	wantNormalized := []string{"--k8s", "mycmd", "--bar", "--baz"}
	if got := got.normalized(); !slices.Equal(got, wantNormalized) {
		t.Errorf("normalized = %v, want %v", got, wantNormalized)
	}
}

func TestNormalizeArgsSpaceValue(t *testing.T) {
	in := []string{"mycmd", "--sbx-profile", "dev", "--bar"}
	want := []string{"--profile", "dev", "mycmd", "--bar"}
	got := normalizeArgs(in, newParser(t))
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNormalizeArgsEqualsValue(t *testing.T) {
	in := []string{"mycmd", "--sbx-profile=dev", "--bar"}
	want := []string{"--profile=dev", "mycmd", "--bar"}
	got := normalizeArgs(in, newParser(t))
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNormalizeArgsNegated(t *testing.T) {
	in := []string{"mycmd", "--sbx-no-k8s", "--bar"}
	want := []string{"--no-k8s", "mycmd", "--bar"}
	got := normalizeArgs(in, newParser(t))
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNormalizeArgsSliceRepeated(t *testing.T) {
	in := []string{"mycmd", "--sbx-profile", "prod", "--sbx-k8s"}
	want := []string{"--profile", "prod", "--k8s", "mycmd"}
	got := normalizeArgs(in, newParser(t))
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNormalizeArgsBoolDoesNotConsumeNext(t *testing.T) {
	in := []string{"--sbx-dump", "mycmd", "arg"}
	want := []string{"--dump", "mycmd", "arg"}
	got := normalizeArgs(in, newParser(t))
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNormalizeArgsBareDashSbxIgnored(t *testing.T) {
	in := []string{"mycmd", "--sbx-", "arg"}
	got := normalizeArgs(in, newParser(t))
	if !slices.Equal(got, in) {
		t.Errorf("got %v, want %v", got, in)
	}
}

func TestApplyCLIOverridesNoChange(t *testing.T) {
	prof := config.Profile{K8s: &config.K8sProfile{Rules: []config.K8sRule{{Action: "allow", Mode: "rw", Pattern: "profile"}}}}
	applyCLIOverrides(&prof, &opts{})
	if prof.K8s == nil || len(prof.K8s.Rules) != 1 || prof.K8s.Rules[0].Pattern != "profile" {
		t.Fatalf("profile mutated: %+v", prof)
	}
}

func TestApplyCLIOverridesNoK8sDisables(t *testing.T) {
	f := false
	prof := config.Profile{K8s: &config.K8sProfile{Rules: []config.K8sRule{{Action: "allow", Mode: "rw", Pattern: "profile"}}}}
	applyCLIOverrides(&prof, &opts{K8s: &f})
	if prof.K8s != nil {
		t.Fatalf("--no-k8s should clear K8s, got %+v", prof.K8s)
	}
}

func TestApplyCLIOverridesK8sEnables(t *testing.T) {
	tr := true
	prof := config.Profile{}
	applyCLIOverrides(&prof, &opts{K8s: &tr})
	if prof.K8s == nil {
		t.Fatal("--k8s should enable K8s on profile without it")
	}
}

func TestApplyCLIOverridesUnsetKeepsProfile(t *testing.T) {
	prof := config.Profile{K8s: &config.K8sProfile{
		Rules: []config.K8sRule{{Action: "allow", Mode: "rw", Pattern: "prof"}},
	}}
	applyCLIOverrides(&prof, &opts{})
	want := []config.K8sRule{{Action: "allow", Mode: "rw", Pattern: "prof"}}
	if !slices.Equal(prof.K8s.Rules, want) {
		t.Errorf("rules = %v, want %v", prof.K8s.Rules, want)
	}
}

func TestApplyCLIOverridesNoSSHDisables(t *testing.T) {
	f := false
	prof := config.Profile{SSH: &config.SSHProfile{Rules: []config.SSHRule{{Action: "allow", Pattern: "profile"}}}}
	applyCLIOverrides(&prof, &opts{SSH: &f})
	if prof.SSH != nil {
		t.Fatalf("--no-ssh should clear SSH, got %+v", prof.SSH)
	}
}

func TestApplyCLIOverridesSSHEnables(t *testing.T) {
	tr := true
	prof := config.Profile{}
	applyCLIOverrides(&prof, &opts{SSH: &tr})
	if prof.SSH == nil {
		t.Fatal("--ssh should enable SSH on profile without it")
	}
}
