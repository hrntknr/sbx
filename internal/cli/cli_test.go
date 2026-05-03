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
	in := []string{"mycmd", "--sbx-k8s-config", "/tmp/kc", "--bar"}
	want := []string{"--k8s-config", "/tmp/kc", "mycmd", "--bar"}
	got := normalizeArgs(in, newParser(t))
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNormalizeArgsEqualsValue(t *testing.T) {
	in := []string{"mycmd", "--sbx-k8s-config=/tmp/kc", "--bar"}
	want := []string{"--k8s-config=/tmp/kc", "mycmd", "--bar"}
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
	in := []string{"mycmd", "--sbx-k8s-context", "a,b", "--sbx-k8s-context=c"}
	want := []string{"--k8s-context", "a,b", "--k8s-context=c", "mycmd"}
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
	prof := config.Profile{K8s: &config.K8sProfile{Mode: "rw"}}
	applyCLIOverrides(&prof, &opts{})
	if prof.K8s == nil || prof.K8s.Mode != "rw" {
		t.Fatalf("profile mutated: %+v", prof)
	}
}

func TestApplyCLIOverridesNoK8sDisables(t *testing.T) {
	f := false
	prof := config.Profile{K8s: &config.K8sProfile{Mode: "rw"}}
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

func TestApplyCLIOverridesOverrideImpliesEnable(t *testing.T) {
	mode := "ro"
	prof := config.Profile{}
	applyCLIOverrides(&prof, &opts{K8sMode: &mode})
	if prof.K8s == nil || prof.K8s.Mode != "ro" {
		t.Fatalf("--k8s-mode should enable and set mode, got %+v", prof.K8s)
	}
}

func TestApplyCLIOverridesFieldsWin(t *testing.T) {
	prof := config.Profile{K8s: &config.K8sProfile{
		Config:   "/profile.yaml",
		Contexts: []string{"prof"},
		Mode:     "rw",
	}}
	cfg := "/cli.yaml"
	mode := "ro"
	applyCLIOverrides(&prof, &opts{
		K8sConfig:  &cfg,
		K8sContext: []string{"cli"},
		K8sMode:    &mode,
	})
	if prof.K8s.Config != cfg || prof.K8s.Mode != mode {
		t.Errorf("CLI fields didn't win: %+v", prof.K8s)
	}
	if !slices.Equal(prof.K8s.Contexts, []string{"cli"}) {
		t.Errorf("contexts = %v, want [cli]", prof.K8s.Contexts)
	}
}

func TestApplyCLIOverridesUnsetKeepsProfile(t *testing.T) {
	prof := config.Profile{K8s: &config.K8sProfile{
		Config:   "/profile.yaml",
		Contexts: []string{"prof"},
		Mode:     "rw",
	}}
	applyCLIOverrides(&prof, &opts{})
	if prof.K8s.Config != "/profile.yaml" || prof.K8s.Mode != "rw" {
		t.Errorf("unset CLI fields shouldn't change profile: %+v", prof.K8s)
	}
	if !slices.Equal(prof.K8s.Contexts, []string{"prof"}) {
		t.Errorf("contexts = %v, want [prof]", prof.K8s.Contexts)
	}
}

func TestNormalizeArgsCFlag(t *testing.T) {
	in := []string{"-c", "echo hello"}
	got := normalizeArgs(in, newParser(t))
	if !slices.Equal(got, in) {
		t.Errorf("got %v, want %v", got, in)
	}
}
