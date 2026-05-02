package main

import (
	"slices"
	"testing"

	"github.com/hrntknr/sbx/internal/config"
)

func TestApplyCLIOverridesNoChange(t *testing.T) {
	prof := config.Profile{K8s: &config.K8sProfile{Mode: "rw"}}
	applyCLIOverrides(&prof, &cli{})
	if prof.K8s == nil || prof.K8s.Mode != "rw" {
		t.Fatalf("profile mutated: %+v", prof)
	}
}

func TestApplyCLIOverridesNoK8sDisables(t *testing.T) {
	f := false
	prof := config.Profile{K8s: &config.K8sProfile{Mode: "rw"}}
	applyCLIOverrides(&prof, &cli{K8s: &f})
	if prof.K8s != nil {
		t.Fatalf("--no-k8s should clear K8s, got %+v", prof.K8s)
	}
}

func TestApplyCLIOverridesK8sEnables(t *testing.T) {
	tr := true
	prof := config.Profile{}
	applyCLIOverrides(&prof, &cli{K8s: &tr})
	if prof.K8s == nil {
		t.Fatal("--k8s should enable K8s on profile without it")
	}
}

func TestApplyCLIOverridesOverrideImpliesEnable(t *testing.T) {
	mode := "ro"
	prof := config.Profile{}
	applyCLIOverrides(&prof, &cli{K8sMode: &mode})
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
	applyCLIOverrides(&prof, &cli{
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
	applyCLIOverrides(&prof, &cli{})
	if prof.K8s.Config != "/profile.yaml" || prof.K8s.Mode != "rw" {
		t.Errorf("unset CLI fields shouldn't change profile: %+v", prof.K8s)
	}
	if !slices.Equal(prof.K8s.Contexts, []string{"prof"}) {
		t.Errorf("contexts = %v, want [prof]", prof.K8s.Contexts)
	}
}
