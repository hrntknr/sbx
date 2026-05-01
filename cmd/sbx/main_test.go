package main

import "testing"

func TestCommandProfile(t *testing.T) {
	args, profile, err := commandProfile([]string{"echo", "--sbx-profile", "locked", "ok"}, "")
	if err != nil {
		t.Fatalf("commandProfile: %v", err)
	}
	if profile != "locked" {
		t.Fatalf("profile = %q, want locked", profile)
	}
	if len(args) != 2 || args[0] != "echo" || args[1] != "ok" {
		t.Fatalf("args = %#v, want echo ok", args)
	}
}

func TestCommandProfileEquals(t *testing.T) {
	args, profile, err := commandProfile([]string{"echo", "--sbx-profile=locked", "ok"}, "default")
	if err != nil {
		t.Fatalf("commandProfile: %v", err)
	}
	if profile != "locked" {
		t.Fatalf("profile = %q, want locked", profile)
	}
	if len(args) != 2 || args[0] != "echo" || args[1] != "ok" {
		t.Fatalf("args = %#v, want echo ok", args)
	}
}

func TestCommandProfileMissingValue(t *testing.T) {
	if _, _, err := commandProfile([]string{"echo", "--sbx-profile"}, ""); err == nil {
		t.Fatal("commandProfile: expected missing value error")
	}
}
