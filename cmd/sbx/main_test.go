package main

import (
	"flag"
	"testing"
)

func TestCommandOptionsString(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	var profile string
	flags.StringVar(&profile, "profile", "", "")

	args, err := commandOptions([]string{"echo", "--sbx-profile", "locked", "ok"}, flags)
	if err != nil {
		t.Fatalf("commandOptions: %v", err)
	}
	if profile != "locked" {
		t.Fatalf("profile = %q, want locked", profile)
	}
	if len(args) != 2 || args[0] != "echo" || args[1] != "ok" {
		t.Fatalf("args = %#v, want echo ok", args)
	}
}

func TestCommandOptionsEquals(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	var profile string
	flags.StringVar(&profile, "profile", "default", "")

	args, err := commandOptions([]string{"echo", "--sbx-profile=locked", "ok"}, flags)
	if err != nil {
		t.Fatalf("commandOptions: %v", err)
	}
	if profile != "locked" {
		t.Fatalf("profile = %q, want locked", profile)
	}
	if len(args) != 2 || args[0] != "echo" || args[1] != "ok" {
		t.Fatalf("args = %#v, want echo ok", args)
	}
}

func TestCommandOptionsBool(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	var dump bool
	flags.BoolVar(&dump, "dump", false, "")

	args, err := commandOptions([]string{"echo", "--sbx-dump", "ok"}, flags)
	if err != nil {
		t.Fatalf("commandOptions: %v", err)
	}
	if !dump {
		t.Fatal("dump = false, want true")
	}
	if len(args) != 2 || args[0] != "echo" || args[1] != "ok" {
		t.Fatalf("args = %#v, want echo ok", args)
	}
}

func TestCommandOptionsUnknown(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	if _, err := commandOptions([]string{"echo", "--sbx-missing"}, flags); err == nil {
		t.Fatal("commandOptions: expected unknown option error")
	}
}

func TestCommandOptionsMissingValue(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	var profile string
	flags.StringVar(&profile, "profile", "", "")

	if _, err := commandOptions([]string{"echo", "--sbx-profile"}, flags); err == nil {
		t.Fatal("commandOptions: expected missing value error")
	}
}
