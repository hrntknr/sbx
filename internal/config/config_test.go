package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Rule
	}{
		{"allow(rw, /foo)", Rule{"allow", "rw", "/foo"}},
		{"deny(w, /etc)", Rule{"deny", "w", "/etc"}},
		{"  allow ( r , /usr ) ", Rule{"allow", "r", "/usr"}},
		{"allow(rw, ${WORK_DIR})", Rule{"allow", "rw", "${WORK_DIR}"}},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"allow rw /foo", "allow(rw)", "allow(rw, /foo", "(rw, /foo)"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q): expected error", in)
		}
	}
}

func TestParseMode(t *testing.T) {
	cases := []struct {
		in          string
		read, write bool
		expectError bool
	}{
		{"rw", true, true, false},
		{"r", true, false, false},
		{"w", false, true, false},
		{"ro", false, false, true},
		{"", false, false, true},
	}
	for _, c := range cases {
		r, w, err := ParseMode(c.in)
		if c.expectError != (err != nil) || r != c.read || w != c.write {
			t.Errorf("ParseMode(%q) = (%v,%v,%v), want (%v,%v,err=%v)",
				c.in, r, w, err, c.read, c.write, c.expectError)
		}
	}
}

func TestLoadProfileList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbx.yaml")
	data := []byte(`
- name: default
  rules:
    - allow(rw, ${WORK_DIR})
    - allow(r, /)
- name: locked
  rules:
    - deny(rw, ~/.*)
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadProfile(path, "")
	if err != nil {
		t.Fatalf("LoadProfile default: %v", err)
	}
	if len(got) != 2 || got[0] != (Rule{"allow", "rw", "${WORK_DIR}"}) || got[1] != (Rule{"allow", "r", "/"}) {
		t.Fatalf("LoadProfile default = %+v", got)
	}

	got, err = LoadProfile(path, "locked")
	if err != nil {
		t.Fatalf("LoadProfile locked: %v", err)
	}
	if len(got) != 1 || got[0] != (Rule{"deny", "rw", "~/.*"}) {
		t.Fatalf("LoadProfile locked = %+v", got)
	}
}

func TestLoadSingleProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbx.yaml")
	data := []byte(`
name: default
rules:
  - allow(rw, ${WORK_DIR})
  - allow(r, /)
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadProfile(path, "")
	if err != nil {
		t.Fatalf("LoadProfile default: %v", err)
	}
	if len(got) != 2 || got[0] != (Rule{"allow", "rw", "${WORK_DIR}"}) || got[1] != (Rule{"allow", "r", "/"}) {
		t.Fatalf("LoadProfile default = %+v", got)
	}
	if _, err := LoadProfile(path, "locked"); err == nil {
		t.Fatal("LoadProfile locked: expected error")
	}
}

func TestLoadProfileDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbx.yaml")
	data := []byte(`
name: default
rules:
  - allow(rw, ${WORK_DIR})
---
name: test
rules:
  - deny(rw, ~/.*)
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadProfile(path, "")
	if err != nil {
		t.Fatalf("LoadProfile default: %v", err)
	}
	if len(got) != 1 || got[0] != (Rule{"allow", "rw", "${WORK_DIR}"}) {
		t.Fatalf("LoadProfile default = %+v", got)
	}

	got, err = LoadProfile(path, "test")
	if err != nil {
		t.Fatalf("LoadProfile test: %v", err)
	}
	if len(got) != 1 || got[0] != (Rule{"deny", "rw", "~/.*"}) {
		t.Fatalf("LoadProfile test = %+v", got)
	}
}

func TestLoadProfileLegacyList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbx.yaml")
	data := []byte(`
- allow(rw, ${WORK_DIR})
- allow(r, /)
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadProfile(path, "")
	if err != nil {
		t.Fatalf("LoadProfile legacy default: %v", err)
	}
	if len(got) != 2 || got[0] != (Rule{"allow", "rw", "${WORK_DIR}"}) || got[1] != (Rule{"allow", "r", "/"}) {
		t.Fatalf("LoadProfile legacy default = %+v", got)
	}
	if _, err := LoadProfile(path, "locked"); err == nil {
		t.Fatal("LoadProfile legacy locked: expected error")
	}
}
