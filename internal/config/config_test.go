package config

import "testing"

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
