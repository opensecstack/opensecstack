package correlate

import "testing"

func TestHostFromURL(t *testing.T) {
	cases := map[string]string{
		"http://bad.example/a":            "bad.example",
		"https://LOGIN.bank.example:8080": "login.bank.example",
		"notaurl":                          "",
		"":                                  "",
	}
	for in, want := range cases {
		if got := hostFromURL(in); got != want {
			t.Errorf("hostFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}
