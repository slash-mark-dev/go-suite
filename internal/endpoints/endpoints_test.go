package endpoints

import "testing"

type env map[string]string

func (e env) Getenv(k string) string { return e[k] }

func TestVanityFetchURL(t *testing.T) {
	base := env{"SMGO_VANITY_BASE": "http://127.0.0.1:9/vanity/"}
	for _, c := range []struct {
		e         Getenv
		raw, want string
	}{
		{env{}, "https://go.googlesource.com/net/info/refs?service=git-upload-pack", "https://go.googlesource.com/net/info/refs?service=git-upload-pack"},
		{base, "https://go.googlesource.com/net/info/refs?service=git-upload-pack", "http://127.0.0.1:9/vanity/go.googlesource.com/net/info/refs?service=git-upload-pack"},
		{base, "http://git.example.org/x", "http://127.0.0.1:9/vanity-http/git.example.org/x"},
		{base, "http://127.0.0.1:8080/proxy/x/@v/list", "http://127.0.0.1:8080/proxy/x/@v/list"},
		{base, "https://localhost/x", "https://localhost/x"},
		{base, "ssh://git@example.org/x", "ssh://git@example.org/x"},
	} {
		if got := VanityFetchURL(c.e, c.raw); got != c.want {
			t.Errorf("VanityFetchURL(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}
