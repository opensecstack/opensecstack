package content

import (
	"path/filepath"
	"testing"
)

func TestHashTrack_Deterministic(t *testing.T) {
	root, _ := filepath.Abs("testdata")
	a, err := LoadTrack(root, "sample-track")
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadTrack(root, "sample-track")
	if err != nil {
		t.Fatal(err)
	}
	h1 := HashTrack(a)
	h2 := HashTrack(b)
	if h1 != h2 {
		t.Errorf("non-deterministic hash: %s vs %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("expected sha256 hex (64 chars), got %d", len(h1))
	}
}

func TestHashTrack_DifferentInputs(t *testing.T) {
	root, _ := filepath.Abs("testdata")
	tr, err := LoadTrack(root, "sample-track")
	if err != nil {
		t.Fatal(err)
	}
	h1 := HashTrack(tr)
	tr.TitleEN = "Modified"
	h2 := HashTrack(tr)
	if h1 == h2 {
		t.Error("expected hash to change after mutation")
	}
}

func TestHashTrack_IgnoresContentHashField(t *testing.T) {
	root, _ := filepath.Abs("testdata")
	tr, _ := LoadTrack(root, "sample-track")
	tr.ContentHash = ""
	h1 := HashTrack(tr)
	tr.ContentHash = "blake3:something-stale"
	h2 := HashTrack(tr)
	if h1 != h2 {
		t.Errorf("ContentHash should be blanked before hashing: %s vs %s", h1, h2)
	}
}

func TestHashLesson(t *testing.T) {
	a := HashLesson("hello")
	b := HashLesson("hello")
	c := HashLesson("hello!")
	if a != b {
		t.Errorf("same input → different hash")
	}
	if a == c {
		t.Errorf("different inputs collided")
	}
	// Known sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	if a != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Errorf("unexpected sha256(hello): %s", a)
	}
}

func TestHashLab(t *testing.T) {
	root, _ := filepath.Abs("testdata")
	tr, _ := LoadTrack(root, "sample-track")
	lab := tr.Modules[0].Lab.Lab
	h1 := HashLab(lab)
	h2 := HashLab(lab)
	if h1 != h2 {
		t.Error("lab hash non-deterministic")
	}
	lab.ContentHash = "stale"
	h3 := HashLab(lab)
	if h1 != h3 {
		t.Error("lab content_hash not blanked before hashing")
	}
}

func TestHashQuiz(t *testing.T) {
	root, _ := filepath.Abs("testdata")
	tr, _ := LoadTrack(root, "sample-track")
	q := tr.Modules[0].Quiz
	h1 := HashQuiz(q)
	h2 := HashQuiz(q)
	if h1 != h2 {
		t.Error("quiz hash non-deterministic")
	}
}

func TestCanonicalJSON_SortedKeys(t *testing.T) {
	in := map[string]interface{}{
		"b": 1,
		"a": 2,
	}
	out, err := canonicalJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	want := `{"a":2,"b":1}`
	if got != want {
		t.Errorf("canonical = %q want %q", got, want)
	}
}
