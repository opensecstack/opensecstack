package content_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opensecstack/cyberpath/internal/content"
	"gopkg.in/yaml.v3"
)

const trackID = "fuzz-track"

func FuzzContentYAML(f *testing.F) {
	minimalTrack := []byte(
		"id: fuzz-track\n" +
			"version: 1.0.0\n" +
			"title:\n  sq: \"Titulli\"\n  en: \"Title\"\n" +
			"description:\n  sq: \"Përshkrim\"\n  en: \"Desc\"\n" +
			"audience:\n  - all-staff\n" +
			"nis2_mappings:\n  primary: art21.g\n" +
			"prerequisites: []\n" +
			"duration_minutes: 30\n" +
			"language_source: sq\n" +
			"modules: []\n" +
			"certification:\n  offered: false\n  level: baseline\n  expires_after_months: 12\n" +
			"content_hash: \"\"\n",
	)

	longVal := strings.Repeat("A", 100*1024)
	oversized := []byte("id: fuzz-track\ntitle:\n  sq: \"" + longVal + "\"\n  en: \"Title\"\n")

	f.Add(minimalTrack)
	f.Add(oversized)
	f.Add([]byte("{ : }"))
	f.Add([]byte(""))
	f.Add([]byte("a: &a\n  - *a\n  - *a\n  - *a\n  - *a\n  - *a\n"))
	f.Add([]byte("null"))
	f.Add([]byte("id: fuzz-track\nversion: \"!!\""))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		trackDir := filepath.Join(dir, trackID)
		if err := os.MkdirAll(trackDir, 0o755); err != nil {
			return
		}
		trackYAML := filepath.Join(trackDir, "track.yaml")
		if err := os.WriteFile(trackYAML, data, 0o600); err != nil {
			return
		}

		track, err := content.LoadTrack(dir, trackID)
		if err != nil {
			return
		}
		_ = content.ValidateTrack(track)
	})
}

func FuzzLabYAML(f *testing.F) {
	validLab := []byte(
		"id: sample-lab\n" +
			"version: 1.0.0\n" +
			"runtime: wasmtime\n" +
			"image: \"ghcr.io/opensecstack/cyberpath-labs/wasm-shell:1.0.0\"\n" +
			"entry_command: \"/bin/sh\"\n" +
			"assets: []\n" +
			"validation: []\n" +
			"time_limit_seconds: 600\n" +
			"network:\n  egress_whitelist: []\n" +
			"success_criteria:\n  min_score: 1\n  required_rules: []\n" +
			"hints: []\n" +
			"content_hash: \"\"\n",
	)

	f.Add(validLab)
	f.Add([]byte(""))
	f.Add([]byte("null"))
	f.Add([]byte("{ : }"))
	f.Add([]byte("a: &a\n  - *a\n  - *a\n  - *a\n"))
	f.Add([]byte("id: lab\nruntime: " + strings.Repeat("X", 64*1024)))

	f.Fuzz(func(t *testing.T, data []byte) {
		var lab content.LabYAML
		_ = yaml.Unmarshal(data, &lab)
	})
}
