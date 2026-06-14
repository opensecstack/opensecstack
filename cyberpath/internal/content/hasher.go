// Package content — hasher.go produces deterministic sha256 content
// hashes for tracks, modules, lessons, quizzes and labs.
//
// # Canonical-JSON algorithm
//
// The hash is sha256(canonicalJSON(struct)) hex-encoded. canonicalJSON
// is deterministic with the following rules:
//
//   - Each value is first marshalled with encoding/json (which honours
//     struct field order and `json:` tags) and then re-decoded into a
//     generic interface{}.
//   - Maps are emitted with keys sorted lexicographically (byte order).
//   - Strings are JSON-escaped exactly as encoding/json does (UTF-8
//     safe, control chars escaped, no HTML-escaping — we set
//     SetEscapeHTML(false)).
//   - Numbers are emitted using json.Number to round-trip integers
//     and floats without normalisation drift.
//   - No whitespace anywhere — no spaces, no newlines.
//   - The ContentHash field on the input struct is zeroed before
//     hashing so that re-hashing a previously-hashed value yields the
//     same digest (avoids the chicken-and-egg of "what is the hash of
//     a struct that contains its own hash?").
//
// Same struct → same hash forever. This is the audit-reproducibility
// requirement from docs/nis2-evidence-flow.md.
package content

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// HashTrack returns the canonical sha256 hex digest of t.
//
// The function does NOT mutate t; it works on a copy with ContentHash
// blanked. The lab content_hash within referenced labs is also blanked
// because labs have their own hash and we don't want to double-count.
func HashTrack(t *TrackYAML) string {
	if t == nil {
		return ""
	}
	cp := *t
	cp.ContentHash = ""
	// Deep-copy modules so we can blank nested hashes without mutating.
	cp.Modules = make([]ModuleYAML, len(t.Modules))
	copy(cp.Modules, t.Modules)
	for i := range cp.Modules {
		if cp.Modules[i].Lab != nil && cp.Modules[i].Lab.Lab != nil {
			labCopy := *cp.Modules[i].Lab.Lab
			labCopy.ContentHash = ""
			cp.Modules[i].Lab = &LabRef{ID: cp.Modules[i].Lab.ID, Lab: &labCopy}
		}
	}
	return hashCanonical(cp)
}

// HashLab returns the canonical sha256 hex digest of l. The
// ContentHash field is blanked before hashing.
func HashLab(l *LabYAML) string {
	if l == nil {
		return ""
	}
	cp := *l
	cp.ContentHash = ""
	return hashCanonical(cp)
}

// HashLesson returns the sha256 hex digest of the lesson body bytes.
//
// The body is a single string (already a concatenation of frontmatter
// + markdown), so we hash it directly rather than canonicalising. This
// keeps re-publishing idempotent: byte-identical body → identical hash.
func HashLesson(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// HashQuiz returns the canonical sha256 hex digest of q.
func HashQuiz(q *QuizYAML) string {
	if q == nil {
		return ""
	}
	return hashCanonical(*q)
}

// hashCanonical is the core helper: marshal → canonicalise → sha256 hex.
func hashCanonical(v interface{}) string {
	canon, err := canonicalJSON(v)
	if err != nil {
		// In practice json.Marshal cannot fail on our content structs
		// (no channels / funcs / unsupported types). If it does, the
		// hash becomes a sentinel that audit tooling can flag.
		return fmt.Sprintf("ERR:%v", err)
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])
}

// canonicalJSON serialises v with sorted map keys and no whitespace.
//
// Implementation: encoding/json → re-decode to interface{} (using
// json.Number to preserve numeric exactness) → walk the tree sorting
// map keys → re-encode by hand into a bytes.Buffer.
func canonicalJSON(v interface{}) ([]byte, error) {
	// First marshal with encoding/json so struct tags + field ordering
	// are honoured.
	raw, err := jsonMarshalNoEscape(v)
	if err != nil {
		return nil, err
	}
	// Decode into a generic structure preserving number types.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic interface{}
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func jsonMarshalNoEscape(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encoder.Encode appends a trailing newline; trim it.
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}

func writeCanonical(buf *bytes.Buffer, v interface{}) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(x.String())
	case string:
		// Reuse encoding/json for string escaping rules.
		s, err := jsonMarshalNoEscape(x)
		if err != nil {
			return err
		}
		buf.Write(s)
	case []interface{}:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			ks, err := jsonMarshalNoEscape(k)
			if err != nil {
				return err
			}
			buf.Write(ks)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonicalJSON: unsupported type %T", v)
	}
	return nil
}
