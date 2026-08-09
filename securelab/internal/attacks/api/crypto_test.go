// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

import (
	"bytes"
	"testing"
)

func TestHmacSHA256_KnownVector(t *testing.T) {
	// RFC 4231 test case 1.
	key := bytes.Repeat([]byte{0x0b}, 20)
	data := []byte("Hi There")
	want := []byte{
		0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
		0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
		0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
		0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
	}
	got := hmacSHA256(key, data)
	if !bytes.Equal(got, want) {
		t.Errorf("hmacSHA256 = %x, want %x", got, want)
	}
}

func TestHmacSHA256_DifferentKeysProduceDifferentMACs(t *testing.T) {
	data := []byte("payload")
	mac1 := hmacSHA256([]byte("key1"), data)
	mac2 := hmacSHA256([]byte("key2"), data)
	if bytes.Equal(mac1, mac2) {
		t.Error("expected different MACs for different keys")
	}
}

func TestHmacSHA256_EmptyKey(t *testing.T) {
	got := hmacSHA256([]byte(""), []byte("data"))
	if len(got) != 32 {
		t.Errorf("expected 32-byte SHA256 HMAC, got %d bytes", len(got))
	}
}
