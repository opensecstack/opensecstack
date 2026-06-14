// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

import (
	"crypto/hmac"
	"crypto/sha256"
)

// hmacSHA256 returns the HMAC-SHA256 of data under key.
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
