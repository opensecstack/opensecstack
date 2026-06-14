// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// Package migrations exposes the embedded SQL migration files.
package migrations

import "embed"

// FS holds all *.sql migration files embedded at compile time.
//
//go:embed *.sql
var FS embed.FS
