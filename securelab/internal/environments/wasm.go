// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package environments

import (
	"context"
	"time"

	"github.com/opensecstack/securelab/internal/db"
)

// WasmEnvironment is a stub for PyramidOS Wasm sandbox targets.
//
// The Wasm sandbox is managed externally; SecureLab simply records the
// environment metadata and passes the provided targetURL to attack modules.
// No container or network management is performed here.
type WasmEnvironment struct{}

// NewWasmEnvironment returns a WasmEnvironment.
func NewWasmEnvironment() *WasmEnvironment { return &WasmEnvironment{} }

// Provision returns an Environment record with kind=wasm and the provided
// targetURL. It does not perform any container or network operations.
func (w *WasmEnvironment) Provision(_ context.Context, name, targetURL string) (*db.Environment, error) {
	return &db.Environment{
		ID:        "wasm-" + name,
		Name:      name,
		Kind:      "wasm",
		NetworkID: "",
		TargetURL: targetURL,
		Status:    "running",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}
