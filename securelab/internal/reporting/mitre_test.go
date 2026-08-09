// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package reporting_test

import (
	"testing"

	"github.com/opensecstack/securelab/internal/reporting"
)

func TestLookupByKind_KnownKind(t *testing.T) {
	entry, ok := reporting.LookupByKind("bola")
	if !ok {
		t.Fatal("expected bola to be found")
	}
	if entry.TechniqueID != "T1078" {
		t.Errorf("TechniqueID = %q, want T1078", entry.TechniqueID)
	}
	if entry.Name != "Valid Accounts" {
		t.Errorf("Name = %q, want Valid Accounts", entry.Name)
	}
}

func TestLookupByKind_CaseInsensitive(t *testing.T) {
	entry, ok := reporting.LookupByKind("BoLa")
	if !ok {
		t.Fatal("expected case-insensitive lookup to succeed")
	}
	if entry.AttackKind != "bola" {
		t.Errorf("AttackKind = %q, want bola", entry.AttackKind)
	}
}

func TestLookupByKind_UnknownKind(t *testing.T) {
	_, ok := reporting.LookupByKind("not_a_real_kind")
	if ok {
		t.Fatal("expected unknown kind to return false")
	}
}

func TestMITREMapping_AllEntriesHaveRequiredFields(t *testing.T) {
	for kind, entry := range reporting.MITREMapping {
		if entry.TechniqueID == "" {
			t.Errorf("kind %q: missing TechniqueID", kind)
		}
		if entry.Name == "" {
			t.Errorf("kind %q: missing Name", kind)
		}
		if entry.URL == "" {
			t.Errorf("kind %q: missing URL", kind)
		}
		if entry.AttackKind != kind {
			t.Errorf("kind %q: AttackKind field = %q, want match with map key", kind, entry.AttackKind)
		}
	}
}
