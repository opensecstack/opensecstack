//go:build integration

package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestIntegration_Stix_CreateBundleAndInsertObject(t *testing.T) {
	pool := testDB(t)
	s := NewStixStore(pool)
	ctx := context.Background()

	b := &StixBundle{
		StixID:      "bundle--" + uuid.NewString(),
		Direction:   "export",
		Source:      "threatflow",
		ObjectCount: 1,
		BundleHash:  HashBundle([]byte(`{"type":"bundle"}`)),
	}
	mustOK(t, s.CreateBundle(ctx, b), "create bundle")
	if b.ID.String() == "" {
		t.Fatal("expected bundle ID to be populated")
	}

	obj := &StixObject{
		StixID:   "indicator--" + uuid.NewString(),
		StixType: "indicator",
		BundleID: b.ID,
		Content:  []byte(`{"type":"indicator","pattern":"[ipv4-addr:value = '1.2.3.4']"}`),
	}
	mustOK(t, s.InsertObject(ctx, obj), "insert object")

	// Re-inserting the same stix_id is idempotent (ON CONFLICT DO NOTHING).
	mustOK(t, s.InsertObject(ctx, &StixObject{
		StixID:   obj.StixID,
		StixType: "indicator",
		BundleID: b.ID,
		Content:  []byte(`{"type":"indicator"}`),
	}), "insert duplicate object")

	objs, err := s.ObjectsForBundle(ctx, b.ID)
	mustOK(t, err, "objects for bundle")
	if len(objs) != 1 {
		t.Fatalf("len(objs) = %d, want 1", len(objs))
	}
	if objs[0].StixID != obj.StixID {
		t.Errorf("StixID = %q, want %q", objs[0].StixID, obj.StixID)
	}
}

func TestIntegration_Stix_CreateBundle_DuplicateStixIDUpdatesInPlace(t *testing.T) {
	pool := testDB(t)
	s := NewStixStore(pool)
	ctx := context.Background()

	stixID := "bundle--" + uuid.NewString()
	b1 := &StixBundle{StixID: stixID, Direction: "import", Source: "feed", ObjectCount: 1, BundleHash: "h1"}
	mustOK(t, s.CreateBundle(ctx, b1), "create bundle 1")

	b2 := &StixBundle{StixID: stixID, Direction: "import", Source: "feed", ObjectCount: 5, BundleHash: "h1"}
	mustOK(t, s.CreateBundle(ctx, b2), "create bundle 2 (conflict)")

	if b1.ID != b2.ID {
		t.Errorf("expected same bundle ID on conflict, got %s vs %s", b1.ID, b2.ID)
	}

	got, err := s.GetBundle(ctx, b1.ID)
	mustOK(t, err, "get bundle")
	if got.ObjectCount != 5 {
		t.Errorf("ObjectCount = %d, want 5 (updated by conflict)", got.ObjectCount)
	}

	if _, err := s.GetBundle(ctx, uuid.New()); err != ErrNotFound {
		t.Errorf("want ErrNotFound for unknown bundle, got %v", err)
	}
}

func TestIntegration_Stix_ListBundles_FiltersByDirectionAndPaginates(t *testing.T) {
	pool := testDB(t)
	s := NewStixStore(pool)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		mustOK(t, s.CreateBundle(ctx, &StixBundle{
			StixID: "bundle--" + uuid.NewString(), Direction: "import", Source: "feed",
			ObjectCount: 1, BundleHash: itoa(i),
		}), "create inbound")
	}
	mustOK(t, s.CreateBundle(ctx, &StixBundle{
		StixID: "bundle--" + uuid.NewString(), Direction: "export", Source: "feed",
		ObjectCount: 1, BundleHash: "out",
	}), "create outbound")

	inbound, total, err := s.ListBundles(ctx, "import", 0, 0)
	mustOK(t, err, "list inbound")
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if len(inbound) != 3 {
		t.Errorf("len(inbound) = %d, want 3", len(inbound))
	}

	all, totalAll, err := s.ListBundles(ctx, "", 2, 0)
	mustOK(t, err, "list all limited")
	if totalAll != 4 {
		t.Errorf("totalAll = %d, want 4", totalAll)
	}
	if len(all) != 2 {
		t.Errorf("len(all) with limit=2 = %d, want 2", len(all))
	}
}
