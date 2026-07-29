package csaf

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/db/store"
)

// Importer ingests CSAF 2.0 advisory documents: parse + validate, map to
// STIX 2.1 Vulnerability objects plus advisory-specific rows, and persist
// both under the revision/dedup semantics documented on
// store.AdvisoryStore.UpsertRevision. Mirrors the shape of
// internal/stix.Importer (see threatflow/adrs/004-opencsirt-advisory-ingestion-gap.md
// for why the two are not the same importer).
type Importer struct {
	advisories *store.AdvisoryStore
	stix       *store.StixStore
	logger     zerolog.Logger
}

// NewImporter wires a CSAF Importer. Both stores are required — unlike
// internal/stix.Importer, there is no "scaffold" (nil-store) mode here
// because the handler already provides that fallback (see
// handlers.Advisory.Ingest) before ever calling Ingest.
func NewImporter(advisories *store.AdvisoryStore, stixStore *store.StixStore, logger zerolog.Logger) *Importer {
	return &Importer{
		advisories: advisories,
		stix:       stixStore,
		logger:     logger.With().Str("component", "csaf-importer").Logger(),
	}
}

// IngestResult summarises one CSAF ingestion call.
type IngestResult struct {
	AdvisoryID            string               `json:"advisory_id"`
	TrackingID            string               `json:"tracking_id"`
	Revision              string               `json:"revision"`
	Action                store.AdvisoryAction `json:"action"`
	VulnerabilitiesMapped int                  `json:"vulnerabilities_mapped"`
	ProductsMapped        int                  `json:"products_mapped"`
}

// Ingest parses, maps, and persists a single CSAF 2.0 document. payload is
// the raw request body exactly as received (used for content-addressed
// dedup evidence in advisory_revisions.document_hash).
func (i *Importer) Ingest(ctx context.Context, payload []byte, source string) (*IngestResult, error) {
	doc, err := ParseDocument(payload)
	if err != nil {
		return nil, err
	}

	mapped, err := Map(doc, source)
	if err != nil {
		return nil, fmt.Errorf("map csaf document: %w", err)
	}

	// Persist STIX objects first — advisory_vulnerabilities.stix_object_ref
	// is a foreign key into stix_objects.stix_id, so the referenced rows
	// must exist before AdvisoryStore.UpsertRevision writes the vulnerability
	// rows that point at them. This mirrors internal/stix.Importer's own
	// bundle-then-objects ordering.
	if len(mapped.StixObjects) > 0 {
		bundleRow := &store.StixBundle{
			StixID:      mapped.StixBundleID,
			Direction:   "import",
			Source:      source,
			ObjectCount: len(mapped.StixObjects),
			BundleHash:  store.HashBundle(payload),
		}
		if err := i.stix.CreateBundle(ctx, bundleRow); err != nil {
			return nil, fmt.Errorf("persist stix bundle: %w", err)
		}
		mapped.Advisory.StixBundleID = &bundleRow.ID

		for _, obj := range mapped.StixObjects {
			row := &store.StixObject{
				StixID:   obj.StixID,
				StixType: "vulnerability",
				BundleID: bundleRow.ID,
				Content:  obj.Content,
			}
			if err := i.stix.InsertObject(ctx, row); err != nil {
				return nil, fmt.Errorf("persist stix vulnerability %s: %w", obj.StixID, err)
			}
		}
	}

	res, err := i.advisories.UpsertRevision(ctx, &store.UpsertAdvisoryInput{
		Advisory:        mapped.Advisory,
		Vulnerabilities: mapped.Vulnerabilities,
		Products:        mapped.Products,
		DocumentHash:    store.HashBundle(payload),
	})
	if err != nil {
		return nil, fmt.Errorf("upsert advisory revision: %w", err)
	}

	return &IngestResult{
		AdvisoryID:            res.Advisory.ID.String(),
		TrackingID:            res.Advisory.TrackingID,
		Revision:              res.Advisory.Revision,
		Action:                res.Action,
		VulnerabilitiesMapped: len(mapped.Vulnerabilities),
		ProductsMapped:        len(mapped.Products),
	}, nil
}
