package stix

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/attack"
	"github.com/opensecstack/threatflow/internal/correlate"
	"github.com/opensecstack/threatflow/internal/db/store"
)

// Importer converts parsed STIX bundles into ThreatFlow rows (stix_bundles,
// stix_objects, iocs, ttp_tags, ioc_correlations). All DB operations use
// upserts so re-importing the same bundle is idempotent.
type Importer struct {
	stix       *store.StixStore
	iocs       *store.IOCStore
	ttps       *store.TTPStore
	correlator *correlate.Engine
	logger     zerolog.Logger
}

// NewImporter wires a bundle Importer. ttpStore and correlator may be nil;
// when absent the importer still runs but skips the corresponding enrichment.
func NewImporter(stix *store.StixStore, iocs *store.IOCStore, ttps *store.TTPStore, correlator *correlate.Engine, logger zerolog.Logger) *Importer {
	return &Importer{
		stix:       stix,
		iocs:       iocs,
		ttps:       ttps,
		correlator: correlator,
		logger:     logger.With().Str("component", "stix-importer").Logger(),
	}
}

// ImportResult summarises a single bundle import.
type ImportResult struct {
	BundleID       uuid.UUID `json:"bundle_id"`
	ObjectsStored  int       `json:"objects_stored"`
	IndicatorsSeen int       `json:"indicators_seen"`
	IOCsUpserted   int       `json:"iocs_upserted"`
	TTPsTagged     int       `json:"ttps_tagged"`
	Correlations   int       `json:"correlations"`
	Skipped        int       `json:"skipped"`
}

// Import parses, validates, and persists a STIX bundle.
func (i *Importer) Import(ctx context.Context, payload []byte, source string, feedID *uuid.UUID) (*ImportResult, error) {
	b, err := ParseBundle(payload)
	if err != nil {
		return nil, err
	}
	objects, err := DecodeObjects(b)
	if err != nil {
		return nil, err
	}

	bundleRow := &store.StixBundle{
		StixID:      b.ID,
		Direction:   "import",
		Source:      source,
		ObjectCount: len(objects),
		BundleHash:  store.HashBundle(payload),
	}
	if err := i.stix.CreateBundle(ctx, bundleRow); err != nil {
		return nil, fmt.Errorf("persist bundle: %w", err)
	}

	res := &ImportResult{BundleID: bundleRow.ID}

	for _, obj := range objects {
		res.ObjectsStored++
		stixObj := &store.StixObject{
			StixID:   obj.ID,
			StixType: obj.Type,
			BundleID: bundleRow.ID,
			Content:  obj.Raw,
		}
		if err := i.stix.InsertObject(ctx, stixObj); err != nil {
			i.logger.Warn().Err(err).Str("stix_id", obj.ID).Msg("store object")
			continue
		}

		ind, ok, err := AsIndicator(obj)
		if err != nil || !ok {
			continue
		}
		res.IndicatorsSeen++

		ioc := indicatorToIOC(ind, source, feedID)
		if ioc == nil {
			res.Skipped++
			continue
		}
		if err := i.iocs.Upsert(ctx, ioc); err != nil {
			i.logger.Warn().Err(err).Str("stix_id", ind.ID).Msg("upsert ioc")
			res.Skipped++
			continue
		}
		res.IOCsUpserted++

		if i.ttps != nil {
			tagged, err := i.tagTechniques(ctx, ioc, ind)
			if err != nil {
				i.logger.Warn().Err(err).Str("ioc_id", ioc.ID.String()).Msg("tag ttps")
			}
			res.TTPsTagged += tagged
		}

		if i.correlator != nil {
			linked, err := i.correlator.CorrelateIOC(ctx, ioc)
			if err != nil {
				i.logger.Warn().Err(err).Str("ioc_id", ioc.ID.String()).Msg("correlate")
			}
			res.Correlations += linked
		}
	}

	return res, nil
}

// tagTechniques derives ATT&CK mappings from the indicator and persists them.
func (i *Importer) tagTechniques(ctx context.Context, ioc *store.IOC, ind Indicator) (int, error) {
	feedMappings := attack.Merge(
		attack.FromKillChainPhases(killChainToAttack(ind.KillChain)),
		attack.FromExternalRefs(externalRefsToAttack(ind.ExternalRefs)),
	)
	autoMappings := attack.Auto(ioc.Type, ioc.Tags)
	all := attack.Merge(feedMappings, autoMappings)
	if len(all) == 0 {
		return 0, nil
	}

	tags := make([]*store.TTPTag, 0, len(all))
	for _, m := range all {
		tags = append(tags, &store.TTPTag{
			IOCID:       ioc.ID,
			TechniqueID: m.TechniqueID,
			Source:      string(m.Source),
			Confidence:  m.Confidence,
		})
	}
	if err := i.ttps.UpsertMany(ctx, tags); err != nil {
		return 0, err
	}
	return len(tags), nil
}

// killChainToAttack converts stix.KillChainPhase slices to the attack package's
// local mirror type so that /internal/attack does not need to import /stix.
func killChainToAttack(phases []KillChainPhase) []attack.StixKillChainPhase {
	out := make([]attack.StixKillChainPhase, 0, len(phases))
	for _, p := range phases {
		out = append(out, attack.StixKillChainPhase{
			KillChainName: p.KillChainName,
			PhaseName:     p.PhaseName,
		})
	}
	return out
}

func externalRefsToAttack(refs []ExternalRef) []attack.StixExternalRef {
	out := make([]attack.StixExternalRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, attack.StixExternalRef{
			SourceName: r.SourceName,
			ExternalID: r.ExternalID,
			URL:        r.URL,
		})
	}
	return out
}

// indicatorToIOC converts a STIX Indicator to a ThreatFlow IOC row. Returns
// nil when the pattern cannot be parsed (compound patterns, LIKE/MATCHES, etc.)
func indicatorToIOC(ind Indicator, source string, feedID *uuid.UUID) *store.IOC {
	iocType, value, err := PrimaryIOC(ind.Pattern)
	if err != nil {
		if errors.Is(err, ErrUnsupportedPattern) {
			return nil
		}
		return nil
	}

	confidence := ind.Confidence
	if confidence == 0 {
		confidence = 50
	}

	description := ind.Description
	if description == "" {
		description = ind.Name
	}

	tags := dedupStrings(ind.IndicatorTypes, ind.Labels)

	return &store.IOC{
		StixID:      ind.ID,
		Type:        iocType,
		Value:       value,
		Pattern:     ind.Pattern,
		FeedID:      feedID,
		Source:      source,
		Confidence:  confidence,
		Description: description,
		Tags:        tags,
		Revoked:     ind.Revoked,
	}
}

func dedupStrings(sets ...[]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, set := range sets {
		for _, s := range set {
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	if out == nil {
		return []string{}
	}
	return out
}
