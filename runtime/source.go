// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package runtime

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/document"
	"github.com/eshu-hq/eshu-collector-sbom-attestation/urlredact"
)

// DocumentProvider fetches one bounded SBOM or attestation document.
type DocumentProvider interface {
	FetchDocument(context.Context, TargetConfig) (Document, error)
}

// Document is the parser input returned by a hosted document provider.
type Document struct {
	Body           []byte
	SourceURI      string
	SourceRecordID string
	MediaType      string
	ObservedAt     time.Time
}

// ClaimedSource implements collector.ClaimedSource for hosted SBOM and
// attestation targets.
type ClaimedSource struct {
	collectorInstanceID string
	targets             map[string]TargetConfig
	provider            DocumentProvider
	now                 func() time.Time
}

// NewClaimedSource validates configuration and builds a claim-driven source.
func NewClaimedSource(config SourceConfig) (*ClaimedSource, error) {
	collectorID := strings.TrimSpace(config.CollectorInstanceID)
	if collectorID == "" {
		return nil, fmt.Errorf("SBOM attestation collector instance ID is required")
	}
	if config.Provider == nil {
		return nil, fmt.Errorf("SBOM attestation document provider is required")
	}
	targets := make(map[string]TargetConfig, len(config.Targets))
	for i, target := range config.Targets {
		validated, err := target.validate()
		if err != nil {
			return nil, fmt.Errorf("target %d: %w", i, err)
		}
		if _, exists := targets[validated.ScopeID]; exists {
			return nil, fmt.Errorf("duplicate SBOM attestation target scope_id %q", validated.ScopeID)
		}
		targets[validated.ScopeID] = validated
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one SBOM attestation target is required")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &ClaimedSource{
		collectorInstanceID: collectorID,
		targets:             targets,
		provider:            config.Provider,
		now:                 now,
	}, nil
}

// NextClaimed collects the hosted SBOM or attestation target named by the
// claim. The SDK claim carries the core-owned work-item identity; the static
// config authorizes targets. A delivered claim IS claimed work: the
// claimed-status gate lives host-side now.
func (s *ClaimedSource) NextClaimed(
	ctx context.Context,
	claim sdkcollector.Claim,
) (CollectedSnapshot, bool, error) {
	if strings.TrimSpace(claim.InstanceID) != s.collectorInstanceID {
		return CollectedSnapshot{}, false, fmt.Errorf(
			"SBOM attestation claim collector_instance_id %q does not match source %q",
			claim.InstanceID,
			s.collectorInstanceID,
		)
	}
	if strings.TrimSpace(claim.CollectorKind) != "" && claim.CollectorKind != CollectorKind {
		return CollectedSnapshot{}, false, fmt.Errorf(
			"SBOM attestation source cannot collect %q claims",
			claim.CollectorKind,
		)
	}
	// The SDK requires every fact's source system to equal the claim's, so
	// a claim with no source system can never produce host-acceptable
	// facts: fail fast here instead of emitting work the host must reject.
	if strings.TrimSpace(claim.SourceSystem) == "" {
		return CollectedSnapshot{}, false, fmt.Errorf("SBOM attestation claim source_system is required")
	}
	if claim.SourceSystem != CollectorKind {
		return CollectedSnapshot{}, false, fmt.Errorf(
			"SBOM attestation claim source_system %q must be %q",
			claim.SourceSystem,
			CollectorKind,
		)
	}
	generationID := strings.TrimSpace(claim.GenerationID)
	if generationID == "" {
		return CollectedSnapshot{}, false, fmt.Errorf("SBOM attestation claim generation_id is required")
	}
	// FencingToken arrives on the claim as a string and must round-trip to
	// int64: a present-but-unparseable token is a caller error, never a
	// silent zero.
	var fencingToken int64
	if raw := strings.TrimSpace(string(claim.FencingToken)); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return CollectedSnapshot{}, false, fmt.Errorf("SBOM attestation claim fencing_token %q does not round-trip to int64: %w", claim.FencingToken, err)
		}
		fencingToken = parsed
	}
	target, ok := s.targets[strings.TrimSpace(claim.Scope.ID)]
	if !ok {
		return CollectedSnapshot{}, false, fmt.Errorf(
			"SBOM attestation target scope_id %q is not configured for collector instance %q",
			claim.Scope.ID,
			s.collectorInstanceID,
		)
	}
	item := workItem{
		ScopeID:             target.ScopeID,
		GenerationID:        generationID,
		CollectorInstanceID: s.collectorInstanceID,
		CollectorKind:       CollectorKind,
		CurrentFencingToken: fencingToken,
	}
	fetched, err := s.provider.FetchDocument(ctx, target)
	if err != nil {
		return CollectedSnapshot{}, false, fmt.Errorf("fetch SBOM attestation document: %w", err)
	}
	// The advertised MaxBytes bound is enforced here, at the only choke
	// point every provider flows through; the live transport's readBounded
	// stays core-side with the registry lane. Mirrors its limit semantics:
	// non-positive falls back to the default, oversize fails closed.
	maxBytes := target.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxDocumentBytes
	}
	if int64(len(fetched.Body)) > maxBytes {
		return CollectedSnapshot{}, false, fmt.Errorf("SBOM attestation document exceeds max_bytes")
	}
	envs, observedAt, err := s.envelopes(item, target, fetched)
	if err != nil {
		return CollectedSnapshot{}, false, err
	}
	return CollectedSnapshot{
		Scope:      ScopeInfo{ScopeID: target.ScopeID, ScopeKind: ScopeKind, CollectorKind: CollectorKind},
		Generation: GenerationInfo{GenerationID: generationID, ObservedAt: observedAt},
		Envelopes:  envs,
	}, true, nil
}

func (s *ClaimedSource) envelopes(
	item workItem,
	target TargetConfig,
	document Document,
) ([]Envelope, time.Time, error) {
	observedAt := document.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = s.now().UTC()
	}
	sourceURI := safeSourceURI(firstNonBlank(document.SourceURI, target.SourceURI, target.DocumentURL, target.Registry))
	sourceRecordID := firstNonBlank(document.SourceRecordID, target.SourceRecordID, target.ReferrerDigest, target.DocumentURL, target.ScopeID)
	// Extraction boundary (in-tree parity pin holds this channel open and
	// names this refusal): a record ID that carries userinfo fails closed
	// instead of shipping a credential into envelopes. In-tree bytes stay
	// frozen for cutover comparability; the extracted producer refuses.
	// Operators carry credentials by env reference, never inline.
	if urlredact.CarriesUserinfo(sourceRecordID) {
		return nil, time.Time{}, fmt.Errorf("SBOM attestation scope %q carries a credential-bearing record ID: configure an explicit source_record_id and carry credentials by env reference", target.ScopeID)
	}
	switch target.ArtifactKind {
	case ArtifactKindSBOM:
		envs, err := envelopes(item, target, document.Body, observedAt, sourceURI, sourceRecordID)
		return envs, observedAt, err
	case ArtifactKindAttestation:
		envs, err := attestationEnvelopes(item, target, document.Body, observedAt, sourceURI, sourceRecordID)
		return envs, observedAt, err
	default:
		return nil, time.Time{}, fmt.Errorf("unsupported artifact_kind %q", target.ArtifactKind)
	}
}

func envelopes(
	item workItem,
	target TargetConfig,
	raw []byte,
	observedAt time.Time,
	sourceURI string,
	sourceRecordID string,
) ([]Envelope, error) {
	ctx := document.FixtureContext{
		ScopeID:             target.ScopeID,
		GenerationID:        item.GenerationID,
		CollectorInstanceID: strings.TrimSpace(item.CollectorInstanceID),
		FencingToken:        item.CurrentFencingToken,
		ObservedAt:          observedAt,
		SourceURI:           sourceURI,
		SourceRecordID:      sourceRecordID,
	}
	switch target.DocumentFormat {
	case DocumentFormatCycloneDX:
		return document.CycloneDXFixtureEnvelopes(raw, ctx)
	case DocumentFormatSPDX:
		return document.SPDXFixtureEnvelopes(raw, ctx)
	default:
		return nil, fmt.Errorf("unsupported SBOM document_format %q", target.DocumentFormat)
	}
}

func safeSourceURI(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" {
		return ""
	}
	if parsed.Host == "" && urlredact.CarriesUserinfo(trimmed) {
		// Not hierarchical, so User can be nil with a credential in plain
		// sight (`svc:SECRET@host/x` keeps it in Opaque, which String()
		// round-trips verbatim). A purl's "@" sits after the first "/", so
		// purls keep flowing; only an authority-shaped credential drops.
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}

// CI-SEED round R (RED proof, will revert): unused function trips lint.
func ciSeedUnused() {}
