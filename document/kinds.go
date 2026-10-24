// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package document

// Provenance: fact-kind vocabulary ported from
// go/internal/facts/supply/chain/sbom_attestation.go at core commit
// 695a0e0d9b. All eight kinds share schema 1.1.0
// (SBOMAttestationSchemaVersionV1); the grant census lives core-side until
// cutover.

const (
	// SBOMDocumentFactKind identifies one parsed or attempted SBOM document.
	SBOMDocumentFactKind = "sbom.document"
	// SBOMComponentFactKind identifies one component from an SBOM document.
	SBOMComponentFactKind = "sbom.component"
	// SBOMDependencyRelationshipFactKind identifies one SBOM dependency edge.
	SBOMDependencyRelationshipFactKind = "sbom.dependency_relationship"
	// SBOMExternalReferenceFactKind identifies one SBOM external reference.
	SBOMExternalReferenceFactKind = "sbom.external_reference"
	// AttestationStatementFactKind identifies one in-toto statement envelope.
	AttestationStatementFactKind = "attestation.statement"
	// AttestationSLSAProvenanceFactKind identifies one SLSA provenance predicate.
	AttestationSLSAProvenanceFactKind = "attestation.slsa_provenance"
	// AttestationSignatureVerificationFactKind identifies one signature verification result.
	AttestationSignatureVerificationFactKind = "attestation.signature_verification"
	// SBOMWarningFactKind identifies non-fatal SBOM or attestation warnings.
	SBOMWarningFactKind = "sbom.warning"

	// SBOMAttestationSchemaVersionV1 is the shared schema version for all
	// eight kinds.
	SBOMAttestationSchemaVersionV1 = "1.1.0"
)

// SBOMAttestationFactKinds returns the eight fact kinds this collector emits.
func SBOMAttestationFactKinds() []string {
	return []string{
		SBOMDocumentFactKind,
		SBOMComponentFactKind,
		SBOMDependencyRelationshipFactKind,
		SBOMExternalReferenceFactKind,
		AttestationStatementFactKind,
		AttestationSLSAProvenanceFactKind,
		AttestationSignatureVerificationFactKind,
		SBOMWarningFactKind,
	}
}

// SBOMAttestationSchemaVersion returns the schema version for one fact kind.
func SBOMAttestationSchemaVersion(factKind string) (string, bool) {
	switch factKind {
	case SBOMDocumentFactKind,
		SBOMComponentFactKind,
		SBOMDependencyRelationshipFactKind,
		SBOMExternalReferenceFactKind,
		AttestationStatementFactKind,
		AttestationSLSAProvenanceFactKind,
		AttestationSignatureVerificationFactKind,
		SBOMWarningFactKind:
		return SBOMAttestationSchemaVersionV1, true
	default:
		return "", false
	}
}
