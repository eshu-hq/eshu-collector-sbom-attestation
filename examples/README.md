# Examples

This repo doesn't ship runnable example apps. What it does ship is a set of real sample documents the tests parse, and they're the quickest way to see what the collector accepts. Each link below points at the canonical file, so what you read is exactly what the tests read. Nothing here is a copy.

- [document/testdata/cyclonedx_image_subject.json](../document/testdata/cyclonedx_image_subject.json) is a healthy CycloneDX SBOM for a container image. Open it to see the shape of a document that parses cleanly into component and dependency facts.
- [document/testdata/spdx_image_subject.json](../document/testdata/spdx_image_subject.json) is the SPDX counterpart for the same kind of image subject. Handy if you're comparing the two formats side by side.
- [document/testdata/cyclonedx_malformed.json](../document/testdata/cyclonedx_malformed.json) and [document/testdata/spdx_malformed.json](../document/testdata/spdx_malformed.json) are deliberately broken documents. They exist to prove the parser fails cleanly instead of guessing.
- [document/testdata/cyclonedx_missing_subject.json](../document/testdata/cyclonedx_missing_subject.json) and [document/testdata/spdx_missing_subject.json](../document/testdata/spdx_missing_subject.json) leave out the subject the document describes. These cover the "well-formed but incomplete" path.
- [runtime/testdata/8865-parity-sbom-attestation.json](../runtime/testdata/8865-parity-sbom-attestation.json) holds the expected fact envelopes for a known input. If you want to see facts out rather than documents in, start here.

New to the flow? Read [concepts](../docs/concepts/README.md) first, then come back and poke at these files.
