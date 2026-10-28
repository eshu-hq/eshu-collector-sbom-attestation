# Contributing

The test suite is the product contract: the parity, hostile-input, and
boundary tests must stay green. Never weaken them to land a change.

Credentials travel by env reference, never inline. Tests inject stub
providers and resolvers. Never log a token, password, URL, or provider
body.

## Local checks

You need Go (see `go.mod`), `golangci-lint` v2.12.2, and Docker for the
image lane.

```sh
make ci   # lint + test + race, the whole local contract
```

`make lint` runs `go vet`, whole-repo `golangci-lint run` (config in
`.golangci.yml`, org lint set; no baselines), the gofumpt format check,
`go mod tidy -diff`, and the 500-line cap on `.go` files. `make race`
also enforces the statement-coverage floor (`COVERAGE_FLOOR`, may only
rise toward the 90% finish line). `make actionlint` mirrors the
actionlint lane.

## CI lanes

`.github/workflows/ci.yml` runs a `changes` job first, so a PR only pays
for lanes its paths can affect: Go sources run `lint`, `test`, `race`,
`image`, `boundary`, `govulncheck`, and `gosec`; fixtures and embedded config
(`testdata/**`, `**/*.json`, `manifest.yaml`) run `test` only; shell
scripts run `shell` only (no test executes `scripts/pin-digest.sh`, so a
shell-only change never pays for `test`); `Dockerfile`, `.dockerignore`,
and `manifest.yaml` run `image`; dependency changes run `govulncheck`;
workflow changes run `actionlint` plus the Go lanes. Anything
unclassified runs the full Go lanes (fail closed). `ci-complete` is the
only required check: it fails when a needed lane fails and passes when
lanes were legitimately skipped (docs-only PRs).

The manifest keeps the all-zero placeholder digest permanently:
`manifest.yaml` is `go:embed`'d into the binary, so a committed digest
could only describe an older build (`manifest_test.go`,
`TestManifestReleaseProvenance`). Deployments stamp the digest they
pulled with `collector seed --image-ref`. The `image` lane fails loud
on any manifest image that is neither the placeholder nor a real
digest pin.

Coverage stands at 90.4% of statements (`COVERAGE_FLOOR`, ratcheted from
the 68.9% epic baseline through 71.0%); the floor may only rise. Weekly,
`govulncheck` and `gosec` (SARIF to the Security tab, advisory until its
false-positive rate is measured) run on a schedule and file an issue on
findings. Dependabot proposes weekly grouped `gomod` and
`github-actions` bumps.
