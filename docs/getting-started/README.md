# Getting started

Here's the fastest honest path from a fresh checkout to a working collector, with no steps skipped just because they're boring.

## First, say hello locally

You need Go at the version pinned in `go.mod`. Clone the repository, then run the same checks CI runs:

```bash
make ci   # lint + test + race
```

If that's green, your checkout is healthy. `make test` alone builds everything and runs the full suite when you want a quicker loop.

## Understand how Eshu will run it

You won't normally start this program yourself and leave it running. Eshu's component host starts it for one claim at a time, sends one bounded `collector-sdk/v1alpha1` request on stdin, and reads one result from stdout:

```bash
collector --sdk-stdio   # serve one claim from stdin
```

That's the whole runtime shape. The [claim lifecycle diagram](../diagrams/README.md#claim-lifecycle) draws it, and [concepts](../concepts/README.md) walks through what happens in between. To install the binary where a host expects it, the image can seed itself into a component folder. The [guides](../guides/README.md) cover that step by step, and the [deployment diagram](../diagrams/README.md#deployment-and-seed) shows the shape.

## Set up your first target

There's no config file to write for a first local look. The host normally passes setup as JSON on each request, and [the configuration reference](../reference/configuration.md) shows that shape. For now, building and testing the binary is the honest first success, and the sample documents under `document/testdata/` (listed in [examples](../../examples/README.md)) show exactly what it happily parses.

When you're ready to operate it for real, head to the [guides](../guides/README.md) for seeding, day-to-day signals, and troubleshooting.
