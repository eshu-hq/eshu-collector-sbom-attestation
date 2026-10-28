// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Shape tests for the caller-side artifact and security-reporting jobs:
// the image lane must run on Go-source changes (the Dockerfile builds the
// binary from the whole context), and the gosec SARIF upload must stay
// non-PR-only without continue-on-error.
// Shared workflow types and readers live in ci_workflow_test.go.
package collector

import (
	"os"
	"strings"
	"testing"
)

// imageLaneClauseProblems returns every way cond breaks the image-lane
// selection contract: the image embeds Go sources and the whole build
// context, so the run-image wiring must fire when the go or misc change
// class is true. A bare substring check accepts an inverted comparison,
// which selects the lane exactly when the class did not change and skips
// it when it did.
func imageLaneClauseProblems(cond string) []string {
	var problems []string
	for _, class := range []string{"go", "misc"} {
		want := "needs.changes.outputs." + class + " == 'true'"
		if !strings.Contains(cond, want) {
			problems = append(problems, "run-image lacks \""+want+"\": Go sources and the whole context ship in the image")
		}
		for _, inverted := range []string{
			"needs.changes.outputs." + class + " != 'true'",
			"needs.changes.outputs." + class + " == 'false'",
			"needs.changes.outputs." + class + " != 'false'",
		} {
			if strings.Contains(cond, inverted) {
				problems = append(problems, "run-image contains inverted clause "+inverted)
			}
		}
	}
	return problems
}

// TestImageLaneRunsOnGoSources keeps the shipped artifact validated on
// PRs that change what it embeds: the Dockerfile COPYs go.mod/go.sum,
// COPYs the whole context (which keeps .go sources), and go-builds the
// binary, so a Go-source or go.mod PR must select the image lane. A
// go.mod toolchain bump past the pinned base would otherwise pass every
// Go lane yet break docker build, surfacing only as post-merge red main.
// Unclassified files ride along too: the image embeds the whole build
// context, so a misc-only change could still affect the build.
// The live ci.yml wiring must pass; an inverted or removed go or misc
// clause must fail. The image-command must keep the seed contract and
// the manifest digest checks the reusable cannot own.
func TestImageLaneRunsOnGoSources(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	call, ok := workflow.Jobs["go-ci"]
	if !ok {
		t.Fatal("ci.yml has no go-ci job")
	}
	runImage, _ := call.With["run-image"].(string)
	if problems := imageLaneClauseProblems(runImage); len(problems) > 0 {
		t.Errorf("image lane breaks its selection contract:\n%s", strings.Join(problems, "\n"))
	}

	invertedGo := strings.Replace(runImage, "needs.changes.outputs.go == 'true'", "needs.changes.outputs.go != 'true'", 1)
	if len(imageLaneClauseProblems(invertedGo)) == 0 {
		t.Errorf("inverted go clause: the gate accepted a lane that skips Go-source PRs")
	}
	invertedMisc := strings.Replace(runImage, "needs.changes.outputs.misc == 'true'", "needs.changes.outputs.misc != 'true'", 1)
	if len(imageLaneClauseProblems(invertedMisc)) == 0 {
		t.Errorf("inverted misc clause: the gate accepted a lane that skips misc-only PRs")
	}
	removedGo := strings.ReplaceAll(runImage, "needs.changes.outputs.go == 'true'", "")
	if len(imageLaneClauseProblems(removedGo)) == 0 {
		t.Errorf("removed go clause: the gate accepted a lane with no go selection")
	}

	imageCommand, _ := call.With["image-command"].(string)
	for _, want := range []string{"seed --dest", "manifest.yaml", "Dockerfile"} {
		if !strings.Contains(imageCommand, want) {
			t.Errorf("image-command lacks %q: the seed contract and digest pins must ride the reusable image lane", want)
		}
	}

	// The go class must actually select .go sources and the module
	// files, or the lane clause above never fires.
	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	filters := text[strings.Index(text, "filters: |"):]
	goIdx := strings.Index(filters, "\n            go:\n")
	fixIdx := strings.Index(filters, "\n            fixtures:\n")
	if goIdx < 0 || fixIdx < 0 || fixIdx < goIdx {
		t.Fatal("ci.yml changes job has no go class before the fixtures class")
	}
	goClass := filters[goIdx:fixIdx]
	for _, want := range []string{"'**/*.go'", "'go.mod'", "'go.sum'"} {
		if !strings.Contains(goClass, want) {
			t.Errorf("go class lacks %q: a Go-source or go.mod PR would never select the go lanes", want)
		}
	}
}

// gosecUploadProblems returns every way the gosec SARIF upload step breaks
// its non-PR-only contract: fork PRs cannot write code-scanning results,
// so the step must skip them via the event gate (not fail on them), and it
// must fail loud on push/schedule where the token carries
// security-events:write — continue-on-error would turn a real failure
// into a silent green run with no Security-tab SARIF.
func gosecUploadProblems(upload workflowStep) []string {
	var problems []string
	if !strings.Contains(upload.If, "github.event_name != 'pull_request'") {
		problems = append(problems, "gosec upload step if lacks the non-PR gate (fork PRs would fail on code-scanning write)")
	}
	if upload.ContinueOnError {
		problems = append(problems, "gosec upload step sets continue-on-error (a real push/schedule failure goes silent)")
	}
	return problems
}

// TestGosecUploadRunsOnNonPRWithoutContinueOnError pins the SARIF upload
// shape on the caller-side job: the live ci.yml text must pass, and a
// silenced or ungated upload mutant must fail. The job rehydrates the
// upstream gosec artifact, so the SARIF the tab shows is the scanned one.
func TestGosecUploadRunsOnNonPRWithoutContinueOnError(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	job, ok := workflow.Jobs["gosec-sarif"]
	if !ok {
		t.Fatal("ci.yml has no gosec-sarif job")
	}
	downloadIdx := stepIndex(job.Steps, func(s workflowStep) bool {
		name, _ := s.With["name"].(string)
		return strings.Contains(s.Uses, "download-artifact") && strings.Contains(name, "gosec-sbom-attestation")
	})
	uploadIdx := stepIndex(job.Steps, func(s workflowStep) bool { return strings.Contains(s.Uses, "upload-sarif") })
	if downloadIdx < 0 {
		t.Error("gosec-sarif job rehydrates no gosec-sbom-attestation artifact")
	}
	if uploadIdx < 0 {
		t.Fatal("gosec-sarif job has no upload-sarif step")
	}
	// The non-PR gate lives on the job in the caller shape (fork PRs skip
	// the whole job); merge it into the step view the contract checks.
	upload := job.Steps[uploadIdx]
	upload.If = job.If + " " + upload.If
	if problems := gosecUploadProblems(upload); len(problems) > 0 {
		t.Errorf("gosec SARIF upload breaks its contract:\n%s", strings.Join(problems, "\n"))
	}

	quiet := upload
	quiet.ContinueOnError = true
	if len(gosecUploadProblems(quiet)) == 0 {
		t.Errorf("continue-on-error upload: the gate accepted a silenced failure")
	}
	ungated := upload
	ungated.If = ""
	if len(gosecUploadProblems(ungated)) == 0 {
		t.Errorf("ungated upload: the gate accepted a step without the non-PR gate")
	}
}
