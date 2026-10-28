// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	pinnedAction     = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$`)
	secretUsePattern = regexp.MustCompile(`secrets\.([A-Za-z0-9_]+)`)
	// reusableCall pins the shared lane bodies: full path, full commit
	// SHA, never a mutable tag.
	reusableCall = regexp.MustCompile(`^eshu-hq/\.github/\.github/workflows/go-collector-ci\.yml@[0-9a-f]{40}$`)
)

type workflowStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	// If holds the step's `if:` condition; ContinueOnError holds
	// `continue-on-error:`. Both default to the zero value when absent.
	If              string `yaml:"if"`
	ContinueOnError bool   `yaml:"continue-on-error"`
}

// needsList accepts the scalar (`needs: changes`) and sequence
// (`needs: [a, b]`) forms GitHub allows.
type needsList []string

func (n *needsList) UnmarshalYAML(value *yaml.Node) error {
	var single string
	if err := value.Decode(&single); err == nil {
		*n = []string{single}
		return nil
	}
	var multi []string
	if err := value.Decode(&multi); err != nil {
		return err
	}
	*n = multi
	return nil
}

type workflowJob struct {
	Needs       needsList         `yaml:"needs"`
	If          string            `yaml:"if"`
	Uses        string            `yaml:"uses"`
	With        map[string]any    `yaml:"with"`
	Permissions map[string]string `yaml:"permissions"`
	Timeout     int               `yaml:"timeout-minutes"`
	Env         map[string]string `yaml:"env"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowFile struct {
	On          map[string]any         `yaml:"on"`
	Permissions map[string]string      `yaml:"permissions"`
	Concurrency map[string]any         `yaml:"concurrency"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

// stepIndex returns the position of the first step for which match is true,
// or -1.
func stepIndex(steps []workflowStep, match func(workflowStep) bool) int {
	for i, step := range steps {
		if match(step) {
			return i
		}
	}
	return -1
}

func readCIWorkflow(t *testing.T) workflowFile {
	t.Helper()

	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow workflowFile
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	if len(workflow.Jobs) == 0 {
		t.Fatal("ci.yml defines no jobs")
	}
	return workflow
}

// TestCIWorkflowPinsActionsByCommitSHA keeps a moved tag from changing what
// pull-request CI executes. CI holds only contents: read, but it still runs
// third-party action code on every pull request. release.yml is covered
// too: it publishes and attests the image, so a moved tag there ships
// unreviewed build code. The reusable call itself is pinned the same way.
func TestCIWorkflowPinsActionsByCommitSHA(t *testing.T) {
	t.Parallel()

	for _, file := range []string{".github/workflows/ci.yml", ".github/workflows/release.yml"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var workflow workflowFile
		if err := yaml.Unmarshal(raw, &workflow); err != nil {
			t.Fatal(err)
		}
		for name, job := range workflow.Jobs {
			if job.Uses != "" && !reusableCall.MatchString(job.Uses) {
				t.Errorf("%s job %s uses %q, want the pinned reusable call", file, name, job.Uses)
			}
			for _, step := range job.Steps {
				if step.Uses != "" && !pinnedAction.MatchString(step.Uses) {
					t.Errorf("%s job %s uses %q, want a full commit SHA pin", file, name, step.Uses)
				}
			}
		}
	}
}

// callerJobs are the only top-level jobs in the thin caller: lane bodies
// live upstream. Check runs nest as `go-ci / <lane>`, so the ruleset
// requires `go-ci / ci-complete`.
var callerJobs = []string{"changes", "go-ci", "scheduled-findings", "gosec-sarif"}

// TestCIWorkflowIsAThinCaller keeps the lane bodies upstream: the caller
// holds the paths-filter job, one pinned reusable call, and the two
// caller-side jobs the reusable cannot own (weekly findings issue, SARIF
// upload). No lane body may drift back into this file.
func TestCIWorkflowIsAThinCaller(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	for _, name := range callerJobs {
		if _, ok := workflow.Jobs[name]; !ok {
			t.Errorf("ci.yml has no %q job, want the thin-caller jobs %v", name, callerJobs)
		}
	}
	for _, name := range []string{"lint", "test", "race", "shell", "image", "boundary", "govulncheck", "gosec", "actionlint", "ci-complete"} {
		if _, ok := workflow.Jobs[name]; ok {
			t.Errorf("ci.yml has a top-level %q job, want lane bodies only in the reusable call", name)
		}
	}
	call, ok := workflow.Jobs["go-ci"]
	if !ok {
		t.Fatal("ci.yml has no go-ci job")
	}
	if !reusableCall.MatchString(call.Uses) {
		t.Errorf("go-ci uses %q, want the pinned reusable call", call.Uses)
	}
}

// TestCIWorkflowSetsJobTimeouts keeps a hung runner from holding a PR open
// forever: every lane declares a timeout. The reusable-call job is exempt:
// a call accepts no timeout-minutes, so its ceiling lives in the upstream
// inner-lane timeouts.
func TestCIWorkflowSetsJobTimeouts(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	for name, job := range workflow.Jobs {
		if job.Uses != "" {
			continue
		}
		if job.Timeout <= 0 {
			t.Errorf("job %s sets no timeout-minutes", name)
		}
	}
}

// TestCIWorkflowCancelsSupersededRuns keeps stale pushes from consuming
// runners: one concurrency group per PR (or ref) with cancellation.
func TestCIWorkflowCancelsSupersededRuns(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	if group := fmt.Sprint(workflow.Concurrency["group"]); !strings.Contains(group, "github.event.pull_request.number") {
		t.Errorf("concurrency group = %q, want one group per PR", group)
	}
	if cancel := fmt.Sprint(workflow.Concurrency["cancel-in-progress"]); cancel != "true" {
		t.Errorf("cancel-in-progress = %q, want true", cancel)
	}
}

// TestCIWorkflowPRLeanesNeedNoConfiguredSecrets keeps fork PRs working: the
// only secret any lane may touch is the automatic GITHUB_TOKEN (used solely
// by the schedule-only issue step). The top level stays empty (fork-safe);
// the reusable-call job holds the minimum contents: read that can fetch
// the upstream workflow definition.
func TestCIWorkflowPRLeanesNeedNoConfiguredSecrets(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	if len(workflow.Permissions) != 0 {
		t.Errorf("top-level permissions = %v, want empty (fork-safe)", workflow.Permissions)
	}
	call, ok := workflow.Jobs["go-ci"]
	if !ok {
		t.Fatal("ci.yml has no go-ci job")
	}
	if got := call.Permissions["contents"]; got != "read" {
		t.Errorf("go-ci contents permission = %q, want read", got)
	}
	for name, job := range workflow.Jobs {
		var texts []string
		for key, value := range job.Env {
			texts = append(texts, key+"="+value)
		}
		for _, step := range job.Steps {
			texts = append(texts, step.Run)
			for key, value := range step.Env {
				texts = append(texts, key+"="+value)
			}
			for key, value := range step.With {
				texts = append(texts, key+"="+fmt.Sprint(value))
			}
		}
		for key, value := range job.With {
			texts = append(texts, key+"="+fmt.Sprint(value))
		}
		for _, text := range texts {
			for _, match := range secretUsePattern.FindAllStringSubmatch(text, -1) {
				if match[1] != "GITHUB_TOKEN" {
					t.Errorf("job %s uses configured secret %q, want no secrets but GITHUB_TOKEN", name, match[1])
				}
			}
		}
	}
}

// TestChangesDefinesFixtureAndMiscClasses keeps the skip matrix honest: the
// changes job must define the fixtures class (fixture-only PRs run test
// only) and the misc catch-all (unclassified files run the full Go lanes),
// with the some-with-excludes quantifier the misc negations need.
func TestChangesDefinesFixtureAndMiscClasses(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"fixtures:", "misc:", "predicate-quantifier: 'some-with-excludes'"} {
		if !strings.Contains(text, want) {
			t.Errorf("ci.yml changes job lacks %q", want)
		}
	}
	// Every fixtures/image/shell entry must be negated in misc, or a
	// narrow-lane PR also trips misc and pays for lint and race.
	miscIdx := strings.Index(text, "misc:")
	if miscIdx < 0 {
		t.Fatal("ci.yml has no misc class")
	}
	misc := text[miscIdx:]
	for _, entry := range []string{"manifest.yaml", "testdata/**", "**/*.json", "**/*.sh", "Dockerfile"} {
		if !strings.Contains(misc, "'!"+entry+"'") {
			t.Errorf("misc class does not negate %q: a narrow-lane PR would also run the full lanes", entry)
		}
	}
}

// wiringProblems returns every way the go-ci lane wiring breaks the
// fail-closed contract: the floor must sit at the ratcheted value, every
// Go-affecting lane must also fire on misc (unclassified files run the
// full lanes), the image lane on go and misc (it embeds both), and the
// scheduled scans on the schedule event.
func wiringProblems(with map[string]any) []string {
	var problems []string
	str := func(key string) string { return fmt.Sprint(with[key]) }
	if str("coverage-floor") != "90.4" {
		problems = append(problems, "coverage-floor = "+str("coverage-floor")+", want 90.4 (the floor may only rise)")
	}
	for _, key := range []string{"run-lint", "run-test", "run-race", "run-boundary", "run-govulncheck", "run-gosec"} {
		if !strings.Contains(str(key), "needs.changes.outputs.misc == 'true'") {
			problems = append(problems, key+" lacks the misc clause: an unclassified PR would skip a Go lane")
		}
	}
	for _, class := range []string{"go", "misc"} {
		want := "needs.changes.outputs." + class + " == 'true'"
		if !strings.Contains(str("run-image"), want) {
			problems = append(problems, "run-image lacks \""+want+"\": Go sources and the whole context ship in the image")
		}
	}
	if !strings.Contains(str("run-shell"), "needs.changes.outputs.shell == 'true'") {
		problems = append(problems, "run-shell lacks the shell clause")
	}
	if !strings.Contains(str("run-govulncheck"), "needs.changes.outputs.deps == 'true'") {
		problems = append(problems, "run-govulncheck lacks the deps clause")
	}
	if !strings.Contains(str("run-actionlint"), "needs.changes.outputs.workflows == 'true'") {
		problems = append(problems, "run-actionlint lacks the workflows clause")
	}
	for _, key := range []string{"run-govulncheck", "run-gosec", "gosec-fail-on-findings", "run-actionlint"} {
		if !strings.Contains(str(key), "schedule") {
			problems = append(problems, key+" never fires on schedule: the weekly scan would go silent")
		}
	}
	return problems
}

// TestGoCICallCarriesLaneWiring keeps the thin caller fail-closed: the
// live ci.yml wiring must pass, and a wiring with a removed misc clause
// (or a lowered floor) must fail.
func TestGoCICallCarriesLaneWiring(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	call, ok := workflow.Jobs["go-ci"]
	if !ok {
		t.Fatal("ci.yml has no go-ci job")
	}
	if problems := wiringProblems(call.With); len(problems) > 0 {
		t.Errorf("go-ci wiring breaks its contract:\n%s", strings.Join(problems, "\n"))
	}

	dropped := make(map[string]any, len(call.With))
	for key, value := range call.With {
		dropped[key] = value
	}
	dropped["run-lint"] = strings.ReplaceAll(fmt.Sprint(call.With["run-lint"]), "needs.changes.outputs.misc == 'true'", "")
	if len(wiringProblems(dropped)) == 0 {
		t.Errorf("removed misc clause: the gate accepted a wiring that skips Go lanes on unclassified PRs")
	}
	lowered := make(map[string]any, len(call.With))
	for key, value := range call.With {
		lowered[key] = value
	}
	lowered["coverage-floor"] = 71.0
	if len(wiringProblems(lowered)) == 0 {
		t.Errorf("lowered floor: the gate accepted a coverage floor below the ratchet")
	}
}

// findingsProblems returns every way the scheduled-findings job breaks its
// notification contract: it must fire only when the reusable call failed
// on a schedule event (fork-PR safety), carry issues:write, and file or
// update the weekly issue.
func findingsProblems(job workflowJob) []string {
	var problems []string
	for _, want := range []string{"failure()", "schedule"} {
		if !strings.Contains(job.If, want) {
			problems = append(problems, "scheduled-findings if lacks "+want)
		}
	}
	if job.Permissions["issues"] != "write" {
		problems = append(problems, "scheduled-findings lacks issues:write (the filing step cannot run)")
	}
	runs := make([]string, 0, len(job.Steps))
	for _, step := range job.Steps {
		runs = append(runs, step.Run)
	}
	if joined := strings.Join(runs, "\n"); !strings.Contains(joined, "gh issue create") {
		problems = append(problems, "scheduled-findings has no issue-filing step")
	}
	return problems
}

// TestScheduledFindingsFilesIssues pins the schedule-only notification
// shape: the live ci.yml text must pass, and an ungated job must fail.
func TestScheduledFindingsFilesIssues(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	job, ok := workflow.Jobs["scheduled-findings"]
	if !ok {
		t.Fatal("ci.yml has no scheduled-findings job")
	}
	if problems := findingsProblems(job); len(problems) > 0 {
		t.Errorf("scheduled findings break their contract:\n%s", strings.Join(problems, "\n"))
	}

	ungated := job
	ungated.If = ""
	if len(findingsProblems(ungated)) == 0 {
		t.Errorf("ungated findings job: the gate accepted a job without failure()/schedule")
	}
}
