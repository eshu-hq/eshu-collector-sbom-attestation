// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/runtime"
)

// Settings is the validated activation config for one claim: the standalone
// source config the handler runs. Parse errors name config keys only and
// never quote a configured value, so they are safe for diagnostic logs.
type Settings struct {
	Source runtime.SourceConfig
}

// ParseSettings decodes the host-supplied config object into validated source
// settings. It accepts the JSON shapes command.Run produces (numbers arrive
// as json.Number) as well as plain decoded maps. Credential material is
// resolved from the environment at call time into runtime-only fields: it
// never reaches facts, logs, metric labels, or docs. Inline credential keys
// are rejected outright; operators carry credentials by *_env reference.
//
// The standalone image serves configured_source targets only. oci_referrer
// targets fail fast here: the OCI Distribution and ECR token-exchange fetch
// path stays core-side, and silently accepting the target would drop coverage
// the activation believes it has.
func ParseSettings(config map[string]any, getenv func(string) string) (Settings, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	collectorID, err := configString(config, "collector_instance_id")
	if err != nil {
		return Settings{}, err
	}
	if strings.TrimSpace(collectorID) == "" {
		return Settings{}, fmt.Errorf("config: collector_instance_id is required")
	}
	targets, err := parseTargets(config, getenv)
	if err != nil {
		return Settings{}, err
	}
	return Settings{Source: runtime.SourceConfig{
		CollectorInstanceID: strings.TrimSpace(collectorID),
		Targets:             targets,
	}}, nil
}

func parseTargets(config map[string]any, getenv func(string) string) ([]runtime.TargetConfig, error) {
	raw, ok := config["targets"]
	if !ok || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("config: targets must be a list")
	}
	targets := make([]runtime.TargetConfig, 0, len(list))
	for i, item := range list {
		mapped, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("config: targets[%d] must be an object", i)
		}
		target, err := parseTarget(mapped, getenv)
		if err != nil {
			return nil, fmt.Errorf("config: targets[%d]: %w", i, err)
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func parseTarget(raw map[string]any, getenv func(string) string) (runtime.TargetConfig, error) {
	for _, key := range []string{"username", "password", "bearer_token"} {
		if value, ok := raw[key]; ok && hasInlineValue(value) {
			return runtime.TargetConfig{}, fmt.Errorf("config: %s must be carried by %s_env reference, never inline", key, key)
		}
	}
	scopeID, err := configString(raw, "scope_id")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	sourceType, err := configString(raw, "source_type")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	switch runtime.SourceType(strings.TrimSpace(sourceType)) {
	case runtime.SourceTypeConfigured:
	case runtime.SourceTypeOCIReferrer:
		return runtime.TargetConfig{}, fmt.Errorf("config: source_type %q is not served by the standalone image (configured_source only)", "oci_referrer")
	default:
		return runtime.TargetConfig{}, fmt.Errorf("config: source_type is required")
	}
	artifactKind, err := configString(raw, "artifact_kind")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	documentFormat, err := configString(raw, "document_format")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	documentURL, err := configString(raw, "document_url")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	sourceURI, err := configString(raw, "source_uri")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	sourceRecordID, err := configString(raw, "source_record_id")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	provider, err := configString(raw, "provider")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	registry, err := configString(raw, "registry")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	subjectDigest, err := configString(raw, "subject_digest")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	referrerDigest, err := configString(raw, "referrer_digest")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	verificationResult, err := configString(raw, "verification_result")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	verificationPolicy, err := configString(raw, "verification_policy")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	maxBytes, err := configInt(raw, "max_bytes")
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	username, err := configEnvRef(raw, "username_env", getenv)
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	password, err := configEnvRef(raw, "password_env", getenv)
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	bearerToken, err := configEnvRef(raw, "bearer_token_env", getenv)
	if err != nil {
		return runtime.TargetConfig{}, err
	}
	return runtime.TargetConfig{
		ScopeID:            strings.TrimSpace(scopeID),
		SourceType:         runtime.SourceType(strings.TrimSpace(sourceType)),
		ArtifactKind:       runtime.ArtifactKind(strings.TrimSpace(artifactKind)),
		DocumentFormat:     runtime.DocumentFormat(strings.TrimSpace(documentFormat)),
		Provider:           strings.TrimSpace(provider),
		Registry:           strings.TrimSpace(registry),
		Repository:         "",
		DocumentURL:        strings.TrimSpace(documentURL),
		SourceURI:          strings.TrimSpace(sourceURI),
		SourceRecordID:     strings.TrimSpace(sourceRecordID),
		SubjectDigest:      strings.TrimSpace(subjectDigest),
		ReferrerDigest:     strings.TrimSpace(referrerDigest),
		VerificationResult: strings.TrimSpace(verificationResult),
		VerificationPolicy: strings.TrimSpace(verificationPolicy),
		Username:           username,
		Password:           password,
		BearerToken:        bearerToken,
		MaxBytes:           maxBytes,
	}, nil
}

// configEnvRef resolves a *_env key into its environment value. A missing or
// blank key means no credential; a named-but-unset variable fails closed so a
// typo cannot silently downgrade an authenticated fetch to an anonymous one.
func configEnvRef(raw map[string]any, key string, getenv func(string) string) (string, error) {
	name, err := configString(raw, key)
	if err != nil {
		return "", err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	value := getenv(name)
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s names environment variable %q, which is unset or blank; refusing to downgrade to an anonymous fetch", key, name)
	}
	return value, nil
}

// hasInlineValue reports whether an inline credential key carries anything to
// reject: any non-string value, or any non-blank string. A blank string is
// the same as absent.
func hasInlineValue(value any) bool {
	if value == nil {
		return false
	}
	str, ok := value.(string)
	return !ok || strings.TrimSpace(str) != ""
}

// configString reads an optional string key. A missing key is empty; a
// present non-string value fails naming the key, never quoting the value.
func configString(raw map[string]any, key string) (string, error) {
	value, ok := raw[key]
	if !ok || value == nil {
		return "", nil
	}
	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("config: %s must be a string", key)
	}
	return str, nil
}

// configInt reads an optional integer key, accepting the json.Number shape
// command.Run decodes as well as plain float64 and int values.
func configInt(raw map[string]any, key string) (int64, error) {
	value, ok := raw[key]
	if !ok || value == nil {
		return 0, nil
	}
	switch num := value.(type) {
	case json.Number:
		parsed, err := num.Int64()
		if err != nil {
			return 0, fmt.Errorf("config: %s must be an integer", key)
		}
		return parsed, nil
	case float64:
		if parsed := int64(num); float64(parsed) == num {
			return parsed, nil
		}
		return 0, fmt.Errorf("config: %s must be an integer", key)
	case int:
		return int64(num), nil
	case int64:
		return num, nil
	default:
		return 0, fmt.Errorf("config: %s must be an integer", key)
	}
}
