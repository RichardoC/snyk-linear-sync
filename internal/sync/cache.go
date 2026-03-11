package sync

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

const metadataSchemaVersion = "2026-03-11-ui-links-source-location-due-dates-v1"

func managedSchemaSignature() string {
	return metadataSchemaVersion
}

func desiredIssueHash(desired model.DesiredIssue) string {
	return digestParts(
		desired.Fingerprint,
		desired.Title,
		normalizeDescriptionForCompare(desired.Description),
		desired.DueDate,
		string(desired.State),
		fmt.Sprintf("%d", desired.Priority),
	)
}

func existingIssueHash(existing model.ExistingIssue) string {
	return digestParts(
		existing.Fingerprint,
		existing.Title,
		normalizeDescriptionForCompare(existing.Description),
		existing.DueDate,
		normalizeWorkflowStateName(existing.StateName),
		fmt.Sprintf("%d", existing.Priority),
	)
}

func nextLinearHashes(desiredByFingerprint map[string]model.DesiredIssue, existingByFingerprint map[string]model.ExistingIssue, conflicted map[string]struct{}) map[string]string {
	out := make(map[string]string, len(existingByFingerprint)+len(desiredByFingerprint))

	for fingerprint, desired := range desiredByFingerprint {
		if _, blocked := conflicted[fingerprint]; blocked {
			continue
		}
		existing, ok := existingByFingerprint[fingerprint]
		if ok && !needsUpdate(existing, desired) {
			out[fingerprint] = existingIssueHash(existing)
			continue
		}
		out[fingerprint] = desiredIssueHash(desired)
	}

	for fingerprint, existing := range existingByFingerprint {
		if _, blocked := conflicted[fingerprint]; blocked {
			continue
		}
		if _, ok := desiredByFingerprint[fingerprint]; ok {
			continue
		}

		resolved := model.DesiredIssue{
			Fingerprint: existing.Fingerprint,
			Title:       existing.Title,
			Description: existing.Description,
			DueDate:     existing.DueDate,
			State:       model.StateDone,
			Priority:    existing.Priority,
		}
		if needsUpdate(existing, resolved) {
			out[fingerprint] = desiredIssueHash(resolved)
			continue
		}
		out[fingerprint] = existingIssueHash(existing)
	}

	return out
}

func digestParts(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
