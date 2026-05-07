package sync

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

const metadataSchemaVersion = "2026-05-07-temporary-ignore-due-date-v1"

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
		strings.Join(normalizeManagedLabelNames(desired.ManagedLabels), ","),
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
		strings.Join(normalizeManagedLabelNames(existing.ManagedLabels), ","),
		strings.Join(presentManagedLabelNames(existing.Labels, existing.ManagedLabels), ","),
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
			Fingerprint:   existing.Fingerprint,
			Title:         existing.Title,
			Description:   existing.Description,
			DueDate:       existing.DueDate,
			State:         model.StateDone,
			ManagedLabels: existing.ManagedLabels,
			Priority:      existing.Priority,
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

func presentManagedLabelNames(labels []model.IssueLabel, managed []string) []string {
	out := make([]string, 0, len(managed))
	for _, label := range normalizeManagedLabelNames(managed) {
		if hasLabelNamed(labels, label) {
			out = append(out, label)
		}
	}
	return out
}
