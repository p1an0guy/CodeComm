package reducer

import (
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/publication"
)

func reducePublicationApplied(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"expected_canonical_ref_version", "staging_receipts"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	expectedRefVersion, versionOK := decodeValue[uint64](
		payload,
		"expected_canonical_ref_version",
	)
	receiptObjects, receiptsOK := decodeValue[[]json.RawMessage](
		payload,
		"staging_receipts",
	)
	receipts, validReceipts := decodeStagingReceipts(receiptObjects)
	if !versionOK || !receiptsOK || !validReceipts ||
		expectedRefVersion < 1 ||
		!domain.ValidUnsignedInteger(expectedRefVersion) {
		return context.reject(CodeInvalidPayload), nil
	}
	current, outcome, done, err := loadMutablePublication(context)
	if err != nil || done {
		return outcome, err
	}
	currentRef := context.state.canonicalRef
	if expectedRefVersion != currentRef.EntityVersion {
		return context.reject(CodeCanonicalRefVersionMismatch), nil
	}
	if currentRef.EntityVersion == domain.MaxSafeInteger {
		return context.reject(CodeCanonicalRefVersionExhausted), nil
	}
	if current.Metadata.BaseCommit != currentRef.CommitOID {
		return context.reject(CodePublicationBaseCommitMismatch), nil
	}
	if code := validatePublicationReceipts(
		context.state,
		current.Metadata,
		receipts,
	); code != "" {
		return context.reject(code), nil
	}

	next := clonePublication(current)
	next.StagingReceipts = append(
		[]publication.StagingReceipt(nil),
		receipts...,
	)
	next.State = publication.StateApplied
	next.TerminalSource = publication.TerminalSourceApply
	next.CanonicalLineageMember = true
	next.EntityVersion++
	if err := publication.ValidateTransition(
		publication.OperationApply,
		current,
		next,
	); err != nil {
		return context.reject(CodeInvalidPublicationTransition), nil
	}
	nextRef := publication.CanonicalRef{
		RefName:       publication.CanonicalRefName,
		CommitOID:     current.Metadata.CommitOID,
		EntityVersion: currentRef.EntityVersion + 1,
	}
	return context.acceptPublication(next, &nextRef)
}
