package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain/publication"
)

func reducePublicationReviewed(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"verdict"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	verdictText, ok := decodeValue[string](payload, "verdict")
	verdict := publication.ReviewVerdict(verdictText)
	if !ok || !verdict.Valid() {
		return context.reject(CodeInvalidPayload), nil
	}
	current, outcome, done, err := loadMutablePublication(context)
	if err != nil || done {
		return outcome, err
	}
	reviewerDeviceID, reviewerSessionID, actorType, err :=
		publicationReviewer(context)
	if err != nil {
		return Outcome{}, err
	}
	if actorType == publication.ReviewActorAgent &&
		reviewerDeviceID == current.Metadata.AuthorDeviceID {
		return context.reject(CodePublicationReviewNotIndependent), nil
	}

	next := clonePublication(current)
	next.ReviewVerdict = verdict
	next.ReviewerDeviceID = reviewerDeviceID
	next.ReviewerAgentSessionID = reviewerSessionID
	next.ReviewActorType = actorType
	next.EntityVersion++
	var operation publication.Operation
	switch verdict {
	case publication.ReviewVerdictApprove:
		next.State = publication.StateApproved
		operation = publication.OperationReviewApprove
	case publication.ReviewVerdictReject:
		next.State = publication.StateRejected
		next.TerminalSource = publication.TerminalSourceReview
		operation = publication.OperationReviewReject
	}
	if err := publication.ValidateTransition(
		operation,
		current,
		next,
	); err != nil {
		return context.reject(CodeInvalidPublicationTransition), nil
	}
	return context.acceptPublication(next, nil)
}
