package reducer

import "github.com/ijonahch/codecomm/internal/domain/controlfile"

func reduceControlFileChangeProposed(
	context reductionContext,
) (Outcome, error) {
	proposal, code := decodeControlFileProposal(context)
	if code != "" {
		return context.reject(code), nil
	}
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes:         []OriginScope{context.scope},
			ControlFileProposals: []controlfile.Proposal{proposal.Clone()},
		},
	}, nil
}
