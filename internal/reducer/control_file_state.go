package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/controlfile"
	"github.com/ijonahch/codecomm/internal/domain/controlpath"
)

func (state *State) loadControlFileSnapshot(
	proposals map[domain.UUIDv7]controlfile.Proposal,
) error {
	if state == nil {
		return invalidState("nil reducer state")
	}
	chainPositions := make(map[uint64]domain.UUIDv7, len(proposals))
	for id, proposal := range proposals {
		if id != proposal.ProposalEventID {
			return invalidState(
				"control-file proposal map key does not match row",
			)
		}
		if err := state.validateControlFileProposal(proposal, false); err != nil {
			return invalidState("control-file proposal %q: %v", id, err)
		}
		if proposal.ChainIndex > state.currentChainIndex {
			return invalidState(
				"control-file proposal %q has a future chain index",
				id,
			)
		}
		if prior, duplicate := chainPositions[proposal.ChainIndex]; duplicate {
			return invalidState(
				"control-file proposals %q and %q reuse chain index %d",
				prior,
				id,
				proposal.ChainIndex,
			)
		}
		chainPositions[proposal.ChainIndex] = id
		state.controlFileProposals[id] = proposal.Clone()
	}
	return nil
}

func (state State) validateControlFileChanges(
	values []controlfile.Proposal,
) (map[domain.UUIDv7]controlfile.Proposal, error) {
	pending := make(map[domain.UUIDv7]controlfile.Proposal, len(values))
	if len(values) > 1 {
		return pending, invalidState(
			"control-file change set contains more than one proposal",
		)
	}
	for _, value := range values {
		if err := state.validateControlFileProposal(value, true); err != nil {
			return pending, invalidState(
				"control-file proposal change %q: %v",
				value.ProposalEventID,
				err,
			)
		}
		if _, exists := state.controlFileProposals[value.ProposalEventID]; exists {
			return pending, invalidState(
				"control-file proposal %q is not append-only",
				value.ProposalEventID,
			)
		}
		if _, duplicate := pending[value.ProposalEventID]; duplicate {
			return pending, invalidState(
				"duplicate control-file proposal %q",
				value.ProposalEventID,
			)
		}
		if value.ChainIndex != state.currentChainIndex+1 {
			return pending, invalidState(
				"control-file proposal %q has chain index %d, want %d",
				value.ProposalEventID,
				value.ChainIndex,
				state.currentChainIndex+1,
			)
		}
		pending[value.ProposalEventID] = value.Clone()
	}
	return pending, nil
}

func (state State) validateControlFileProposal(
	proposal controlfile.Proposal,
	requireCurrentSession bool,
) error {
	if err := proposal.Validate(); err != nil {
		return err
	}
	if requireCurrentSession && proposal.SessionID != state.sessionID {
		return invalidState("has wrong session")
	}
	if !controlpath.IsControlledV1(proposal.Path) {
		return invalidState("path %q is not controlled", proposal.Path)
	}
	member, exists := state.devices[proposal.ProposedByDeviceID]
	if !exists || member.ID != proposal.ProposedByDeviceID {
		return invalidState(
			"references missing proposer %q",
			proposal.ProposedByDeviceID,
		)
	}
	if err := member.Validate(); err != nil {
		return invalidState(
			"proposer %q: %v",
			proposal.ProposedByDeviceID,
			err,
		)
	}
	return nil
}
