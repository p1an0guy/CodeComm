package reducer

func reduceConsensusCheckpoint(
	context reductionContext,
	applyContext CheckpointApplyContext,
) (Outcome, error) {
	if err := applyContext.validate(); err != nil {
		return Outcome{}, err
	}
	if applyContext.ChainIndex != context.state.currentChainIndex ||
		applyContext.ResultIndex != context.state.currentResultIndex {
		return Outcome{}, invalidState(
			"checkpoint apply context does not match reducer state",
		)
	}
	directive, ok := decodeCheckpointProof(
		context.state,
		context.proposal.Payload,
	)
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	code, err := validateCheckpointAtApply(directive, applyContext)
	if err != nil {
		return Outcome{}, err
	}
	if code != "" {
		return context.reject(code), nil
	}
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes: []OriginScope{context.scope},
		},
		Checkpoint: &directive,
	}, nil
}
