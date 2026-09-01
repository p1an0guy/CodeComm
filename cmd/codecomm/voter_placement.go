package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/ui"
)

var errVoterPlacementUnavailable = errors.New(
	"codecomm: guided voter placement is unavailable",
)

type voterPlacementOperator interface {
	Status(context.Context) (ui.Snapshot, error)
	SetVoters(
		context.Context,
		ui.SetVotersRequest,
	) (ui.CommandResult, error)
}

type voterPlacementPlan struct {
	current domain.DeviceID
	joined  domain.DeviceID
	version uint64
}

func runGuidedVoterPlacement(
	ctx context.Context,
	operator voterPlacementOperator,
	expectedJoiner domain.DeviceID,
	input io.Reader,
	output io.Writer,
) (bool, ui.CommandResult, error) {
	if ctx == nil || operator == nil || input == nil || output == nil {
		return false, ui.CommandResult{}, errVoterPlacementUnavailable
	}
	snapshot, err := operator.Status(ctx)
	if err != nil {
		return false, ui.CommandResult{}, err
	}
	plan, err := buildVoterPlacementPlan(snapshot, expectedJoiner)
	if err != nil {
		return false, ui.CommandResult{}, err
	}
	if _, err := fmt.Fprintf(
		output,
		"Choose the sole voter, preferably the device most likely to stay awake and reachable (typically a desktop): current %s, joined %s, or later.\nWarning: while the selected sole voter is asleep or unreachable, the other device can read and work locally but cannot commit strong changes; its content links close when its credential expires.\nType current, joined, or later: ",
		plan.current,
		plan.joined,
	); err != nil {
		return false, ui.CommandResult{}, err
	}
	line, err := readContextLine(
		ctx,
		input,
		maxDecisionInputBytes,
		false,
	)
	if err != nil {
		return false, ui.CommandResult{}, err
	}
	switch strings.TrimSpace(string(line)) {
	case "", "later":
		_, err = fmt.Fprintf(
			output,
			"Voter placement deferred; target remains %s.\n",
			plan.current,
		)
		return false, ui.CommandResult{}, err
	case "current":
		_, err = fmt.Fprintf(
			output,
			"Voter target remains %s.\n",
			plan.current,
		)
		return false, ui.CommandResult{}, err
	case "joined":
	default:
		return false, ui.CommandResult{}, fmt.Errorf(
			"%w: voter placement must be exactly current, joined, or later",
			errInvalidCLI,
		)
	}

	target := []domain.DeviceID{plan.joined}
	prompt := fmt.Sprintf(
		"Set voter target at version %d to %s? Type yes: ",
		plan.version,
		plan.joined,
	)
	confirmed, err := confirmOperatorAction(ctx, input, output, prompt)
	if err != nil {
		return false, ui.CommandResult{}, err
	}
	if !confirmed {
		return false, ui.CommandResult{}, fmt.Errorf(
			"%w: confirmation declined",
			errInvalidCLI,
		)
	}
	result, err := operator.SetVoters(ctx, ui.SetVotersRequest{
		ExpectedVoterSetVersion: plan.version,
		VoterDeviceIDs:          target,
	})
	if err != nil {
		return false, ui.CommandResult{}, err
	}
	if result.Status != store.OutcomeAccepted {
		return false, result, fmt.Errorf(
			"%w: voter target rejected with %s",
			errVoterPlacementUnavailable,
			result.Code,
		)
	}
	return true, result, nil
}

func buildVoterPlacementPlan(
	snapshot ui.Snapshot,
	expectedJoiner domain.DeviceID,
) (voterPlacementPlan, error) {
	if snapshot.MembersTruncated ||
		snapshot.MemberTotal != uint64(len(snapshot.Members)) ||
		snapshot.Session.MemberRole != string(device.RoleOwner) ||
		snapshot.Session.MemberStatus != string(device.StatusActive) ||
		snapshot.Consensus.LiveConfigurationSource !=
			string(coordstatus.LiveConfigurationLocal) ||
		!snapshot.Consensus.ConfigurationReconciled ||
		snapshot.Consensus.ReconciliationState !=
			string(coordstatus.ReconciliationStable) ||
		snapshot.Consensus.ReconciliationStep !=
			string(coordstatus.ReconciliationStepComplete) ||
		snapshot.Consensus.ReconciliationBlocker !=
			string(coordstatus.ReconciliationBlockerNone) ||
		len(snapshot.Consensus.LiveVoterDeviceIDs) != 1 ||
		len(snapshot.Consensus.TargetVoterDeviceIDs) != 1 ||
		len(snapshot.Consensus.ActivatedVoterDeviceIDs) != 1 ||
		snapshot.Consensus.VoterSetVersion < 1 {
		return voterPlacementPlan{}, fmt.Errorf(
			"%w: require a complete, stable two-device owner status",
			errVoterPlacementUnavailable,
		)
	}
	current := domain.DeviceID(snapshot.Consensus.TargetVoterDeviceIDs[0])
	if !current.Valid() ||
		snapshot.Consensus.LiveVoterDeviceIDs[0] != string(current) ||
		snapshot.Consensus.ActivatedVoterDeviceIDs[0] != string(current) ||
		snapshot.Session.LocalDeviceID != string(current) {
		return voterPlacementPlan{}, fmt.Errorf(
			"%w: current voter state is not stable",
			errVoterPlacementUnavailable,
		)
	}

	active := make([]domain.DeviceID, 0, 2)
	for _, member := range snapshot.Members {
		if member.Status != string(device.StatusActive) {
			continue
		}
		id := domain.DeviceID(member.DeviceID)
		if !id.Valid() {
			return voterPlacementPlan{}, errVoterPlacementUnavailable
		}
		active = append(active, id)
	}
	if len(active) != 2 {
		return voterPlacementPlan{}, fmt.Errorf(
			"%w: require exactly two active devices",
			errVoterPlacementUnavailable,
		)
	}
	var joined domain.DeviceID
	switch {
	case active[0] == current:
		joined = active[1]
	case active[1] == current:
		joined = active[0]
	default:
		return voterPlacementPlan{}, fmt.Errorf(
			"%w: current voter is not active",
			errVoterPlacementUnavailable,
		)
	}
	if expectedJoiner != "" &&
		(!expectedJoiner.Valid() || expectedJoiner != joined) {
		return voterPlacementPlan{}, fmt.Errorf(
			"%w: joined device no longer matches the reviewed admission",
			errVoterPlacementUnavailable,
		)
	}
	return voterPlacementPlan{
		current: current,
		joined:  joined,
		version: snapshot.Consensus.VoterSetVersion,
	}, nil
}
