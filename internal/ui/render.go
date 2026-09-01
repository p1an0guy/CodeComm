package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/charmbracelet/x/ansi"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
)

func (model Model) View() string {
	width := model.width
	if width <= 0 {
		width = 80
	}
	lines := []string{
		fitLine("CodeComm  "+model.connectionLabel(), width),
	}
	if !model.hasSnapshot {
		lines = append(lines, "")
		switch model.connection {
		case ConnectionUnavailable:
			lines = append(lines, fitLine("Local status unavailable; retrying.", width))
		default:
			lines = append(lines, fitLine("Loading local status.", width))
		}
		return joinBoundedLines(lines, width, model.height)
	}

	snapshot := model.snapshot
	idWidth := 12
	if width >= 100 {
		idWidth = 20
	}
	deviceIDs, agentIDs, taskIDs := statusIDMaps(snapshot, idWidth)
	sessionID := compactID(snapshot.Session.SessionID)
	workspaceID := compactID(snapshot.Session.WorkspaceID)
	if width >= 76 {
		lines = append(lines,
			fitLine(
				fmt.Sprintf(
					"Session %s  Workspace %s  Generation %d",
					prefixID(sessionID, idWidth),
					prefixID(workspaceID, idWidth),
					snapshot.Session.RecoveryGeneration,
				),
				width,
			),
			fitLine(
				fmt.Sprintf(
					"Device %s  %s / %s  daemon %s",
					deviceIDs[snapshot.Session.LocalDeviceID],
					sanitizeTerminalText(snapshot.Session.MemberRole),
					sanitizeTerminalText(snapshot.Session.MemberStatus),
					sanitizeTerminalText(snapshot.Session.DaemonVersion),
				),
				width,
			),
		)
	} else {
		lines = append(lines,
			fitLine("Session   "+prefixID(sessionID, idWidth), width),
			fitLine("Workspace "+prefixID(workspaceID, idWidth), width),
			fitLine(
				fmt.Sprintf(
					"Device %s  %s / %s",
					deviceIDs[snapshot.Session.LocalDeviceID],
					sanitizeTerminalText(snapshot.Session.MemberRole),
					sanitizeTerminalText(snapshot.Session.MemberStatus),
				),
				width,
			),
		)
	}

	leader := "none"
	if snapshot.Consensus.LeaderDeviceID != nil {
		leader = deviceIDs[*snapshot.Consensus.LeaderDeviceID]
	}
	lines = append(lines, fitLine(
		fmt.Sprintf(
			"Consensus %s / %s  leader %s",
			strings.ToUpper(sanitizeTerminalText(snapshot.Consensus.State)),
			sanitizeTerminalText(snapshot.Consensus.Role),
			leader,
		),
		width,
	))
	if snapshot.Consensus.State == string(coordstatus.ConsensusSettled) {
		lines = append(lines, fitLine(
			fmt.Sprintf(
				"Replica %s  observed %d/%d authorities  watermark %d",
				strings.ToUpper(
					sanitizeTerminalText(
						snapshot.Consensus.ReplicaCurrency,
					),
				),
				len(snapshot.Consensus.ObservedAuthorityIDs),
				len(snapshot.Consensus.ActivatedVoterDeviceIDs),
				snapshot.Consensus.ObservedResultIndex,
			),
			width,
		))
	}
	if snapshot.Network.MulticastState == string(MulticastDegraded) {
		detail := "multicast unavailable"
		if snapshot.Network.MulticastError != nil {
			detail = sanitizeTerminalText(*snapshot.Network.MulticastError)
		}
		lines = append(
			lines,
			wrapLine("Discovery DEGRADED: "+detail, width)...,
		)
		lines = append(lines, wrapLine(
			"Configure a manual route with codecomm peer endpoint add.",
			width,
		)...)
	}
	switch snapshot.Consensus.LiveConfigurationSource {
	case string(coordstatus.LiveConfigurationUnknown):
		lines = append(lines, fitLine(
			fmt.Sprintf(
				"Live configuration UNKNOWN  target %d",
				len(snapshot.Consensus.TargetVoterDeviceIDs),
			),
			width,
		))
		if width >= 60 {
			lines = append(
				lines,
				fitLine(
					"Strong writes "+
						sanitizeTerminalText(
							snapshot.Consensus.StrongWrites,
						),
					width,
				),
				fitLine(appliedLine(snapshot), width),
			)
		} else {
			lines = append(lines, fitLine(
				"Strong writes "+
					sanitizeTerminalText(snapshot.Consensus.StrongWrites),
				width,
			))
			lines = append(lines, narrowAppliedLines(snapshot)...)
		}
	case string(coordstatus.LiveConfigurationVoterReported):
		lines = append(lines, fitLine(
			"Live configuration VOTER-REPORTED",
			width,
		))
		if width >= 60 {
			lines = append(
				lines,
				fitLine(
					fmt.Sprintf(
						"Voters %d  target %d  quorum %d  writes %s",
						len(snapshot.Consensus.LiveVoterDeviceIDs),
						len(snapshot.Consensus.TargetVoterDeviceIDs),
						snapshot.Consensus.QuorumRequired,
						sanitizeTerminalText(
							snapshot.Consensus.StrongWrites,
						),
					),
					width,
				),
				fitLine(appliedLine(snapshot), width),
			)
		} else {
			lines = append(
				lines,
				fitLine(
					fmt.Sprintf(
						"Voters %d  target %d  quorum %d",
						len(snapshot.Consensus.LiveVoterDeviceIDs),
						len(snapshot.Consensus.TargetVoterDeviceIDs),
						snapshot.Consensus.QuorumRequired,
					),
					width,
				),
				fitLine(
					"Strong writes "+
						sanitizeTerminalText(
							snapshot.Consensus.StrongWrites,
						),
					width,
				),
			)
			lines = append(lines, narrowAppliedLines(snapshot)...)
		}
	default:
		if width >= 60 {
			lines = append(lines,
				fitLine(
					fmt.Sprintf(
						"Voters live %d  target %d  quorum %d  writes %s",
						len(snapshot.Consensus.LiveVoterDeviceIDs),
						len(snapshot.Consensus.TargetVoterDeviceIDs),
						snapshot.Consensus.QuorumRequired,
						sanitizeTerminalText(
							snapshot.Consensus.StrongWrites,
						),
					),
					width,
				),
				fitLine(appliedLine(snapshot), width),
			)
		} else {
			lines = append(lines,
				fitLine(
					fmt.Sprintf(
						"Voters live %d  target %d  quorum %d",
						len(snapshot.Consensus.LiveVoterDeviceIDs),
						len(snapshot.Consensus.TargetVoterDeviceIDs),
						snapshot.Consensus.QuorumRequired,
					),
					width,
				),
				fitLine(
					"Strong writes "+
						sanitizeTerminalText(
							snapshot.Consensus.StrongWrites,
						),
					width,
				),
			)
			lines = append(lines, narrowAppliedLines(snapshot)...)
		}
	}
	degradedVoters := len(snapshot.Consensus.LiveVoterDeviceIDs)
	degradedLabel := "voter"
	if snapshot.Consensus.LiveConfigurationSource ==
		string(coordstatus.LiveConfigurationUnknown) {
		degradedVoters = len(snapshot.Consensus.TargetVoterDeviceIDs)
		degradedLabel = "target voter"
	}
	if degradedVoters < 3 {
		lines = append(
			lines,
			wrapLine(
				fmt.Sprintf(
					"DEGRADED: %d %s%s; no voter loss tolerated",
					degradedVoters,
					degradedLabel,
					pluralSuffix(degradedVoters),
				),
				width,
			)...,
		)
	}
	switch snapshot.Consensus.ReconciliationState {
	case string(coordstatus.ReconciliationUnknown):
		lines = append(
			lines,
			fitLine("Voter reconciliation UNKNOWN", width),
		)
	case string(coordstatus.ReconciliationStable):
	default:
		reconciliation := fmt.Sprintf(
			"Voter transition %s  step %s",
			strings.ToUpper(
				sanitizeTerminalText(
					snapshot.Consensus.ReconciliationState,
				),
			),
			sanitizeTerminalText(
				snapshot.Consensus.ReconciliationStep,
			),
		)
		if snapshot.Consensus.ReconciliationBlocker !=
			string(coordstatus.ReconciliationBlockerNone) {
			reconciliation += "  blocker " + sanitizeTerminalText(
				snapshot.Consensus.ReconciliationBlocker,
			)
		}
		if snapshot.Consensus.ReconciliationDeviceID != nil {
			reconciliation += "  device " +
				deviceIDs[*snapshot.Consensus.ReconciliationDeviceID]
		}
		lines = append(lines, wrapLine(reconciliation, width)...)
	}

	lines = append(lines, "", fitLine(
		fmt.Sprintf("Agents (%d)", len(snapshot.Agents)),
		width,
	))
	taskClaims := claimedTasksByAgent(snapshot, taskIDs)
	for _, agent := range snapshot.Agents {
		label := sanitizeTerminalText(agent.ClientKind)
		if agent.AgentProfileID != nil {
			label += ":" + sanitizeTerminalText(*agent.AgentProfileID)
		}
		claims := taskClaims[agent.AgentSessionID]
		claimText := "no task"
		if len(claims) != 0 {
			claimText = "task " + strings.Join(claims, ",")
		}
		if width >= 76 {
			lines = append(lines, fitLine(
				fmt.Sprintf(
					"  %s  %-18s  %-12s  %s",
					agentIDs[agent.AgentSessionID],
					label,
					sanitizeTerminalText(agent.State),
					claimText,
				),
				width,
			))
		} else {
			lines = append(lines,
				fitLine(
					fmt.Sprintf(
						"  %s  %s",
						agentIDs[agent.AgentSessionID],
						sanitizeTerminalText(agent.State),
					),
					width,
				),
				fitLine("    "+label+"  "+claimText, width),
			)
		}
	}
	if len(snapshot.Agents) == 0 {
		lines = append(lines, fitLine("  none", width))
	}

	taskHeading := fmt.Sprintf("Tasks (%d)", snapshot.TaskTotal)
	if snapshot.Truncated {
		taskHeading += fmt.Sprintf("; showing %d", len(snapshot.Tasks))
	}
	lines = append(lines, "", fitLine(taskHeading, width))
	for _, value := range snapshot.Tasks {
		owner := "unassigned"
		if value.OwnerAgentSessionID != nil {
			owner = "owner " + agentIDs[*value.OwnerAgentSessionID]
		} else if value.IntendedDeviceID != nil {
			owner = "target " + deviceIDs[*value.IntendedDeviceID]
		}
		details := owner
		if value.DependencyCount != 0 {
			details += fmt.Sprintf("  deps %d", value.DependencyCount)
		}
		if width >= 76 {
			lines = append(lines, fitLine(
				fmt.Sprintf(
					"  P%d %s  %-11s  %s  %s",
					value.Priority,
					taskIDs[value.TaskID],
					sanitizeTerminalText(value.State),
					sanitizeTerminalText(value.Title),
					details,
				),
				width,
			))
		} else {
			lines = append(lines,
				fitLine(
					fmt.Sprintf(
						"  P%d %s  %s",
						value.Priority,
						taskIDs[value.TaskID],
						sanitizeTerminalText(value.State),
					),
					width,
				),
				fitLine(
					"    "+sanitizeTerminalText(value.Title)+"  "+details,
					width,
				),
			)
		}
		if value.StateReason != nil {
			lines = append(lines, fitLine(
				"    reason: "+sanitizeTerminalText(*value.StateReason),
				width,
			))
		}
	}
	if len(snapshot.Tasks) == 0 {
		lines = append(lines, fitLine("  none", width))
	}
	return joinBoundedLines(lines, width, model.height)
}

func (model Model) connectionLabel() string {
	switch model.connection {
	case ConnectionLive:
		return "[LIVE]"
	case ConnectionStale:
		age := model.clock().Sub(model.lastGoodAt)
		if age < 0 {
			age = 0
		}
		return "[STALE " + formatAge(age) + "]"
	case ConnectionUnavailable:
		return "[UNAVAILABLE]"
	default:
		return "[LOADING]"
	}
}

func appliedLine(snapshot Snapshot) string {
	term := "-"
	if snapshot.Session.AppliedTerm != nil {
		term = fmt.Sprintf("%d", *snapshot.Session.AppliedTerm)
	}
	raftIndex := "-"
	if snapshot.Session.AppliedRaftIndex != nil {
		raftIndex = fmt.Sprintf("%d", *snapshot.Session.AppliedRaftIndex)
	}
	return fmt.Sprintf(
		"Applied term %s  raft %s  event %d  result %d",
		term,
		raftIndex,
		snapshot.Session.EventChainIndex,
		snapshot.Session.ResultIndex,
	)
}

func narrowAppliedLines(snapshot Snapshot) []string {
	term := "-"
	if snapshot.Session.AppliedTerm != nil {
		term = fmt.Sprintf("%d", *snapshot.Session.AppliedTerm)
	}
	raftIndex := "-"
	if snapshot.Session.AppliedRaftIndex != nil {
		raftIndex = fmt.Sprintf("%d", *snapshot.Session.AppliedRaftIndex)
	}
	return []string{
		fmt.Sprintf("Applied term %s  raft %s", term, raftIndex),
		fmt.Sprintf(
			"Applied event %d  result %d",
			snapshot.Session.EventChainIndex,
			snapshot.Session.ResultIndex,
		),
	}
}

func statusIDMaps(
	snapshot Snapshot,
	maximum int,
) (map[string]string, map[string]string, map[string]string) {
	deviceValues := []string{snapshot.Session.LocalDeviceID}
	if snapshot.Consensus.LeaderDeviceID != nil {
		deviceValues = append(deviceValues, *snapshot.Consensus.LeaderDeviceID)
	}
	deviceValues = append(
		deviceValues,
		snapshot.Consensus.LiveVoterDeviceIDs...,
	)
	deviceValues = append(
		deviceValues,
		snapshot.Consensus.LiveNonvoterDeviceIDs...,
	)
	deviceValues = append(
		deviceValues,
		snapshot.Consensus.TargetVoterDeviceIDs...,
	)
	deviceValues = append(
		deviceValues,
		snapshot.Consensus.ActivatedVoterDeviceIDs...,
	)
	if snapshot.Consensus.ReconciliationDeviceID != nil {
		deviceValues = append(
			deviceValues,
			*snapshot.Consensus.ReconciliationDeviceID,
		)
	}
	agentValues := make([]string, 0, len(snapshot.Agents))
	taskValues := make([]string, 0, len(snapshot.Tasks))
	for _, agent := range snapshot.Agents {
		deviceValues = append(deviceValues, agent.DeviceID)
		agentValues = append(agentValues, agent.AgentSessionID)
	}
	for _, value := range snapshot.Tasks {
		taskValues = append(taskValues, value.TaskID)
		if value.OwnerDeviceID != nil {
			deviceValues = append(deviceValues, *value.OwnerDeviceID)
		}
		if value.OwnerAgentSessionID != nil {
			agentValues = append(agentValues, *value.OwnerAgentSessionID)
		}
		if value.IntendedDeviceID != nil {
			deviceValues = append(deviceValues, *value.IntendedDeviceID)
		}
	}
	return abbreviateIDs(deviceValues, 10, maximum),
		abbreviateIDs(agentValues, 8, maximum),
		abbreviateIDs(taskValues, 8, maximum)
}

func claimedTasksByAgent(
	snapshot Snapshot,
	taskIDs map[string]string,
) map[string][]string {
	result := make(map[string][]string)
	for _, value := range snapshot.Tasks {
		if value.OwnerAgentSessionID == nil {
			continue
		}
		result[*value.OwnerAgentSessionID] = append(
			result[*value.OwnerAgentSessionID],
			taskIDs[value.TaskID],
		)
	}
	return result
}

func abbreviateIDs(
	values []string,
	minimum, maximum int,
) map[string]string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			unique[value] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(unique))
	for value := range unique {
		ordered = append(ordered, value)
	}
	sort.Strings(ordered)
	if minimum < 1 {
		minimum = 1
	}
	if maximum < minimum {
		maximum = minimum
	}
	result := make(map[string]string, len(ordered))
	for _, value := range ordered {
		compact := compactID(value)
		length := minimum
		if length > len(compact) {
			length = len(compact)
		}
		for length < len(compact) && length < maximum {
			candidate := compact[:length]
			if uniquePrefix(compact, candidate, ordered) {
				break
			}
			length++
		}
		candidate := compact[:length]
		if !uniquePrefix(compact, candidate, ordered) {
			digest := sha256.Sum256([]byte(value))
			suffix := hex.EncodeToString(digest[:3])
			headLength := maximum - len(suffix) - 1
			if headLength < 1 {
				headLength = 1
			}
			if headLength > len(compact) {
				headLength = len(compact)
			}
			candidate = compact[:headLength] + "~" + suffix
			if len(candidate) > maximum {
				candidate = candidate[:maximum]
			}
		}
		result[value] = candidate
	}
	return result
}

func uniquePrefix(
	self, candidate string,
	values []string,
) bool {
	for _, other := range values {
		compact := compactID(other)
		if compact == self {
			continue
		}
		if strings.HasPrefix(compact, candidate) {
			return false
		}
	}
	return true
}

func compactID(value string) string {
	return strings.ReplaceAll(value, "-", "")
}

func prefixID(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}

func sanitizeTerminalText(value string) string {
	value = ansi.Strip(value)
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) ||
			unicode.In(character, unicode.Cf, unicode.Zl, unicode.Zp) {
			return ' '
		}
		return character
	}, value)
	return strings.Join(strings.Fields(value), " ")
}

func fitLine(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if ansi.StringWidth(value) <= width {
		return value
	}
	if width <= 3 {
		return ansi.Truncate(value, width, "")
	}
	return ansi.Truncate(value, width, "...")
}

func wrapLine(value string, width int) []string {
	value = sanitizeTerminalText(value)
	if width <= 0 || value == "" {
		return []string{""}
	}
	var (
		lines   []string
		current string
	)
	for _, word := range strings.Fields(value) {
		candidate := word
		if current != "" {
			candidate = current + " " + word
		}
		if ansi.StringWidth(candidate) <= width {
			current = candidate
			continue
		}
		if current != "" {
			lines = append(lines, current)
		}
		current = fitLine(word, width)
	}
	if current != "" {
		lines = append(lines, current)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func joinBoundedLines(
	lines []string,
	width, height int,
) string {
	for index := range lines {
		lines[index] = fitLine(lines[index], width)
	}
	if height > 0 && len(lines) > height {
		omitted := len(lines) - height + 1
		lines = append(
			append([]string(nil), lines[:height-1]...),
			fitLine(
				fmt.Sprintf("... %d additional status rows omitted", omitted),
				width,
			),
		)
	}
	return strings.Join(lines, "\n") + "\n"
}

func formatAge(value time.Duration) string {
	value = value.Truncate(time.Second)
	if value < time.Minute {
		return fmt.Sprintf("%ds", int(value/time.Second))
	}
	if value < time.Hour {
		return fmt.Sprintf(
			"%dm%02ds",
			int(value/time.Minute),
			int(value%time.Minute/time.Second),
		)
	}
	return fmt.Sprintf(
		"%dh%02dm",
		int(value/time.Hour),
		int(value%time.Hour/time.Minute),
	)
}

func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}
