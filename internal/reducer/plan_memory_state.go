package reducer

import (
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
)

type pendingPlanMemoryChanges struct {
	planRevisions map[domain.UUIDv7]plan.Revision
	planCurrent   *plan.Current
	memoryRecords map[domain.UUIDv7]memory.Record
}

func (state *State) loadPlanMemorySnapshot(
	revisions map[domain.UUIDv7]plan.Revision,
	current plan.Current,
	records map[domain.UUIDv7]memory.Record,
) error {
	for id, revision := range revisions {
		if id != revision.ID() {
			return invalidState("plan-revision map key does not match row")
		}
		if err := state.validatePlanRevisionRow(revision, nil); err != nil {
			return invalidState("plan revision %q: %v", id, err)
		}
		state.planRevisions[id] = revision
	}
	for id, revision := range state.planRevisions {
		if predecessorID, present := revision.Supersedes(); present {
			if _, exists := state.planRevisions[predecessorID]; !exists {
				return invalidState(
					"plan revision %q references missing predecessor %q",
					id,
					predecessorID,
				)
			}
		}
	}
	if err := validatePlanRevisionCycles(state.planRevisions); err != nil {
		return invalidState("plan revisions: %v", err)
	}
	if err := state.validateCurrentPlanRow(current); err != nil {
		return invalidState("current plan: %v", err)
	}
	state.planCurrent = current

	for id, record := range records {
		if id != record.ID() {
			return invalidState("memory-record map key does not match row")
		}
		if err := state.validateMemoryRow(record, nil); err != nil {
			return invalidState("memory record %q: %v", id, err)
		}
		state.memoryRecords[id] = record
	}
	for id, record := range state.memoryRecords {
		predecessorID, present := record.Supersedes()
		if !present {
			continue
		}
		predecessor, exists := state.memoryRecords[predecessorID]
		if !exists {
			return invalidState(
				"memory record %q references missing predecessor %q",
				id,
				predecessorID,
			)
		}
		if err := memory.ValidatePredecessor(record, predecessor); err != nil {
			return invalidState("memory record %q: %v", id, err)
		}
		if successor, occupied := state.memorySuccessors[predecessorID]; occupied {
			return invalidState(
				"memory predecessor %q has successors %q and %q",
				predecessorID,
				successor,
				id,
			)
		}
		state.memorySuccessors[predecessorID] = id
	}
	if err := validateMemoryCycles(state.memoryRecords); err != nil {
		return invalidState("memory records: %v", err)
	}
	return nil
}

func (state State) validatePlanMemoryChanges(
	changes Changes,
	pendingTaskIDs map[domain.UUIDv7]struct{},
) (pendingPlanMemoryChanges, error) {
	pending := pendingPlanMemoryChanges{
		planRevisions: make(
			map[domain.UUIDv7]plan.Revision,
			len(changes.PlanRevisions),
		),
		memoryRecords: make(
			map[domain.UUIDv7]memory.Record,
			len(changes.MemoryRecords),
		),
	}

	for _, revision := range changes.PlanRevisions {
		id := revision.ID()
		if _, exists := state.planRevisions[id]; exists {
			return pending, invalidState(
				"immutable plan revision %q already exists",
				id,
			)
		}
		if _, duplicate := pending.planRevisions[id]; duplicate {
			return pending, invalidState(
				"duplicate plan-revision change %q",
				id,
			)
		}
		if err := state.validatePlanRevisionRow(
			revision,
			pendingTaskIDs,
		); err != nil {
			return pending, invalidState(
				"plan-revision change %q: %v",
				id,
				err,
			)
		}
		pending.planRevisions[id] = revision
	}
	for id, revision := range pending.planRevisions {
		predecessorID, present := revision.Supersedes()
		if !present {
			continue
		}
		if _, exists := state.planRevisions[predecessorID]; exists {
			if _, err := state.validateRetainedPlanRevision(
				predecessorID,
			); err != nil {
				return pending, invalidState("%v", err)
			}
			continue
		}
		if _, exists := pending.planRevisions[predecessorID]; !exists {
			return pending, invalidState(
				"plan-revision change %q references missing predecessor %q",
				id,
				predecessorID,
			)
		}
	}
	if err := validatePlanRevisionCycles(pending.planRevisions); err != nil {
		return pending, invalidState("plan-revision changes: %v", err)
	}

	if len(changes.PlanCurrent) > 1 {
		return pending, invalidState("duplicate current-plan change")
	}
	if len(changes.PlanCurrent) == 1 {
		next := changes.PlanCurrent[0]
		if next.SessionID != state.sessionID {
			return pending, invalidState(
				"current-plan change has wrong session",
			)
		}
		if err := state.validateCurrentPlanRow(state.planCurrent); err != nil {
			return pending, invalidState("current plan: %v", err)
		}
		if err := next.Validate(); err != nil {
			return pending, invalidState(
				"current-plan change: %v",
				err,
			)
		}
		if _, exists := state.planRevisions[next.RevisionID]; exists {
			if _, err := state.validateRetainedPlanRevision(
				next.RevisionID,
			); err != nil {
				return pending, invalidState("%v", err)
			}
		} else {
			if _, exists := pending.planRevisions[next.RevisionID]; !exists {
				return pending, invalidState(
					"current-plan change references missing revision %q",
					next.RevisionID,
				)
			}
		}
		if err := plan.ValidateTransition(
			plan.OperationSelect,
			state.planCurrent,
			next,
		); err != nil {
			return pending, invalidState(
				"current-plan change: %v",
				err,
			)
		}
		nextCopy := next
		pending.planCurrent = &nextCopy
	}

	for _, record := range changes.MemoryRecords {
		id := record.ID()
		if _, exists := state.memoryRecords[id]; exists {
			return pending, invalidState(
				"immutable memory record %q already exists",
				id,
			)
		}
		if _, duplicate := pending.memoryRecords[id]; duplicate {
			return pending, invalidState(
				"duplicate memory-record change %q",
				id,
			)
		}
		if err := state.validateMemoryRow(record, pendingTaskIDs); err != nil {
			return pending, invalidState(
				"memory-record change %q: %v",
				id,
				err,
			)
		}
		pending.memoryRecords[id] = record
	}
	pendingSuccessors := make(map[domain.UUIDv7]domain.UUIDv7)
	for id, record := range pending.memoryRecords {
		predecessorID, present := record.Supersedes()
		if !present {
			continue
		}
		var predecessor memory.Record
		_, exists := state.memoryRecords[predecessorID]
		if exists {
			validated, err := state.validateRetainedMemoryRecord(
				predecessorID,
			)
			if err != nil {
				return pending, invalidState("%v", err)
			}
			predecessor = validated
		} else {
			predecessor, exists = pending.memoryRecords[predecessorID]
		}
		if !exists {
			return pending, invalidState(
				"memory-record change %q references missing predecessor %q",
				id,
				predecessorID,
			)
		}
		if err := memory.ValidatePredecessor(record, predecessor); err != nil {
			return pending, invalidState(
				"memory-record change %q: %v",
				id,
				err,
			)
		}
		if successor, occupied := state.memorySuccessors[predecessorID]; occupied {
			validated, err := state.validateRetainedMemoryRecord(successor)
			if err != nil {
				return pending, invalidState("%v", err)
			}
			actualPredecessor, present := validated.Supersedes()
			if !present || actualPredecessor != predecessorID {
				return pending, invalidState(
					"memory successor index disagrees with row",
				)
			}
			return pending, invalidState(
				"memory predecessor %q is already superseded by %q",
				predecessorID,
				successor,
			)
		}
		if successor, occupied := pendingSuccessors[predecessorID]; occupied {
			return pending, invalidState(
				"memory predecessor %q has pending successors %q and %q",
				predecessorID,
				successor,
				id,
			)
		}
		pendingSuccessors[predecessorID] = id
	}
	if err := validateMemoryCycles(pending.memoryRecords); err != nil {
		return pending, invalidState("memory-record changes: %v", err)
	}
	return pending, nil
}

func (state State) validatePlanRevisionRow(
	revision plan.Revision,
	pendingTaskIDs map[domain.UUIDv7]struct{},
) error {
	if err := revision.Validate(); err != nil {
		return err
	}
	member, exists := state.devices[revision.ProposedByDeviceID()]
	if !exists || member.ID != revision.ProposedByDeviceID() {
		return fmt.Errorf(
			"references missing proposer device %q",
			revision.ProposedByDeviceID(),
		)
	}
	if err := member.Validate(); err != nil {
		return fmt.Errorf("proposer device: %v", err)
	}
	for _, taskID := range revision.TaskIDs() {
		if err := state.validatePlanMemoryTaskReference(
			taskID,
			pendingTaskIDs,
		); err != nil {
			return err
		}
	}
	return nil
}

func (state State) validateMemoryRow(
	record memory.Record,
	pendingTaskIDs map[domain.UUIDv7]struct{},
) error {
	if err := record.Validate(); err != nil {
		return err
	}
	if taskID, present := record.TaskID(); present {
		if err := state.validatePlanMemoryTaskReference(
			taskID,
			pendingTaskIDs,
		); err != nil {
			return err
		}
	}
	return nil
}

func (state State) validatePlanMemoryTaskReference(
	id domain.UUIDv7,
	pendingTaskIDs map[domain.UUIDv7]struct{},
) error {
	if value, exists := state.tasks[id]; exists {
		if value.ID != id {
			return fmt.Errorf("task map key does not match referenced row")
		}
		if err := value.Validate(); err != nil {
			return fmt.Errorf("referenced task %q: %v", id, err)
		}
		return nil
	}
	if _, exists := pendingTaskIDs[id]; exists {
		return nil
	}
	return fmt.Errorf("references missing task %q", id)
}

func (state State) validateRetainedPlanRevision(
	id domain.UUIDv7,
) (plan.Revision, error) {
	revision, exists := state.planRevisions[id]
	if !exists {
		return plan.Revision{}, fmt.Errorf("missing plan revision %q", id)
	}
	if revision.ID() != id {
		return plan.Revision{}, fmt.Errorf(
			"plan-revision map key does not match row",
		)
	}
	if err := state.validatePlanRevisionRow(revision, nil); err != nil {
		return plan.Revision{}, fmt.Errorf(
			"plan revision %q: %v",
			id,
			err,
		)
	}
	if predecessorID, present := revision.Supersedes(); present {
		if _, exists := state.planRevisions[predecessorID]; !exists {
			return plan.Revision{}, fmt.Errorf(
				"plan revision %q references missing predecessor %q",
				id,
				predecessorID,
			)
		}
	}
	return revision, nil
}

func (state State) validateCurrentPlanRow(current plan.Current) error {
	if current.SessionID != state.sessionID {
		return fmt.Errorf("row has wrong session")
	}
	if err := current.Validate(); err != nil {
		return err
	}
	if current.RevisionID != "" {
		if _, err := state.validateRetainedPlanRevision(
			current.RevisionID,
		); err != nil {
			return err
		}
	}
	return nil
}

func (state State) validateRetainedMemoryRecord(
	id domain.UUIDv7,
) (memory.Record, error) {
	record, exists := state.memoryRecords[id]
	if !exists {
		return memory.Record{}, fmt.Errorf("missing memory record %q", id)
	}
	if record.ID() != id {
		return memory.Record{}, fmt.Errorf(
			"memory-record map key does not match row",
		)
	}
	if err := state.validateMemoryRow(record, nil); err != nil {
		return memory.Record{}, fmt.Errorf(
			"memory record %q: %v",
			id,
			err,
		)
	}
	if predecessorID, present := record.Supersedes(); present {
		if _, exists := state.memoryRecords[predecessorID]; !exists {
			return memory.Record{}, fmt.Errorf(
				"memory record %q references missing predecessor %q",
				id,
				predecessorID,
			)
		}
	}
	return record, nil
}

func validatePlanRevisionCycles(
	revisions map[domain.UUIDv7]plan.Revision,
) error {
	colors := make(map[domain.UUIDv7]uint8, len(revisions))
	for id := range revisions {
		if colors[id] == 2 {
			continue
		}
		path := make([]domain.UUIDv7, 0)
		current := id
		for current != "" && colors[current] != 2 {
			revision, exists := revisions[current]
			if !exists {
				break
			}
			if colors[current] == 1 {
				return fmt.Errorf("supersession cycle at %q", current)
			}
			colors[current] = 1
			path = append(path, current)
			next, present := revision.Supersedes()
			if !present {
				break
			}
			current = next
		}
		for _, pathID := range path {
			colors[pathID] = 2
		}
	}
	return nil
}

func validateMemoryCycles(records map[domain.UUIDv7]memory.Record) error {
	colors := make(map[domain.UUIDv7]uint8, len(records))
	for id := range records {
		if colors[id] == 2 {
			continue
		}
		path := make([]domain.UUIDv7, 0)
		current := id
		for current != "" && colors[current] != 2 {
			record, exists := records[current]
			if !exists {
				break
			}
			if colors[current] == 1 {
				return fmt.Errorf("supersession cycle at %q", current)
			}
			colors[current] = 1
			path = append(path, current)
			next, present := record.Supersedes()
			if !present {
				break
			}
			current = next
		}
		for _, pathID := range path {
			colors[pathID] = 2
		}
	}
	return nil
}
