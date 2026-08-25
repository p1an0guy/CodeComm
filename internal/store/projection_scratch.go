package store

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/ijonahch/codecomm/internal/chain"
)

// ProjectionScratch is an in-memory copy of the digest-covered projection
// rows. It uses the same validated row encoder as the SQLite apply path.
type ProjectionScratch struct {
	rows map[string]chain.LogicalRow
}

// NewProjectionScratch validates and copies one complete projection cut.
func NewProjectionScratch(
	rows []chain.LogicalRow,
	versions chain.Versions,
) (*ProjectionScratch, error) {
	if _, err := chain.StateDigest(versions, rows); err != nil {
		return nil, fmt.Errorf(
			"%w: initialize projection scratch: %v",
			ErrIntegrityCheck,
			err,
		)
	}
	scratch := &ProjectionScratch{
		rows: make(map[string]chain.LogicalRow, len(rows)),
	}
	for _, row := range rows {
		identity := projectionScratchIdentity(row.Table, row.PrimaryKey)
		scratch.rows[identity] = cloneLogicalRow(row)
	}
	return scratch, nil
}

// Apply validates one logical write set, returns its exact before/after
// mutations, and advances the scratch rows atomically.
func (scratch *ProjectionScratch) Apply(
	writes ProjectionWrites,
) ([]chain.Mutation, error) {
	if scratch == nil || scratch.rows == nil {
		return nil, ErrInvalidOptions
	}
	prepared, err := prepareProjectionWrites(writes)
	if err != nil {
		return nil, err
	}
	targets, err := projectionTargets(prepared)
	if err != nil {
		return nil, err
	}
	mutations := make([]chain.Mutation, len(targets))
	for index, target := range targets {
		identity := projectionScratchIdentity(
			target.table.name,
			target.primaryKey,
		)
		mutation := chain.Mutation{
			Table:      target.table.name,
			PrimaryKey: bytes.Clone(target.primaryKey),
			After:      bytes.Clone(target.expectedAfter),
		}
		if before, exists := scratch.rows[identity]; exists {
			mutation.Before = bytes.Clone(before.Row)
		}
		mutations[index] = mutation
	}
	if _, err := chain.EncodeMutations(mutations); err != nil {
		return nil, fmt.Errorf(
			"%w: validate scratch projection mutations: %v",
			ErrIntegrityCheck,
			err,
		)
	}
	for index, target := range targets {
		row := chain.LogicalRow{
			Table:      target.table.name,
			PrimaryKey: bytes.Clone(target.primaryKey),
			Row:        bytes.Clone(target.expectedAfter),
		}
		scratch.rows[projectionScratchIdentity(
			row.Table,
			row.PrimaryKey,
		)] = row
		mutations[index] = cloneMutation(mutations[index])
	}
	return mutations, nil
}

// Rows returns an independent deterministic copy of the current rows.
func (scratch *ProjectionScratch) Rows() []chain.LogicalRow {
	if scratch == nil || scratch.rows == nil {
		return nil
	}
	identities := make([]string, 0, len(scratch.rows))
	for identity := range scratch.rows {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	rows := make([]chain.LogicalRow, len(identities))
	for index, identity := range identities {
		rows[index] = cloneLogicalRow(scratch.rows[identity])
	}
	return rows
}

// StateDigest returns the full digest at the current scratch cut.
func (scratch *ProjectionScratch) StateDigest(
	versions chain.Versions,
) (chain.Digest, error) {
	if scratch == nil || scratch.rows == nil {
		return chain.Digest{}, ErrInvalidOptions
	}
	rows := make([]chain.LogicalRow, 0, len(scratch.rows))
	for _, row := range scratch.rows {
		rows = append(rows, row)
	}
	return chain.StateDigest(versions, rows)
}

func projectionScratchIdentity(table string, primaryKey []byte) string {
	return table + "\x00" + string(primaryKey)
}

func cloneLogicalRow(row chain.LogicalRow) chain.LogicalRow {
	return chain.LogicalRow{
		Table:      row.Table,
		PrimaryKey: bytes.Clone(row.PrimaryKey),
		Row:        bytes.Clone(row.Row),
	}
}

func cloneMutation(mutation chain.Mutation) chain.Mutation {
	return chain.Mutation{
		Table:      mutation.Table,
		PrimaryKey: bytes.Clone(mutation.PrimaryKey),
		Before:     bytes.Clone(mutation.Before),
		After:      bytes.Clone(mutation.After),
	}
}
