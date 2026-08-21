package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"sort"
)

const maxEncodedMutationBytes = 32 << 20

type preparedMutation struct {
	tableIndex int
	table      string
	primaryKey []byte
	before     []byte
	after      []byte
}

// EncodeMutations validates, sorts, and JCS-encodes exact logical row
// transitions.
func EncodeMutations(mutations []Mutation) ([]byte, error) {
	prepared := make([]preparedMutation, 0, len(mutations))
	for index, mutation := range mutations {
		spec, tableIndex, exists := lookupTable(mutation.Table)
		if !exists {
			return nil, fmt.Errorf(
				"%w: mutation %d table %q",
				ErrUnknownTable,
				index,
				mutation.Table,
			)
		}
		components, err := validatePrimaryKey(spec, mutation.PrimaryKey)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: mutation %d: %w",
				ErrInvalidMutation,
				index,
				err,
			)
		}
		if mutation.Before == nil && mutation.After == nil {
			return nil, fmt.Errorf(
				"%w: mutation %d has null before and after",
				ErrInvalidMutation,
				index,
			)
		}
		if mutation.Before != nil {
			if err := validateLogicalRow(
				spec,
				components,
				mutation.Before,
				ErrInvalidMutation,
			); err != nil {
				return nil, fmt.Errorf("mutation %d: %w", index, err)
			}
		}
		if mutation.After != nil {
			if err := validateLogicalRow(
				spec,
				components,
				mutation.After,
				ErrInvalidMutation,
			); err != nil {
				return nil, fmt.Errorf("mutation %d: %w", index, err)
			}
		}
		if mutation.Before != nil &&
			mutation.After != nil &&
			bytes.Equal(mutation.Before, mutation.After) {
			return nil, fmt.Errorf(
				"%w: mutation %d has identical before and after rows",
				ErrInvalidMutation,
				index,
			)
		}
		prepared = append(prepared, preparedMutation{
			tableIndex: tableIndex,
			table:      mutation.Table,
			primaryKey: mutation.PrimaryKey,
			before:     mutation.Before,
			after:      mutation.After,
		})
	}

	sort.Slice(prepared, func(left, right int) bool {
		if prepared[left].tableIndex != prepared[right].tableIndex {
			return prepared[left].tableIndex < prepared[right].tableIndex
		}
		return bytes.Compare(
			prepared[left].primaryKey,
			prepared[right].primaryKey,
		) < 0
	})
	for index := 1; index < len(prepared); index++ {
		if prepared[index-1].tableIndex == prepared[index].tableIndex &&
			bytes.Equal(prepared[index-1].primaryKey, prepared[index].primaryKey) {
			return nil, fmt.Errorf(
				"%w: table %s",
				ErrDuplicateMutation,
				prepared[index].table,
			)
		}
	}

	return encodePreparedMutations(prepared)
}

// DecodeMutations parses an exact EncodeMutations result. It rejects unknown,
// missing, duplicate, unsorted, or otherwise noncanonical members.
func DecodeMutations(encoded []byte) ([]Mutation, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf("%w: empty encoding", ErrInvalidMutation)
	}
	if len(encoded) > maxEncodedMutationBytes {
		return nil, fmt.Errorf(
			"%w: %w: exceeds %d bytes",
			ErrInvalidMutation,
			ErrMutationSetTooLarge,
			maxEncodedMutationBytes,
		)
	}
	type wireMutation struct {
		After      json.RawMessage `json:"after"`
		Before     json.RawMessage `json:"before"`
		PrimaryKey json.RawMessage `json:"primary_key"`
		Table      *string         `json:"table"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire []wireMutation
	if err := decoder.Decode(&wire); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidMutation, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf(
				"%w: trailing JSON value",
				ErrInvalidMutation,
			)
		}
		return nil, fmt.Errorf(
			"%w: trailing JSON: %v",
			ErrInvalidMutation,
			err,
		)
	}

	mutations := make([]Mutation, len(wire))
	for index, value := range wire {
		if value.Table == nil ||
			value.PrimaryKey == nil ||
			value.Before == nil ||
			value.After == nil {
			return nil, fmt.Errorf(
				"%w: mutation %d omits a required member",
				ErrInvalidMutation,
				index,
			)
		}
		mutations[index] = Mutation{
			Table:      *value.Table,
			PrimaryKey: bytes.Clone(value.PrimaryKey),
			Before:     cloneNullableJSON(value.Before),
			After:      cloneNullableJSON(value.After),
		}
	}
	canonical, err := EncodeMutations(mutations)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMutation, err)
	}
	if !bytes.Equal(canonical, encoded) {
		return nil, fmt.Errorf(
			"%w: encoding is not canonical",
			ErrInvalidMutation,
		)
	}
	return mutations, nil
}

func cloneNullableJSON(value json.RawMessage) []byte {
	if bytes.Equal(value, []byte("null")) {
		return nil
	}
	return bytes.Clone(value)
}

func encodePreparedMutations(prepared []preparedMutation) ([]byte, error) {
	capacity := maxEncodedMutationBytes
	if len(prepared) <= (maxEncodedMutationBytes-2)/128 {
		capacity = 2 + len(prepared)*128
	}
	encoded := make([]byte, 0, capacity)
	appendBytes := func(value []byte) error {
		if len(value) > maxEncodedMutationBytes-len(encoded) {
			return fmt.Errorf(
				"%w: exceeds %d bytes",
				ErrMutationSetTooLarge,
				maxEncodedMutationBytes,
			)
		}
		encoded = append(encoded, value...)
		return nil
	}
	if err := appendBytes([]byte{'['}); err != nil {
		return nil, err
	}
	for index, mutation := range prepared {
		if index != 0 {
			if err := appendBytes([]byte{','}); err != nil {
				return nil, err
			}
		}
		tableJSON, err := json.Marshal(mutation.table)
		if err != nil {
			return nil, fmt.Errorf(
				"chain: encode mutation table %q: %w",
				mutation.table,
				err,
			)
		}
		parts := [][]byte{
			[]byte(`{"after":`),
			nullableJSON(mutation.after),
			[]byte(`,"before":`),
			nullableJSON(mutation.before),
			[]byte(`,"primary_key":`),
			mutation.primaryKey,
			[]byte(`,"table":`),
			tableJSON,
			[]byte{'}'},
		}
		for _, part := range parts {
			if err := appendBytes(part); err != nil {
				return nil, err
			}
		}
	}
	if err := appendBytes([]byte{']'}); err != nil {
		return nil, err
	}
	return encoded, nil
}

// AppendAccumulator extends the projection accumulator and returns the exact
// sorted mutation bytes used in its preimage.
func AppendAccumulator(
	previous Digest,
	resultIndex uint64,
	resultHash Digest,
	mutations []Mutation,
) (Digest, []byte, error) {
	if resultIndex == 0 || resultIndex > maxSafeInteger {
		return Digest{}, nil, fmt.Errorf(
			"%w: accumulator result index %d",
			ErrInvalidIndex,
			resultIndex,
		)
	}
	encoded, err := EncodeMutations(mutations)
	if err != nil {
		return Digest{}, nil, err
	}

	digester := sha256.New()
	writeBytes(digester, []byte(projectionAccumulatorLabel))
	writeBytes(digester, []byte{0})
	writeBytes(digester, previous[:])
	writeUint64(digester, resultIndex)
	writeBytes(digester, resultHash[:])
	writeUint64(digester, uint64(len(encoded)))
	writeBytes(digester, encoded)
	var digest Digest
	copy(digest[:], digester.Sum(nil))
	return digest, encoded, nil
}

type preparedRow struct {
	tableIndex int
	primaryKey []byte
	row        []byte
}

// StateDigester computes the existing projection-state digest from rows
// streamed in covered-table and primary-key order. Counts are supplied first
// because each table digest frames its cardinality before its row hashes.
type StateDigester struct {
	state              hash.Hash
	table              hash.Hash
	counts             []uint64
	tableIndex         int
	rowsInTable        uint64
	previousPrimaryKey []byte
	digest             Digest
	finished           bool
}

// NewStateDigester validates the exact covered-table cardinality vector and
// prepares an ordered streaming projection-state digest.
func NewStateDigester(
	versions Versions,
	counts []TableRowCount,
) (*StateDigester, error) {
	if err := validateStateDigestVersions(versions); err != nil {
		return nil, err
	}
	if len(counts) != len(coveredTableRegistry) {
		return nil, fmt.Errorf(
			"%w: got %d table counts, want %d",
			ErrLogicalRowOrder,
			len(counts),
			len(coveredTableRegistry),
		)
	}
	rowCounts := make([]uint64, len(counts))
	for index, count := range counts {
		if count.Table != coveredTableRegistry[index].name ||
			count.Count > maxSafeInteger {
			return nil, fmt.Errorf(
				"%w: invalid table count %d for %q",
				ErrLogicalRowOrder,
				count.Count,
				count.Table,
			)
		}
		rowCounts[index] = count.Count
	}

	state := sha256.New()
	writeBytes(state, []byte(projectionStateLabel))
	writeBytes(state, []byte{0})
	writeUint64(state, versions.Digest)
	writeUint64(state, versions.ProjectionSchema)
	digester := &StateDigester{
		state:  state,
		counts: rowCounts,
	}
	digester.startTable()
	return digester, nil
}

// Append validates and hashes one logical row. Rows must be strictly ordered
// by covered-table registry position and then canonical primary-key bytes.
func (digester *StateDigester) Append(row LogicalRow) error {
	if digester == nil || digester.finished ||
		digester.tableIndex >= len(coveredTableRegistry) {
		return ErrLogicalRowOrder
	}
	spec, tableIndex, exists := lookupTable(row.Table)
	if !exists {
		return fmt.Errorf("%w: table %q", ErrUnknownTable, row.Table)
	}
	for digester.tableIndex < tableIndex {
		if err := digester.finishTable(); err != nil {
			return err
		}
		digester.tableIndex++
		digester.startTable()
	}
	if tableIndex != digester.tableIndex ||
		digester.rowsInTable >= digester.counts[tableIndex] {
		return fmt.Errorf(
			"%w: unexpected row for table %q",
			ErrLogicalRowOrder,
			row.Table,
		)
	}
	components, err := validatePrimaryKey(spec, row.PrimaryKey)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidLogicalRow, err)
	}
	if err := validateLogicalRow(
		spec,
		components,
		row.Row,
		ErrInvalidLogicalRow,
	); err != nil {
		return err
	}
	if digester.rowsInTable != 0 &&
		bytes.Compare(digester.previousPrimaryKey, row.PrimaryKey) >= 0 {
		return fmt.Errorf(
			"%w: table %s",
			ErrLogicalRowOrder,
			row.Table,
		)
	}
	digest := rowDigest(row.Table, preparedRow{
		tableIndex: tableIndex,
		primaryKey: row.PrimaryKey,
		row:        row.Row,
	})
	writeBytes(digester.table, digest[:])
	digester.rowsInTable++
	digester.previousPrimaryKey = bytes.Clone(row.PrimaryKey)
	return nil
}

// Sum finishes every table, requiring the declared row counts to match, and
// returns the projection-state digest. Repeated calls return the same value.
func (digester *StateDigester) Sum() (Digest, error) {
	if digester == nil || digester.state == nil {
		return Digest{}, ErrLogicalRowOrder
	}
	if digester.finished {
		return digester.digest, nil
	}
	for digester.tableIndex < len(coveredTableRegistry) {
		if err := digester.finishTable(); err != nil {
			return Digest{}, err
		}
		digester.tableIndex++
		if digester.tableIndex < len(coveredTableRegistry) {
			digester.startTable()
		}
	}
	copy(digester.digest[:], digester.state.Sum(nil))
	digester.finished = true
	digester.previousPrimaryKey = nil
	return digester.digest, nil
}

func (digester *StateDigester) startTable() {
	if digester == nil ||
		digester.tableIndex >= len(coveredTableRegistry) {
		return
	}
	table := coveredTableRegistry[digester.tableIndex].name
	digester.table = sha256.New()
	writeBytes(digester.table, []byte(projectionTableLabel))
	writeBytes(digester.table, []byte{0})
	writeUint64(digester.table, uint64(len(table)))
	writeBytes(digester.table, []byte(table))
	writeUint64(digester.table, digester.counts[digester.tableIndex])
	digester.rowsInTable = 0
	digester.previousPrimaryKey = nil
}

func (digester *StateDigester) finishTable() error {
	if digester == nil ||
		digester.tableIndex >= len(coveredTableRegistry) ||
		digester.table == nil ||
		digester.rowsInTable != digester.counts[digester.tableIndex] {
		return fmt.Errorf(
			"%w: table %d row count differs",
			ErrLogicalRowOrder,
			digester.tableIndex,
		)
	}
	writeBytes(digester.state, digester.table.Sum(nil))
	return nil
}

// StateDigest computes the full logical projection-state digest. All covered
// tables contribute in registry order, including tables with no rows.
func StateDigest(versions Versions, rows []LogicalRow) (Digest, error) {
	if err := validateStateDigestVersions(versions); err != nil {
		return Digest{}, err
	}
	prepared := make([]preparedRow, 0, len(rows))
	for index, row := range rows {
		spec, tableIndex, exists := lookupTable(row.Table)
		if !exists {
			return Digest{}, fmt.Errorf(
				"%w: row %d table %q",
				ErrUnknownTable,
				index,
				row.Table,
			)
		}
		components, err := validatePrimaryKey(spec, row.PrimaryKey)
		if err != nil {
			return Digest{}, fmt.Errorf(
				"%w: row %d: %w",
				ErrInvalidLogicalRow,
				index,
				err,
			)
		}
		if err := validateLogicalRow(
			spec,
			components,
			row.Row,
			ErrInvalidLogicalRow,
		); err != nil {
			return Digest{}, fmt.Errorf("row %d: %w", index, err)
		}
		prepared = append(prepared, preparedRow{
			tableIndex: tableIndex,
			primaryKey: row.PrimaryKey,
			row:        row.Row,
		})
	}

	sort.Slice(prepared, func(left, right int) bool {
		if prepared[left].tableIndex != prepared[right].tableIndex {
			return prepared[left].tableIndex < prepared[right].tableIndex
		}
		return bytes.Compare(
			prepared[left].primaryKey,
			prepared[right].primaryKey,
		) < 0
	})
	for index := 1; index < len(prepared); index++ {
		if prepared[index-1].tableIndex == prepared[index].tableIndex &&
			bytes.Equal(prepared[index-1].primaryKey, prepared[index].primaryKey) {
			return Digest{}, fmt.Errorf(
				"%w: table %s",
				ErrDuplicateLogicalRow,
				coveredTableRegistry[prepared[index].tableIndex].name,
			)
		}
	}

	counts := make([]TableRowCount, len(coveredTableRegistry))
	for index := range coveredTableRegistry {
		counts[index].Table = coveredTableRegistry[index].name
	}
	for _, row := range prepared {
		counts[row.tableIndex].Count++
	}
	digester, err := NewStateDigester(versions, counts)
	if err != nil {
		return Digest{}, err
	}
	for _, row := range prepared {
		if err := digester.Append(LogicalRow{
			Table:      coveredTableRegistry[row.tableIndex].name,
			PrimaryKey: row.primaryKey,
			Row:        row.row,
		}); err != nil {
			return Digest{}, err
		}
	}
	return digester.Sum()
}

func validateStateDigestVersions(versions Versions) error {
	if versions.Digest == 0 ||
		versions.Digest > maxSafeInteger ||
		versions.ProjectionSchema == 0 ||
		versions.ProjectionSchema > maxSafeInteger {
		return fmt.Errorf(
			"%w: digest=%d projection_schema=%d",
			ErrInvalidVersions,
			versions.Digest,
			versions.ProjectionSchema,
		)
	}
	return nil
}

func rowDigest(table string, row preparedRow) Digest {
	digester := sha256.New()
	writeBytes(digester, []byte(projectionRowLabel))
	writeBytes(digester, []byte{0})
	writeUint64(digester, uint64(len(table)))
	writeBytes(digester, []byte(table))
	writeUint64(digester, uint64(len(row.primaryKey)))
	writeBytes(digester, row.primaryKey)
	writeUint64(digester, uint64(len(row.row)))
	writeBytes(digester, row.row)
	var digest Digest
	copy(digest[:], digester.Sum(nil))
	return digest
}

func nullableJSON(value []byte) json.RawMessage {
	if value == nil {
		return json.RawMessage("null")
	}
	return json.RawMessage(value)
}
