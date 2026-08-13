package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
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

// StateDigest computes the full logical projection-state digest. All covered
// tables contribute in registry order, including tables with no rows.
func StateDigest(versions Versions, rows []LogicalRow) (Digest, error) {
	if versions.Digest == 0 ||
		versions.Digest > maxSafeInteger ||
		versions.ProjectionSchema == 0 ||
		versions.ProjectionSchema > maxSafeInteger {
		return Digest{}, fmt.Errorf(
			"%w: digest=%d projection_schema=%d",
			ErrInvalidVersions,
			versions.Digest,
			versions.ProjectionSchema,
		)
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

	state := sha256.New()
	writeBytes(state, []byte(projectionStateLabel))
	writeBytes(state, []byte{0})
	writeUint64(state, versions.Digest)
	writeUint64(state, versions.ProjectionSchema)

	rowIndex := 0
	for tableIndex, spec := range coveredTableRegistry {
		start := rowIndex
		for rowIndex < len(prepared) &&
			prepared[rowIndex].tableIndex == tableIndex {
			rowIndex++
		}
		digest := tableDigest(spec.name, prepared[start:rowIndex])
		writeBytes(state, digest[:])
	}

	var digest Digest
	copy(digest[:], state.Sum(nil))
	return digest, nil
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

func tableDigest(table string, rows []preparedRow) Digest {
	digester := sha256.New()
	writeBytes(digester, []byte(projectionTableLabel))
	writeBytes(digester, []byte{0})
	writeUint64(digester, uint64(len(table)))
	writeBytes(digester, []byte(table))
	writeUint64(digester, uint64(len(rows)))
	for _, row := range rows {
		digest := rowDigest(table, row)
		writeBytes(digester, digest[:])
	}
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
