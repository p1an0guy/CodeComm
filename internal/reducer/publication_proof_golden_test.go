package reducer

import (
	"encoding/json"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
)

func TestPublicationMetadataAndReceiptGoldenVectors(t *testing.T) {
	t.Parallel()

	const (
		wantMetadataDigest   = "lad00NjtdxchQKXfqr7MYOTR9ZYxSPFXlVFTC6zbJBk"
		wantReceiptObject    = `{"publication_metadata_digest":"lad00NjtdxchQKXfqr7MYOTR9ZYxSPFXlVFTC6zbJBk","session_id":"01890f47-3e72-7000-8000-000000000001","staged_result_index":1,"voter_device_id":"cc134750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e","voter_set_version":1,"workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
		wantReceiptSignature = "xaUVF7bNrYlerdVimCljOK7C4DlfFUES3yKgLYBm4sOgZUtihuqiZ1JeWOnO5SoJYP7X9Acyw-h9dGgMLnolAQ"
	)
	fixture := newReducerFixture(t)
	metadata := testPublicationMetadata(
		fixture,
		testPublicationID,
		testPublicationEventID,
		"",
		fixture.state.canonicalRef.CommitOID,
		testReducerGitOID(20),
		testReducerGitOID(21),
	)
	digest, err := publicationMetadataDigest(metadata)
	if err != nil {
		t.Fatalf("publicationMetadataDigest() error = %v", err)
	}
	receipt := signedStagingReceipts(
		t,
		fixture,
		metadata,
		fixture.state.currentResultIndex,
	)[0]
	encoded, err := json.Marshal(stagingReceiptUnsignedWire{
		SessionID:       string(receipt.SessionID),
		WorkspaceID:     string(receipt.WorkspaceID),
		VoterSetVersion: receipt.VoterSetVersion,
		PublicationMetadataDigest: codec.EncodeBase64URL(
			receipt.PublicationMetadataDigest[:],
		),
		VoterDeviceID:     string(receipt.VoterDeviceID),
		StagedResultIndex: receipt.StagedResultIndex,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject() error = %v", err)
	}

	if got := codec.EncodeBase64URL(digest[:]); got != wantMetadataDigest {
		t.Fatalf("metadata digest = %q, want %q", got, wantMetadataDigest)
	}
	if got := string(canonical); got != wantReceiptObject {
		t.Fatalf("receipt object = %q, want %q", got, wantReceiptObject)
	}
	if got := codec.EncodeBase64URL(receipt.Signature[:]); got != wantReceiptSignature {
		t.Fatalf("receipt signature = %q, want %q", got, wantReceiptSignature)
	}
	if !verifyStagingReceiptSignature(
		receipt,
		fixture.state.devices[receipt.VoterDeviceID].IdentityPublicKey,
	) {
		t.Fatal("golden receipt signature did not verify")
	}
}
