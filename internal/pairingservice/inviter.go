package pairingservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
)

const inviteCleanupTimeout = 5 * time.Second

var (
	ErrInvalidInviter     = errors.New("pairing service: invalid inviter")
	ErrInviteIssuance     = errors.New("pairing service: invite issuance failed")
	ErrInviteIDCollision  = errors.New("pairing service: invite identifier collision")
	ErrInviteNotRevocable = errors.New("pairing service: invite is not revocable")
)

// InviteState is the local durable boundary used by an issuing device.
type InviteState interface {
	ReservePairingInvite(
		context.Context,
		pairing.SignedInvite,
	) (store.PairingInviteRecord, bool, error)
	ActivatePairingInvite(
		context.Context,
		domain.UUIDv7,
		store.Digest,
	) (store.PairingInviteRecord, bool, error)
	TerminatePairingInvite(
		context.Context,
		domain.UUIDv7,
		store.Digest,
		store.PairingInviteState,
		domain.Timestamp,
	) (store.PairingInviteRecord, bool, error)
	PairingInvite(
		context.Context,
		domain.UUIDv7,
	) (store.PairingInviteRecord, bool, error)
	PairingInvites(
		context.Context,
		domain.DeviceID,
	) ([]store.PairingInviteRecord, error)
}

// InviteSecretStore atomically creates one native-store secret. Deletion is
// driven by the durable pairing_secret_deletions queue owned by Service.
type InviteSecretStore interface {
	Create(context.Context, credentialstore.Reference, []byte) error
}

// InviteSigner signs the exact complete invite without transferring ownership
// of the daemon's long-lived identity key to Inviter.
type InviteSigner func(pairing.Invite) (pairing.SignedInvite, error)

// InviteIDGenerator returns a never-reused UUIDv7.
type InviteIDGenerator func() (domain.UUIDv7, error)

// InviteEndpointProvider returns the issuer's complete current listener
// snapshot. The Inviter validates and clones every result before signing.
type InviteEndpointProvider func() ([]pairing.Endpoint, error)

// InviterOptions bind all issuer-controlled fields that must not come from a
// local operator request.
type InviterOptions struct {
	State               InviteState
	Secrets             InviteSecretStore
	SessionID           domain.UUIDv7
	WorkspaceID         domain.UUIDv4
	RecoveryGeneration  uint64
	IssuerDeviceID      domain.DeviceID
	IdentityPublicKey   []byte
	SignedGenesisDigest [sha256.Size]byte
	Endpoints           []pairing.Endpoint
	EndpointProvider    InviteEndpointProvider
	Sign                InviteSigner
	Clock               func() time.Time
	GenerateID          InviteIDGenerator
}

// CreateInviteRequest contains only the operator-reviewed policy fields.
type CreateInviteRequest struct {
	Mode                   pairing.Mode
	SubjectDeviceID        *domain.DeviceID
	ExpectedEntityVersion  *uint64
	Role                   device.Role
	InitialCredentialEpoch uint64
}

// IssuedInvite is returned only once the native secret and outstanding row
// are both durable.
type IssuedInvite struct {
	Invite pairing.SignedInvite
	Record store.PairingInviteRecord
}

// Inviter owns local invite issue/list/revoke operations.
type Inviter struct {
	state              InviteState
	secrets            InviteSecretStore
	sessionID          domain.UUIDv7
	workspaceID        domain.UUIDv4
	recoveryGeneration uint64
	issuerDeviceID     domain.DeviceID
	identityPublicKey  [ed25519.PublicKeySize]byte
	genesisDigest      [sha256.Size]byte
	endpoints          []pairing.Endpoint
	endpointProvider   InviteEndpointProvider
	sign               InviteSigner
	clock              func() time.Time
	generateID         InviteIDGenerator
}

// NewInviter validates immutable issuer input without creating native state.
func NewInviter(options InviterOptions) (*Inviter, error) {
	if options.State == nil ||
		options.Secrets == nil ||
		!options.SessionID.Valid() ||
		!options.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(options.RecoveryGeneration) ||
		!options.IssuerDeviceID.Valid() ||
		len(options.IdentityPublicKey) != ed25519.PublicKeySize ||
		len(options.Endpoints) > pairing.MaxInviteEndpoints ||
		options.EndpointProvider != nil && len(options.Endpoints) != 0 ||
		options.Sign == nil {
		return nil, ErrInvalidInviter
	}
	derived, err := device.DeriveID(options.IdentityPublicKey)
	if err != nil || derived != options.IssuerDeviceID {
		return nil, ErrInvalidInviter
	}
	endpoints := append([]pairing.Endpoint(nil), options.Endpoints...)
	if len(endpoints) != 0 && !validInviteEndpoints(endpoints) {
		return nil, ErrInvalidInviter
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	generateID := options.GenerateID
	if generateID == nil {
		generateID = generateInviteID
	}
	result := &Inviter{
		state: options.State, secrets: options.Secrets,
		sessionID: options.SessionID, workspaceID: options.WorkspaceID,
		recoveryGeneration: options.RecoveryGeneration,
		issuerDeviceID:     options.IssuerDeviceID,
		genesisDigest:      options.SignedGenesisDigest,
		endpoints:          endpoints,
		endpointProvider:   options.EndpointProvider,
		sign:               options.Sign, clock: clock,
		generateID: generateID,
	}
	copy(result.identityPublicKey[:], options.IdentityPublicKey)
	return result, nil
}

// Create reserves capacity before persisting the one-use secret and exposes
// the code only after the reservation is active.
func (inviter *Inviter) Create(
	ctx context.Context,
	request CreateInviteRequest,
) (IssuedInvite, error) {
	if inviter == nil || ctx == nil || request.validate() != nil {
		return IssuedInvite{}, ErrInvalidInviter
	}
	endpoints, err := inviter.currentEndpoints()
	if err != nil || len(endpoints) == 0 {
		return IssuedInvite{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return IssuedInvite{}, err
	}
	inviteID, err := inviter.generateID()
	if err != nil || !inviteID.Valid() {
		return IssuedInvite{}, fmt.Errorf("%w: generate identifier", ErrInviteIssuance)
	}
	now := inviter.clock().UTC().Truncate(time.Second)
	createdAt := domain.WholeSecondTimestamp(now.Format(time.RFC3339))
	expiresAt := domain.WholeSecondTimestamp(
		now.Add(pairing.InviteTTL).Format(time.RFC3339),
	)
	if !createdAt.Valid() || !expiresAt.Valid() {
		return IssuedInvite{}, fmt.Errorf("%w: invalid clock", ErrInviteIssuance)
	}
	secret, err := pairing.GenerateInviteSecret()
	if err != nil {
		return IssuedInvite{}, fmt.Errorf("%w: generate secret: %w", ErrInviteIssuance, err)
	}
	defer clear(secret[:])

	value := pairing.Invite{
		InviteID: inviteID, SessionID: inviter.sessionID,
		WorkspaceID:        inviter.workspaceID,
		RecoveryGeneration: inviter.recoveryGeneration,
		CreatedAt:          createdAt, ExpiresAt: expiresAt, Secret: secret,
		InviterDeviceID:     inviter.issuerDeviceID,
		SignedGenesisDigest: inviter.genesisDigest,
		Mode:                request.Mode, Role: request.Role,
		InitialCredentialEpoch: request.InitialCredentialEpoch,
		Endpoints:              endpoints,
	}
	copy(value.InviterIdentityPublicKey[:], inviter.identityPublicKey[:])
	value.SubjectDeviceID = cloneDeviceID(request.SubjectDeviceID)
	value.ExpectedEntityVersion = cloneVersion(request.ExpectedEntityVersion)
	signed, err := inviter.sign(value)
	clear(value.Secret[:])
	if err != nil {
		return IssuedInvite{}, fmt.Errorf("%w: sign invite: %w", ErrInviteIssuance, err)
	}

	record, duplicate, err := inviter.state.ReservePairingInvite(ctx, signed)
	if err != nil {
		return IssuedInvite{}, fmt.Errorf("%w: reserve invite: %w", ErrInviteIssuance, err)
	}
	if duplicate {
		return IssuedInvite{}, ErrInviteIDCollision
	}
	reference, err := credentialstore.InviteReference(
		inviter.sessionID,
		record.InviteID,
	)
	if err != nil {
		return IssuedInvite{}, errors.Join(
			fmt.Errorf("%w: secret reference: %w", ErrInviteIssuance, err),
			inviter.abandon(record),
		)
	}
	inviteValue := signed.Invite()
	secretBytes := bytes.Clone(inviteValue.Secret[:])
	clear(inviteValue.Secret[:])
	createErr := inviter.secrets.Create(ctx, reference, secretBytes)
	clear(secretBytes)
	if createErr != nil {
		return IssuedInvite{}, errors.Join(
			fmt.Errorf("%w: persist secret: %w", ErrInviteIssuance, createErr),
			inviter.abandon(record),
		)
	}
	activated, _, err := inviter.state.ActivatePairingInvite(
		ctx,
		record.InviteID,
		record.InviteDigest,
	)
	if err != nil {
		return IssuedInvite{}, errors.Join(
			fmt.Errorf("%w: activate invite: %w", ErrInviteIssuance, err),
			inviter.abandon(record),
		)
	}
	return IssuedInvite{Invite: signed, Record: activated}, nil
}

func (inviter *Inviter) currentEndpoints() (
	endpoints []pairing.Endpoint,
	err error,
) {
	if inviter == nil {
		return nil, ErrInvalidInviter
	}
	if inviter.endpointProvider == nil {
		return append([]pairing.Endpoint(nil), inviter.endpoints...), nil
	}
	defer func() {
		if recover() != nil {
			endpoints = nil
			err = ErrUnavailable
		}
	}()
	endpoints, err = inviter.endpointProvider()
	if err != nil ||
		len(endpoints) == 0 ||
		len(endpoints) > pairing.MaxInviteEndpoints {
		return nil, ErrUnavailable
	}
	endpoints = append([]pairing.Endpoint(nil), endpoints...)
	if !validInviteEndpoints(endpoints) {
		return nil, ErrUnavailable
	}
	return endpoints, nil
}

// List returns only revocable issuer-local invites without reading any secret.
func (inviter *Inviter) List(
	ctx context.Context,
) ([]store.PairingInviteRecord, error) {
	if inviter == nil || ctx == nil {
		return nil, ErrInvalidInviter
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	records, err := inviter.state.PairingInvites(ctx, inviter.issuerDeviceID)
	if err != nil {
		return nil, fmt.Errorf("%w: list invites: %w", ErrUnavailable, err)
	}
	result := make(
		[]store.PairingInviteRecord,
		0,
		min(len(records), store.MaxOutstandingPairingInvites),
	)
	for _, record := range records {
		if record.State != store.PairingInvitePreparing &&
			record.State != store.PairingInviteOutstanding {
			continue
		}
		if len(result) == store.MaxOutstandingPairingInvites {
			return nil, fmt.Errorf(
				"%w: outstanding invite cap exceeded",
				ErrUnavailable,
			)
		}
		result = append(result, record)
	}
	return result, nil
}

// Revoke terminally voids one unused invite and queues native-secret deletion.
func (inviter *Inviter) Revoke(
	ctx context.Context,
	inviteID domain.UUIDv7,
) (store.PairingInviteRecord, bool, error) {
	if inviter == nil || ctx == nil || !inviteID.Valid() {
		return store.PairingInviteRecord{}, false, ErrInvalidInviter
	}
	if err := ctx.Err(); err != nil {
		return store.PairingInviteRecord{}, false, err
	}
	record, found, err := inviter.state.PairingInvite(ctx, inviteID)
	if err != nil {
		return store.PairingInviteRecord{}, false, fmt.Errorf(
			"%w: read invite: %w",
			ErrUnavailable,
			err,
		)
	}
	if !found || record.IssuerDeviceID != inviter.issuerDeviceID {
		return store.PairingInviteRecord{}, false, ErrRequestRejected
	}
	if record.State == store.PairingInviteRevoked {
		return record, true, nil
	}
	if record.State != store.PairingInvitePreparing &&
		record.State != store.PairingInviteOutstanding {
		return store.PairingInviteRecord{}, false, ErrInviteNotRevocable
	}
	now := domain.Timestamp(inviter.clock().UTC().Format(time.RFC3339Nano))
	if !now.Valid() {
		return store.PairingInviteRecord{}, false, ErrUnavailable
	}
	revoked, duplicate, err := inviter.state.TerminatePairingInvite(
		ctx,
		record.InviteID,
		record.InviteDigest,
		store.PairingInviteRevoked,
		now,
	)
	if err != nil {
		return store.PairingInviteRecord{}, false, fmt.Errorf(
			"%w: revoke invite: %w",
			ErrUnavailable,
			err,
		)
	}
	return revoked, duplicate, nil
}

func (inviter *Inviter) abandon(record store.PairingInviteRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), inviteCleanupTimeout)
	defer cancel()
	now := domain.Timestamp(inviter.clock().UTC().Format(time.RFC3339Nano))
	if !now.Valid() {
		now = domain.Timestamp(record.CreatedAt)
	}
	_, _, err := inviter.state.TerminatePairingInvite(
		ctx,
		record.InviteID,
		record.InviteDigest,
		store.PairingInviteAbandoned,
		now,
	)
	if err != nil {
		return fmt.Errorf("pairing service: abandon failed invite: %w", err)
	}
	return nil
}

func (request CreateInviteRequest) validate() error {
	if !request.Mode.Valid() ||
		!request.Role.Valid() ||
		request.InitialCredentialEpoch < 1 ||
		!domain.ValidUnsignedInteger(request.InitialCredentialEpoch) {
		return ErrInvalidInviter
	}
	switch request.Mode {
	case pairing.ModeNew:
		if request.SubjectDeviceID != nil ||
			request.ExpectedEntityVersion != nil ||
			request.InitialCredentialEpoch != 1 {
			return ErrInvalidInviter
		}
	case pairing.ModeRebootstrap:
		if request.SubjectDeviceID == nil ||
			!request.SubjectDeviceID.Valid() ||
			request.ExpectedEntityVersion != nil {
			return ErrInvalidInviter
		}
	case pairing.ModeReadmission:
		if request.SubjectDeviceID == nil ||
			!request.SubjectDeviceID.Valid() ||
			request.ExpectedEntityVersion == nil ||
			*request.ExpectedEntityVersion < 1 ||
			!domain.ValidUnsignedInteger(*request.ExpectedEntityVersion) ||
			request.InitialCredentialEpoch != 1 {
			return ErrInvalidInviter
		}
	default:
		return ErrInvalidInviter
	}
	return nil
}

func validInviteEndpoints(endpoints []pairing.Endpoint) bool {
	if len(endpoints) < 1 || len(endpoints) > pairing.MaxInviteEndpoints {
		return false
	}
	port := endpoints[0].Port
	for index, endpoint := range endpoints {
		address := endpoint.IP
		if !address.IsValid() ||
			address.Zone() != "" ||
			endpoint.Port == 0 ||
			endpoint.Port != port ||
			address.IsLoopback() ||
			address.IsUnspecified() ||
			address.IsMulticast() ||
			address.Is4In6() ||
			address.Is6() && address.IsLinkLocalUnicast() ||
			address.Is4() &&
				address.As4() == [4]byte{255, 255, 255, 255} {
			return false
		}
		if index > 0 &&
			compareInviteEndpoints(endpoints[index-1], endpoint) >= 0 {
			return false
		}
	}
	return true
}

func compareInviteEndpoints(left, right pairing.Endpoint) int {
	if left.IP.Is4() != right.IP.Is4() {
		if left.IP.Is4() {
			return -1
		}
		return 1
	}
	if order := slices.Compare(left.IP.AsSlice(), right.IP.AsSlice()); order != 0 {
		return order
	}
	return int(left.Port) - int(right.Port)
}

func cloneDeviceID(value *domain.DeviceID) *domain.DeviceID {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func generateInviteID() (domain.UUIDv7, error) {
	value, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	result := domain.UUIDv7(value.String())
	if !result.Valid() {
		return "", domain.ErrInvalidUUIDv7
	}
	return result, nil
}
