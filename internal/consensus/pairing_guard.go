package consensus

import (
	"context"
	"errors"
	"sync"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
)

var ErrPairingSubjectConfigured = errors.New(
	"consensus: pairing subject remains in the live Raft configuration",
)

// AcquireSettledNonvoter excludes voter reconciliation while an existing
// device's pairing proof is consumed. The returned release must be called.
func (node *SingleNode) AcquireSettledNonvoter(
	ctx context.Context,
	deviceID domain.DeviceID,
) (func(), error) {
	if node == nil ||
		node.raft == nil ||
		node.voterReconcileGate == nil ||
		ctx == nil ||
		!deviceID.Valid() {
		return nil, ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := node.beginOperation(); err != nil {
		return nil, err
	}
	operationContext, cancel, wait := node.operationContext(ctx)
	ownsOperation := true
	ownsGate := false
	success := false
	release := func() {
		if ownsGate {
			<-node.voterReconcileGate
			ownsGate = false
		}
		if ownsOperation {
			cancel()
			wait()
			node.endOperation()
			ownsOperation = false
		}
	}
	defer func() {
		if !success {
			release()
		}
	}()

	select {
	case node.voterReconcileGate <- struct{}{}:
		ownsGate = true
	case <-operationContext.Done():
		return nil, operationContext.Err()
	}
	if err := node.FatalError(); err != nil {
		return nil, err
	}
	future := node.raft.GetConfiguration()
	if err := waitFuture(operationContext, future); err != nil {
		return nil, err
	}
	for _, server := range future.Configuration().Servers {
		if server.ID == raft.ServerID(deviceID) {
			return nil, ErrPairingSubjectConfigured
		}
	}

	var once sync.Once
	guardRelease := func() {
		once.Do(release)
	}
	success = true
	return guardRelease, nil
}
