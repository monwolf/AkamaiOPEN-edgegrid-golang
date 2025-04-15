//revive:disable:exported

package mtlstruststore

import (
	"context"

	"github.com/stretchr/testify/mock"
)

var _ MTLSTruststore = &Mock{}

// Mock is MTLS Truststore API Mock
type Mock struct {
	mock.Mock
}

func (m *Mock) CreateCASet(ctx context.Context, params CreateCASetRequest) (*CreateCASetResponse, error) {
	args := m.Called(ctx, params)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*CreateCASetResponse), args.Error(1)
}

func (m *Mock) GetCASet(ctx context.Context, params GetCASetRequest) (*GetCASetResponse, error) {
	args := m.Called(ctx, params)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*GetCASetResponse), args.Error(1)
}

func (m *Mock) ListCASets(ctx context.Context, params ListCASetsRequest) (*ListCASetsResponse, error) {
	args := m.Called(ctx, params)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*ListCASetsResponse), args.Error(1)
}

func (m *Mock) DeleteCASet(ctx context.Context, params DeleteCASetRequest) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}
