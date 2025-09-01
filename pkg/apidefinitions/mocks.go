//revive:disable:exported

package apidefinitions

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

var _ APIDefinitions = &Mock{}

func (m *Mock) GetEndpoint(ctx context.Context, request GetEndpointRequest) (*GetEndpointResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*GetEndpointResponse), args.Error(1)
}

func (m *Mock) ActivateVersion(ctx context.Context, req ActivateVersionRequest) (*ActivateVersionResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ActivateVersionResponse), args.Error(1)
}

func (m *Mock) DeactivateVersion(ctx context.Context, req DeactivateVersionRequest) (*DeactivateVersionResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeactivateVersionResponse), args.Error(1)
}

func (m *Mock) VerifyVersion(ctx context.Context, request VerifyVersionRequest) (VerifyVersionResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(VerifyVersionResponse), args.Error(1)
}

func (m *Mock) RegisterEndpoint(ctx context.Context, req RegisterEndpointRequest) (*RegisterEndpointResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*RegisterEndpointResponse), args.Error(1)
}

func (m *Mock) RegisterEndpointFromFile(ctx context.Context, req RegisterEndpointFromFileRequest) (*RegisterEndpointFromFileResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*RegisterEndpointFromFileResponse), args.Error(1)
}

func (m *Mock) ShowEndpoint(ctx context.Context, req ShowEndpointRequest) (*ShowEndpointResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ShowEndpointResponse), args.Error(1)
}

func (m *Mock) HideEndpoint(ctx context.Context, req HideEndpointRequest) (*HideEndpointResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*HideEndpointResponse), args.Error(1)
}

func (m *Mock) DeleteEndpoint(ctx context.Context, req DeleteEndpointRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *Mock) ListEndpoints(ctx context.Context, req ListEndpointsRequest) (*ListEndpointsResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ListEndpointsResponse), args.Error(1)
}

func (m *Mock) ListUserEntitlements(ctx context.Context) (ListUserEntitlementsResponse, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(ListUserEntitlementsResponse), args.Error(1)
}

func (m *Mock) ListEndpointVersions(ctx context.Context, req ListEndpointVersionsRequest) (*ListEndpointVersionsResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ListEndpointVersionsResponse), args.Error(1)
}

func (m *Mock) GetEndpointVersion(ctx context.Context, req GetEndpointVersionRequest) (*GetEndpointVersionResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*GetEndpointVersionResponse), args.Error(1)
}

func (m *Mock) UpdateEndpointVersion(ctx context.Context, req UpdateEndpointVersionRequest) (*UpdateEndpointVersionResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UpdateEndpointVersionResponse), args.Error(1)
}

func (m *Mock) CloneEndpointVersion(ctx context.Context, req CloneEndpointVersionRequest) (*CloneEndpointVersionResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*CloneEndpointVersionResponse), args.Error(1)
}

func (m *Mock) DeleteEndpointVersion(ctx context.Context, req DeleteEndpointVersionRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *Mock) SearchResourceOperations(ctx context.Context) (*SearchResourceOperationsResponse, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*SearchResourceOperationsResponse), args.Error(1)
}
