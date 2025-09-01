//revive:disable:exported

package v0

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

var _ APIDefinitions = &Mock{}

func (m *Mock) FromOpenAPIFile(ctx context.Context, body FromOpenAPIFileRequest) (*FromOpenAPIFileResponse, error) {
	args := m.Called(ctx, body)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*FromOpenAPIFileResponse), args.Error(1)
}

func (m *Mock) ToOpenAPIFile(ctx context.Context, request ToOpenAPIFileRequest) (*ToOpenAPIFileResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ToOpenAPIFileResponse), args.Error(1)
}

func (m *Mock) RegisterAPI(ctx context.Context, request RegisterAPIRequest) (*RegisterAPIResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*RegisterAPIResponse), args.Error(1)
}

func (m *Mock) GetAPIVersion(ctx context.Context, request GetAPIVersionRequest) (*GetAPIVersionResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*GetAPIVersionResponse), args.Error(1)
}

func (m *Mock) UpdateAPIVersion(ctx context.Context, request UpdateAPIVersionRequest) (*UpdateAPIVersionResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UpdateAPIVersionResponse), args.Error(1)
}

func (m *Mock) UpdateResourceOperation(ctx context.Context, req UpdateResourceOperationRequest) (*UpdateResourceOperationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UpdateResourceOperationResponse), args.Error(1)
}

func (m *Mock) GetResourceOperation(ctx context.Context, req GetResourceOperationRequest) (*GetResourceOperationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*GetResourceOperationResponse), args.Error(1)
}

func (m *Mock) DeleteResourceOperation(ctx context.Context, req DeleteResourceOperationRequest) (*DeleteResourceOperationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeleteResourceOperationResponse), args.Error(1)
}
