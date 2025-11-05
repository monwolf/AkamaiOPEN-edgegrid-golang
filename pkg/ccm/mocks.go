//revive:disable:exported

package ccm

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

var _ CCM = &Mock{}

func (m *Mock) CreateCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResponse, error) {
	args := m.Called(ctx, req)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*CreateCertificateResponse), args.Error(1)
}

func (m *Mock) GetCertificate(ctx context.Context, req GetCertificateRequest) (*GetCertificateResponse, error) {
	args := m.Called(ctx, req)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*GetCertificateResponse), args.Error(1)
}

func (m *Mock) PatchCertificate(ctx context.Context, req PatchCertificateRequest) (*PatchCertificateResponse, error) {
	args := m.Called(ctx, req)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*PatchCertificateResponse), args.Error(1)
}

func (m *Mock) UpdateCertificate(ctx context.Context, req UpdateCertificateRequest) (*UpdateCertificateResponse, error) {
	args := m.Called(ctx, req)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*UpdateCertificateResponse), args.Error(1)
}

func (m *Mock) DeleteCertificate(ctx context.Context, req DeleteCertificateRequest) (*DeleteCertificateResponse, error) {
	args := m.Called(ctx, req)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*DeleteCertificateResponse), args.Error(1)
}

func (m *Mock) ListCertificateBindings(ctx context.Context, req ListCertificateBindingsRequest) (*ListCertificateBindingsResponse, error) {
	args := m.Called(ctx, req)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*ListCertificateBindingsResponse), args.Error(1)
}

func (m *Mock) ListCertificates(ctx context.Context, req ListCertificatesRequest) (*ListCertificatesResponse, error) {
	args := m.Called(ctx, req)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*ListCertificatesResponse), args.Error(1)
}

func (m *Mock) ListBindings(ctx context.Context, req ListBindingsRequest) (*ListBindingsResponse, error) {
	args := m.Called(ctx, req)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*ListBindingsResponse), args.Error(1)
}
