//revive:disable:exported

package domainownership

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

var _ DomainOwnership = &Mock{}

func (p *Mock) AddDomains(ctx context.Context, params AddDomainsRequest) (*AddDomainsResponse, error) {
	args := p.Called(ctx, params)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*AddDomainsResponse), args.Error(1)
}

func (p *Mock) DeleteDomain(ctx context.Context, params DeleteDomainRequest) error {
	args := p.Called(ctx, params)
	return args.Error(0)
}

func (p *Mock) DeleteDomains(ctx context.Context, params DeleteDomainsRequest) error {
	args := p.Called(ctx, params)
	return args.Error(0)
}

func (p *Mock) ValidateDomains(ctx context.Context, params ValidateDomainsRequest) (*ValidateDomainsResponse, error) {
	args := p.Called(ctx, params)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*ValidateDomainsResponse), args.Error(1)
}

func (p *Mock) InvalidateDomain(ctx context.Context, params InvalidateDomainRequest) (*InvalidateDomainResponse, error) {
	args := p.Called(ctx, params)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*InvalidateDomainResponse), args.Error(1)
}

func (p *Mock) InvalidateDomains(ctx context.Context, params InvalidateDomainsRequest) (*InvalidateDomainsResponse, error) {
	args := p.Called(ctx, params)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*InvalidateDomainsResponse), args.Error(1)
}

func (p *Mock) ListDomains(ctx context.Context, params ListDomainsRequest) (*ListDomainsResponse, error) {
	args := p.Called(ctx, params)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*ListDomainsResponse), args.Error(1)
}

func (p *Mock) GetDomain(ctx context.Context, params GetDomainRequest) (*GetDomainResponse, error) {
	args := p.Called(ctx, params)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*GetDomainResponse), args.Error(1)
}

func (p *Mock) SearchDomains(ctx context.Context, params SearchDomainsRequest) (*SearchDomainsResponse, error) {
	args := p.Called(ctx, params)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*SearchDomainsResponse), args.Error(1)
}
