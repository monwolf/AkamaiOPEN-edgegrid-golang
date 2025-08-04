//revive:disable:exported

package domainvalidation

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

var _ DomainValidation = &Mock{}

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
