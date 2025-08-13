package domainownership

import (
	"context"
	"errors"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/session"
)

var (
	// ErrStructValidation is returned when given struct validation failed.
	ErrStructValidation = errors.New("struct validation")
)

type (
	// DomainOwnership is the interface for the Domain Ownership Manager that is used for Domain Validation.
	DomainOwnership interface {
		// ListDomains returns the list of available domains.
		//
		// See: https://techdocs.akamai.com/domain-validation/reference/get-domains
		ListDomains(ctx context.Context, params ListDomainsRequest) (*ListDomainsResponse, error)

		// GetDomain gets a specific domain.
		//
		// See: https://techdocs.akamai.com/domain-validation/reference/get-domain
		GetDomain(ctx context.Context, params GetDomainRequest) (*GetDomainResponse, error)

		// SearchDomains returns the status of specified domains. For any nonexistent domains, it returns the closest matching domain status.
		//
		// See: https://techdocs.akamai.com/domain-validation/reference/post-search-domains
		SearchDomains(ctx context.Context, params SearchDomainsRequest) (*SearchDomainsResponse, error)
	}

	domainownership struct {
		session.Session
	}

	// Option is a function that configures the Domain Ownership.
	Option func(*domainownership)
)

// Client creates a new DomainOwnership client.
func Client(sess session.Session, opts ...Option) DomainOwnership {
	c := &domainownership{
		Session: sess,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}
