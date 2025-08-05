package domainvalidation

import (
	"errors"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/session"
)

var (
	// ErrStructValidation is returned when given struct validation failed.
	ErrStructValidation = errors.New("struct validation")
)

type (
	// DomainValidation is the interface for the Domain Validation API.
	DomainValidation interface{}

	domainvalidation struct {
		session.Session
	}

	// Option is a function that configures the Domain Validation.
	Option func(*domainvalidation)
)

// Client creates a new DomainValidation client.
func Client(sess session.Session, opts ...Option) DomainValidation {
	c := &domainvalidation{
		Session: sess,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}
