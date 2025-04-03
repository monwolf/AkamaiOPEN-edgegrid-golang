// Package mtlstruststore provides access to the Akamai mTLS Truststore API.
package mtlstruststore

import (
	"errors"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v10/pkg/session"
)

var (
	// ErrStructValidation is returned when given struct validation failed.
	ErrStructValidation = errors.New("struct validation")
)

type (
	// MTLSTruststore is the API interface for mTLS Truststore.
	MTLSTruststore interface {
	}

	mtlstruststore struct {
		session.Session
	}

	// Option defines an MTLS Truststore option.
	Option func(*mtlstruststore)
)

// Client returns a new mtlstruststore Client instance with the specified controller.
func Client(sess session.Session, opts ...Option) MTLSTruststore {
	c := &mtlstruststore{
		Session: sess,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}
