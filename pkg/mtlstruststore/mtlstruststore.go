// Package mtlstruststore provides access to the Akamai mTLS Truststore v2 API.
package mtlstruststore

import (
	"context"
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
		// CreateCASet creates a new CA set.
		//
		// See: https://techdocs.akamai.com/mtls-edge-truststore/reference/post-ca-set
		CreateCASet(ctx context.Context, params CreateCASetRequest) (*CreateCASetResponse, error)

		// GetCASet returns details for a specific CA set.
		//
		// See: https://techdocs.akamai.com/mtls-edge-truststore/reference/get-ca-set
		GetCASet(ctx context.Context, params GetCASetRequest) (*GetCASetResponse, error)

		// ListCASets returns detailed information about CA sets available to the current user account.
		//
		// https://techdocs.akamai.com/mtls-edge-truststore/reference/get-ca-sets
		ListCASets(ctx context.Context, params ListCASetsRequest) (*ListCASetsResponse, error)

		// DeleteCASet deletes a CA set.
		//
		// See: https://techdocs.akamai.com/mtls-edge-truststore/reference/delete-ca-set
		DeleteCASet(ctx context.Context, params DeleteCASetRequest) error
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
