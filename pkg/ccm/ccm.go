// Package ccm provides access to the Akamai Cloud Certificate Manager API.
package ccm

import (
	"context"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
)

// CCM defines the interface for Akamai Cloud Certificate Manager operations.
type (
	CCM interface {
		//// CreateCertificate creates a new certificate with the given parameters.
		//CreateCertificate(ctx context.Context, params CreateCertificateRequest) (*CreateCertificateResponse, error)
		//
		//// GetCertificate retrieves a certificate by its ID.
		//GetCertificate(ctx context.Context, params GetCertificateRequest) (*GetCertificateResponse, error)
		//

		// PatchCertificate uploads a signed certificate and optional trust chain or renames an existing certificate.
		// In order to reset the name to a default value, provide an empty string as CertificateName.
		//
		// See: TBD
		PatchCertificate(ctx context.Context, params PatchCertificateRequest) (*PatchCertificateResponse, error)

		//// UpdateCertificate updates an existing certificate with new data.
		//UpdateCertificate(ctx context.Context, params UpdateCertificateRequest) (*UpdateCertificateResponse, error)
		//
		//// DeleteCertificate deletes a certificate by its ID.
		//DeleteCertificate(ctx context.Context, params DeleteCertificateRequest) error
		//
		//// GetCertificateBindings retrieves bindings for a specific certificate.
		//GetCertificateBindings(ctx context.Context, params GetCertificateBindingsRequest) (*GetCertificateBindingsResponse, error)
		//

		// ListCertificates lists all certificates that are accessible for the requesting end user.
		//
		// See: TBD
		ListCertificates(ctx context.Context, params ListCertificatesRequest) (*ListCertificatesResponse, error)

		//// ListBindings lists certificate bindings matching the given parameters.
		//ListBindings(ctx context.Context, params ListBindingsRequest) (*ListBindingsResponse, error)
	}

	ccm struct {
		session.Session
	}

	// Option is a function that configures the CCM.
	Option func(*ccm)
)

// Client creates a new CCM client.
func Client(sess session.Session, opts ...Option) CCM {
	c := &ccm{
		Session: sess,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}
