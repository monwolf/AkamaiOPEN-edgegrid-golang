// Package ccm provides access to the Akamai Cloud Certificate Manager API.
package ccm

import (
	"context"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
)

// CCM defines the interface for Akamai Cloud Certificate Manager operations.
type (
	CCM interface {
		// CreateCertificate creates a third party certificate.
		//
		// See: TBD
		CreateCertificate(ctx context.Context, params CreateCertificateRequest) (*CreateCertificateResponse, error)

		// GetCertificate retrieves a single certificate by its certificateId.
		// This includes details such as the certificate name, SANs, subject, certificate signing request, and, if uploaded, the signed certificate and trust chain.
		//
		// See: TBD
		GetCertificate(ctx context.Context, params GetCertificateRequest) (*GetCertificateResponse, error)

		// PatchCertificate update the certificate.
		// It allows to rename or reset the name of certificate or upload of signed certificate and optional trust chain or both in one request.
		//
		// See: TBD
		PatchCertificate(ctx context.Context, params PatchCertificateRequest) (*PatchCertificateResponse, error)

		//// UpdateCertificate update a certificate. This includes renaming the certificate, uploading a signed certificate, and an optional trust chain.
		//// You can perform one or both of these actions in a single request.
		//UpdateCertificate(ctx context.Context, params UpdateCertificateRequest) (*UpdateCertificateResponse, error)
		//

		// DeleteCertificate deletes a certificate by its certificateId. Note that only certificates that are not ACTIVE can be deleted.
		//
		// See: TBD
		DeleteCertificate(ctx context.Context, params DeleteCertificateRequest) error

		// ListCertificateBindings provides hostname bindings for the given certificate.
		//
		// See: TBD
		ListCertificateBindings(ctx context.Context, params ListCertificateBindingsRequest) (*ListCertificateBindingsResponse, error)

		// ListCertificates lists all certificates that are accessible for the requesting end user.
		//
		// See: TBD
		ListCertificates(ctx context.Context, params ListCertificatesRequest) (*ListCertificatesResponse, error)

		// ListBindings provides hostname bindings for user accessible certificates, optionally filtered by contract, group, domain, certificate type, and expiration days.
		//
		// See: TBD
		ListBindings(ctx context.Context, params ListBindingsRequest) (*ListBindingsResponse, error)
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
