// Package ccm provides access to the Akamai Cloud Certificate Manager API.
package ccm

import "context"

// CCM defines the interface for Akamai Cloud Certificate Manager operations.
type (
	CCM interface {
		// CreateCertificate creates a new certificate with the given parameters.
		CreateCertificate(ctx context.Context, params CreateCertificateRequest) (*CreateCertificateResponse, error)

		// GetCertificate retrieves a certificate by its ID.
		GetCertificate(ctx context.Context, params GetCertificateRequest) (*GetCertificateResponse, error)

		// RenameCertificate renames an existing certificate.
		RenameCertificate(ctx context.Context, params RenameCertificateRequest) (*RenameCertificateResponse, error)

		// UploadSignedCertificate uploads a signed certificate and optional trust chain.
		UploadSignedCertificate(ctx context.Context, params UploadSignedCertificateRequest) (*UploadSignedCertificateResponse, error)

		// UpdateCertificate updates an existing certificate with new data.
		UpdateCertificate(ctx context.Context, params UpdateCertificateRequest) (*UpdateCertificateResponse, error)

		// DeleteCertificate deletes a certificate by its ID.
		DeleteCertificate(ctx context.Context, params DeleteCertificateRequest) error

		// GetCertificateBindings retrieves bindings for a specific certificate.
		GetCertificateBindings(ctx context.Context, params GetCertificateBindingsRequest) (*GetCertificateBindingsResponse, error)

		// ListCertificates lists certificates matching the given parameters.
		ListCertificates(ctx context.Context, params ListCertificatesRequest) (*ListCertificatesResponse, error)

		// ListBindings lists certificate bindings matching the given parameters.
		ListBindings(ctx context.Context, params ListBindingsRequest) (*ListBindingsResponse, error)
	}
)
