// Package mtlstruststore provides access to the Akamai mTLS Truststore v2 API.
package mtlstruststore

import (
	"context"
	"errors"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
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
		// See: TBA
		CreateCASet(ctx context.Context, params CreateCASetRequest) (*CreateCASetResponse, error)

		// GetCASet returns details for a specific CA set.
		//
		// See: TBA
		GetCASet(ctx context.Context, params GetCASetRequest) (*GetCASetResponse, error)

		// ListCASets returns detailed information about CA sets available to the current user account.
		//
		// TBA
		ListCASets(ctx context.Context, params ListCASetsRequest) (*ListCASetsResponse, error)

		// DeleteCASet deletes a CA set.
		//
		// See: TBA
		DeleteCASet(ctx context.Context, params DeleteCASetRequest) error

		// CreateCASetVersion creates a new CA set version.
		//
		// See: TBA
		CreateCASetVersion(ctx context.Context, params CreateCASetVersionRequest) (*CreateCASetVersionResponse, error)

		// CloneCASetVersion creates a clone of an existing CA set version.
		//
		// See: TBA
		CloneCASetVersion(ctx context.Context, params CloneCASetVersionRequest) (*CloneCASetVersionResponse, error)

		// ListCASetVersions lists all the available CA sets created under the account.
		//
		// See: TBA
		ListCASetVersions(ctx context.Context, params ListCASetVersionsRequest) (*ListCASetVersionsResponse, error)

		// GetCASetVersion returns details of a CA sets version.
		//
		// See: TBA
		GetCASetVersion(ctx context.Context, params GetCASetVersionRequest) (*GetCASetVersionResponse, error)

		// UpdateCASetVersion updates a CA sets version.
		//
		// See: TBA
		UpdateCASetVersion(ctx context.Context, params UpdateCASetVersionRequest) (*UpdateCASetVersionResponse, error)

		// GetCASetVersionCertificates returns certificates details of a CA sets version.
		//
		// See: TBA
		GetCASetVersionCertificates(ctx context.Context, params GetCASetVersionCertificatesRequest) (*GetCASetVersionCertificatesResponse, error)

		// ActivateCASetVersion activates a CA set version.
		//
		// See: TBA
		ActivateCASetVersion(ctx context.Context, params ActivateCASetVersionRequest) (*ActivateCASetVersionResponse, error)

		// DeactivateCASetVersion deactivates a CA set version.
		//
		// See: TBA
		DeactivateCASetVersion(ctx context.Context, params DeactivateCASetVersionRequest) (*DeactivateCASetVersionResponse, error)

		// GetCASetVersionActivation returns the status of a CA set version activation.
		//
		// See: TBA
		GetCASetVersionActivation(ctx context.Context, params GetCASetVersionActivationRequest) (*GetCASetVersionActivationResponse, error)

		// ListCASetActivations returns a list of CA set activations for a given CA set.
		//
		// See: TBA
		ListCASetActivations(ctx context.Context, params ListCASetActivationsRequest) (*ListCASetActivationsResponse, error)

		// ListCASetVersionActivations returns a list of CA set version activations.
		//
		// See: TBA
		ListCASetVersionActivations(ctx context.Context, params ListCASetVersionActivationsRequest) (*ListCASetVersionActivationsResponse, error)

		// ListCASetAssociations provides of CA Set associations to a Certificate/Slot in CPS (in Commercial) or to a Hostname in Property Manager (in Defense Edge).
		//
		// See: TBA
		ListCASetAssociations(ctx context.Context, params ListCASetAssociationsRequest) (*ListCASetAssociationsResponse, error)

		// CloneCASet clones a CA set with provided name and description.
		//
		// See: TBA
		CloneCASet(ctx context.Context, params CloneCASetRequest) (*CloneCASetResponse, error)

		// GetCASetDeletionStatus fetches the status of delete operation on both the networks.
		//
		// See: TBA
		GetCASetDeletionStatus(ctx context.Context, params GetCASetDeletionStatusRequest) (*GetCASetDeletionStatusResponse, error)

		// ListCASetActivities returns the complete list of activities on a CA set.
		//
		// See: TBA
		ListCASetActivities(ctx context.Context, params ListCASetActivitiesRequest) (*ListCASetActivitiesResponse, error)

		// ValidateCertificates validates provided certificates if they are correct.
		//
		// See: TBA
		ValidateCertificates(ctx context.Context, params ValidateCertificatesRequest) (*ValidateCertificatesResponse, error)
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
