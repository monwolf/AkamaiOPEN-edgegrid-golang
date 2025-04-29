package mtlstruststore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v10/pkg/edgegriderr"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v10/pkg/session"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// CreateCASetVersionRequest is used to request the creation of CA set version.
	CreateCASetVersionRequest struct {
		// CASetID is a unique identifier representing the CA set.
		CASetID int64
		Body    CreateCASetVersionRequestBody
	}

	// CreateCASetVersionRequestBody represents the body of a CreateCASetVersionRequest.
	CreateCASetVersionRequestBody struct {
		// AllowInsecureSHA1 permits SHA-1 signed certificates if set to true. Defaults to false.
		AllowInsecureSHA1 bool `json:"allowInsecureSha1"`

		// Description is an optional description for the can set.
		Description string `json:"description"`

		// Certificates is a list of valid root or intermediate certificates. At least one is required.
		Certificates []Certificate `json:"certificates"`
	}

	// CloneCASetVersionRequest represents a request to clone a specific version of a CA Set.
	CloneCASetVersionRequest struct {
		// CASetID is a unique identifier representing the CA set.
		CASetID int64 `json:"caSetId"`

		// Version is the version number within the CA Set, starting at 1 and incrementing sequentially.
		Version int64 `json:"version"`
	}

	// ListCASetVersionsRequest represents a request to retrieve a list of CA sets.
	ListCASetVersionsRequest struct {
		// CASetID is a unique identifier representing the CA set.
		CASetID int64

		// IncludeCertificates includes certificates in the response if true. Defaults to false. Optional.
		IncludeCertificates *bool

		// ActiveVersionsOnly includes only staging or production active versions if true. Defaults to false. Optional.
		ActiveVersionsOnly *bool
	}

	// GetCASetVersionRequest represents a request to retrieve details of a specific CA Set version.
	GetCASetVersionRequest struct {
		// CASetID is a unique identifier representing the CA set.
		CASetID int64 `json:"caSetId"`

		// Version is the version number within the CA Set, starting at 1 and incrementing sequentially.
		Version int64 `json:"version"`
	}

	// UpdateCASetVersionRequest is used to request the update of an existing CA Set version.
	UpdateCASetVersionRequest struct {
		// CASetID is a unique identifier representing the CA set.
		CASetID int64
		Body    UpdateCASetVersionRequestBody
	}

	//UpdateCASetVersionRequestBody represent the body of a UpdateCASetVersionRequest.
	UpdateCASetVersionRequestBody struct {
		// Version is the version number within the CA Set, starting at 1 and incrementing sequentially.
		Version int64 `json:"version"`

		// CASetName is a descriptive name for the set.
		CASetName string `json:"caSetName"`

		// VersionLink is the hypermedia link to the version resource.
		VersionLink string `json:"versionLink"`

		// Description is an optional description for the ca set.
		Description string `json:"description"`

		// AllowInsecureSHA1 indicates whether SHA-1 certificates are allowed.
		AllowInsecureSHA1 bool `json:"allowInsecureSha1"`

		// StagingStatus is "INACTIVE" initially, changes to "ACTIVE" when active on staging.
		StagingStatus VersionStatus `json:"stagingStatus"`

		// ProductionStatus is "INACTIVE" initially, changes to "ACTIVE" when active on production.
		ProductionStatus VersionStatus `json:"productionStatus"`

		// CreatedDate is the creation timestamp in ISO-8601 format.
		CreatedDate string `json:"createdDate"`

		// CreatedBy is the user who created the version.
		CreatedBy string `json:"createdBy"`

		// ModifiedDate is the last update timestamp in ISO-8601 format or null for new versions.
		ModifiedDate string `json:"modifiedDate"`

		// ModifiedBy is the user who last updated the version or null for new versions.
		ModifiedBy string `json:"modifiedBy"`

		// Certificates is a list of root or intermediate certificates in the version.
		Certificates []Certificate `json:"certificates"`
	}

	// GetCASetVersionCertificatesRequest represents a request to retrieve certificates details of a specific CA Set version.
	GetCASetVersionCertificatesRequest struct {
		// CASetID is a unique identifier representing the CA set.
		CASetID int64 `json:"caSetId"`

		// Version is the version number within the CA Set, starting at 1 and incrementing sequentially.
		Version int64 `json:"version"`

		// CertificateStatus filters by "EXPIRING", "EXPIRED", or both (comma-separated). Required if expiryThresholdInDays is set. Optional.
		CertificateStatus *CertificateStatus

		// ExpiryThresholdInDays filters certificates expiring within or expired in past N days. Defaults to 30 if not set. Optional.
		ExpiryThresholdInDays *int
	}

	// Certificate represents details of a certificate used in a CA Set version.
	Certificate struct {
		// Subject of the certificate.
		Subject string `json:"subject"`

		// Issuer of the certificate.
		Issuer string `json:"issuer"`

		// EndDate is the ISO-8601 date after which the certificate is not valid.
		EndDate string `json:"endDate"`

		// StartDate is the ISO-8601 date before which the certificate is not valid.
		StartDate string `json:"startDate"`

		// Fingerprint is the unique SHA-256 fingerprint of the certificate.
		Fingerprint string `json:"fingerprint"`

		// CertificatePEM is the PEM-encoded representation of the certificate. Required.
		CertificatePEM string `json:"certificatePem"`

		// SerialNumber is the unique serial number of the certificate.
		SerialNumber string `json:"serialNumber"`

		// SignatureAlgorithm used to sign the certificate, e.g., SHA256WITHRSA.
		SignatureAlgorithm string `json:"signatureAlgorithm"`

		// CreatedDate is the ISO-8601 date the certificate was created.
		CreatedDate string `json:"createdDate"`

		// CreatedBy is the user who created the certificate.
		CreatedBy string `json:"createdBy"`

		// Description is an optional description of the certificate.
		Description string `json:"description,omitempty"`
	}

	// CreateCASetVersionResponse represents the response returned after creating a new CA Set version.
	CreateCASetVersionResponse CASetVersion

	// CloneCASetVersionResponse represents the response returned after cloning an existing CA Set version.
	CloneCASetVersionResponse CASetVersion

	// GetCASetVersionResponse represents the response returned when fetching details of a specific CA Set version.
	GetCASetVersionResponse CASetVersion

	// UpdateCASetVersionResponse represents the response returned after updating an existing CA Set version.
	UpdateCASetVersionResponse CASetVersion

	// ListCASetVersionsResponse represents the response containing a list of CA Set versions.
	ListCASetVersionsResponse struct {
		Versions []CASetVersion `json:"versions"`
	}

	// GetCASetVersionCertificatesResponse represents the response with certificates details of a specific CA Set version.
	GetCASetVersionCertificatesResponse struct {
		// CASetID is a unique identifier representing the CA set.
		CASetID int64 `json:"caSetId"`

		// Version is the version number within the CA Set, starting at 1 and incrementing sequentially.
		Version int64 `json:"version"`

		// CASetName is a descriptive name for the set.
		CASetName string `json:"caSetName"`

		// Certificates is a list of valid root or intermediate certificates. At least one is required.
		Certificates []Certificate `json:"certificates"`
	}

	// CASetVersion represents a single version of a CA Set.
	CASetVersion struct {
		// CASetID is a unique identifier representing the CA set.
		CASetID int64 `json:"caSetId"`

		// Version is the version number within the CA Set, starting at 1 and incrementing sequentially.
		Version int64 `json:"version"`

		// CASetName is a descriptive name for the set.
		CASetName string `json:"caSetName"`

		// VersionLink is the hypermedia link to the version resource.
		VersionLink string `json:"versionLink"`

		// Description is an optional description for the version.
		Description string `json:"description"`

		// AllowInsecureSha1 indicates whether SHA-1 certificates are allowed.
		AllowInsecureSha1 bool `json:"allowInsecureSha1"`

		// StagingStatus is "INACTIVE" initially, changes to "ACTIVE" when active on staging.
		StagingStatus string `json:"stagingStatus"`

		// ProductionStatus is "INACTIVE" initially, changes to "ACTIVE" when active on production.
		ProductionStatus string `json:"productionStatus"`

		// CreatedDate is the creation timestamp in ISO-8601 format.
		CreatedDate string `json:"createdDate"`

		// CreatedBy is the user who created the version.
		CreatedBy string `json:"createdBy"`

		// ModifiedDate is the last update timestamp in ISO-8601 format or null for new versions.
		ModifiedDate string `json:"modifiedDate"`

		// ModifiedBy is the user who last updated the version or null for new versions.
		ModifiedBy string `json:"modifiedBy"`

		// Certificates is a list of valid root or intermediate certificates. At least one is required.
		Certificates []Certificate `json:"certificates"`
	}
)

var (
	// ErrCreateCASetVersion represents error when creating a CA set version fails.
	ErrCreateCASetVersion = errors.New("creating a CA set version")
	// ErrCloneCASetVersion represents error when cloning a CA set version fails.
	ErrCloneCASetVersion = errors.New("cloning a CA set version")
	// ErrGetCASetVersion represents error when fetching a CA set version fails.
	ErrGetCASetVersion = errors.New("fetching a CA set version")
	// ErrListCASetVersions represents error when fetching CA set versions fails.
	ErrListCASetVersions = errors.New("fetching CA set versions")
	// ErrGetCASetVersionCertificates represents error when fetching certificates for a CA set version fails.
	ErrGetCASetVersionCertificates = errors.New("fetching certificates for a CA set version")
	// ErrUpdateCASetVersion represents error when updating a CA set version fails.
	ErrUpdateCASetVersion = errors.New("updating a CA set version")
)

// CertificateStatus represents the state of certificates in a CA set version.
type CertificateStatus string

// VersionStatus represents the state of CA set version on the network.
type VersionStatus string

const (
	// ExpiringCert represents certificates that are about to expire within the provided threshold.
	ExpiringCert CertificateStatus = "EXPIRING"
	// ExpiredCert represents certificates that have already expired.
	ExpiredCert CertificateStatus = "EXPIRED"
	// ExpiredOrExpiringCert represents a status filter that matches certificates that are either expiring or expired.
	ExpiredOrExpiringCert CertificateStatus = "EXPIRING,EXPIRED"
	//ACTIVE Version is active on the network.
	ACTIVE VersionStatus = "ACTIVE"
	// INACTIVE Version is not active on the network.
	INACTIVE VersionStatus = "INACTIVE"
)

// Validate validates a CreateCASetVersionRequest.
func (v CreateCASetVersionRequest) Validate() error {
	errs := validation.Errors{
		"CASetID":      validation.Validate(v.CASetID, validation.Required),
		"Description":  validation.Validate(v.Body.Description, validation.Length(0, 255)),
		"Certificates": validation.Validate(v.Body.Certificates, validation.Required, validation.Each(certificateValidationRules())),
	}
	return edgegriderr.ParseValidationErrors(errs)
}

// Validate validates a UpdateCASetVersionRequest.
func (v UpdateCASetVersionRequest) Validate() error {
	errs := validation.Errors{
		"CASetID":      validation.Validate(v.CASetID, validation.Required),
		"Description":  validation.Validate(v.Body.Description, validation.Length(0, 255)),
		"Version":      validation.Validate(v.Body.Version, validation.Required),
		"Certificates": validation.Validate(v.Body.Certificates, validation.Required, validation.Each(certificateValidationRules())),
	}
	return edgegriderr.ParseValidationErrors(errs)
}

// certificateValidationRules defines validation rules for CA set certificates.
func certificateValidationRules() validation.Rule {
	return validation.By(func(val interface{}) error {
		cert, ok := val.(Certificate)
		if !ok {
			return validation.NewError("validation", "invalid certificate type")
		}
		return validation.Errors{
			"CertificatePEM": validation.Validate(cert.CertificatePEM, validation.Required),
			"Description":    validation.Validate(cert.Description, validation.Length(0, 255)),
		}.Filter()
	})
}

// Validate validates a CloneCASetVersionRequest.
func (v CloneCASetVersionRequest) Validate() error {
	return validation.Errors{
		"CaSetID": validation.Validate(v.CASetID, validation.Required),
		"Version": validation.Validate(v.Version, validation.Required),
	}.Filter()
}

// Validate validates a GetCASetVersionRequest.
func (v GetCASetVersionRequest) Validate() error {
	return validation.Errors{
		"CaSetID": validation.Validate(v.CASetID, validation.Required),
		"Version": validation.Validate(v.Version, validation.Required),
	}.Filter()
}

// Validate validates a GetCASetVersionCertificatesRequest.
func (v GetCASetVersionCertificatesRequest) Validate() error {
	return validation.Errors{
		"CaSetID": validation.Validate(v.CASetID, validation.Required),
		"Version": validation.Validate(v.Version, validation.Required),
		"CertificateStatus": validation.Validate(v.CertificateStatus,
			validation.When(
				v.CertificateStatus != nil,
				validation.In(ExpiringCert, ExpiredCert, ExpiredOrExpiringCert).Error(fmt.Sprintf(
					"value must be one of: '%s', '%s', or '%s'",
					ExpiringCert,
					ExpiredCert,
					ExpiredOrExpiringCert,
				)),
			),
		),
	}.Filter()
}

func (m *mtlstruststore) CreateCASetVersion(ctx context.Context, params CreateCASetVersionRequest) (*CreateCASetVersionResponse, error) {
	logger := m.Log(ctx)
	logger.Debug("CreateCASetVersion")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrCreateCASetVersion, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf(
		"/mtls-edge-truststore/v2/ca-sets/%d/versions",
		params.CASetID),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %s", ErrCreateCASetVersion, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrCreateCASetVersion, err)
	}

	var result CreateCASetVersionResponse
	resp, err := m.Exec(req, &result, params.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrCreateCASetVersion, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusCreated {
		return nil, m.Error(resp)
	}

	return &result, nil
}

func (m *mtlstruststore) CloneCASetVersion(ctx context.Context, params CloneCASetVersionRequest) (*CloneCASetVersionResponse, error) {
	logger := m.Log(ctx)
	logger.Debug("CloneCASetVersion")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrCloneCASetVersion, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf(
		"/mtls-edge-truststore/v2/ca-sets/%d/versions/%d/clone",
		params.CASetID,
		params.Version),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %s", ErrCloneCASetVersion, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrCloneCASetVersion, err)
	}

	var result CloneCASetVersionResponse
	resp, err := m.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrCloneCASetVersion, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusCreated {
		return nil, m.Error(resp)
	}

	return &result, nil
}

func (m *mtlstruststore) GetCASetVersion(ctx context.Context, params GetCASetVersionRequest) (*GetCASetVersionResponse, error) {
	logger := m.Log(ctx)
	logger.Debug("GetCASetVersion")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrGetCASetVersion, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf(
		"/mtls-edge-truststore/v2/ca-sets/%d/versions/%d",
		params.CASetID,
		params.Version),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %s", ErrGetCASetVersion, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrGetCASetVersion, err)
	}

	var result GetCASetVersionResponse
	resp, err := m.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrGetCASetVersion, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, m.Error(resp)
	}

	return &result, nil
}

func (m *mtlstruststore) ListCASetVersions(ctx context.Context, params ListCASetVersionsRequest) (*ListCASetVersionsResponse, error) {
	logger := m.Log(ctx)
	logger.Debug("ListCASetVersions")

	err := validation.ValidateStruct(&params,
		validation.Field(&params.CASetID, validation.Required),
	)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrListCASetVersions, ErrStructValidation, err)
	}

	query := url.Values{}
	if params.IncludeCertificates != nil {
		query.Set("includeCertificates", strconv.FormatBool(*params.IncludeCertificates))
	}

	if params.ActiveVersionsOnly != nil {
		query.Set("activeVersionsOnly", strconv.FormatBool(*params.ActiveVersionsOnly))
	}

	uri, err := url.Parse(fmt.Sprintf(
		"/mtls-edge-truststore/v2/ca-sets/%d/versions?%s",
		params.CASetID,
		query.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %s", ErrListCASetVersions, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrListCASetVersions, err)
	}

	var result ListCASetVersionsResponse
	resp, err := m.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrListCASetVersions, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, m.Error(resp)
	}

	return &result, nil
}

func (m *mtlstruststore) GetCASetVersionCertificates(ctx context.Context, params GetCASetVersionCertificatesRequest) (*GetCASetVersionCertificatesResponse, error) {
	logger := m.Log(ctx)
	logger.Debug("GetCASetVersionCertificates")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrGetCASetVersionCertificates, ErrStructValidation, err)
	}

	if params.ExpiryThresholdInDays != nil && params.CertificateStatus == nil {
		return nil, fmt.Errorf("certificateStatus must be provided when expiryThresholdInDays is set")
	}

	uri, err := url.Parse(fmt.Sprintf(
		"/mtls-edge-truststore/v2/ca-sets/%d/versions/%d/certificates",
		params.CASetID,
		params.Version))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %s", ErrGetCASetVersionCertificates, err)
	}

	query := url.Values{}
	if params.CertificateStatus != nil {
		query.Set("certificateStatus", string(*params.CertificateStatus))
	}

	if params.ExpiryThresholdInDays != nil {
		query.Set("expiryThresholdInDays", strconv.Itoa(*params.ExpiryThresholdInDays))
	}

	uri.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrGetCASetVersionCertificates, err)
	}

	var result GetCASetVersionCertificatesResponse
	resp, err := m.Exec(req, &result, params)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrGetCASetVersionCertificates, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, m.Error(resp)
	}

	return &result, nil
}

func (m *mtlstruststore) UpdateCASetVersion(ctx context.Context, params UpdateCASetVersionRequest) (*UpdateCASetVersionResponse, error) {
	logger := m.Log(ctx)
	logger.Debug("UpdateCASetVersion")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrUpdateCASetVersion, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf(
		"/mtls-edge-truststore/v2/ca-sets/%d/versions/%d",
		params.CASetID,
		params.Body.Version),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %s", ErrUpdateCASetVersion, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrUpdateCASetVersion, err)
	}

	var result UpdateCASetVersionResponse

	resp, err := m.Exec(req, &result, params.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrUpdateCASetVersion, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, m.Error(resp)
	}

	return &result, nil
}
