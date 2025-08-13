package ccm

import "time"

type (
	// CreateCertificateRequest represents the parameters for creating a new certificate.
	CreateCertificateRequest struct {
		ContractID string
		GroupID    string
		Body       CertificateRequest
	}

	// CreateCertificateResponse contains the response for a certificate creation request.
	CreateCertificateResponse struct {
		Certificate
		Quota
	}

	// GetCertificateRequest represents the parameters for retrieving a certificate.
	GetCertificateRequest struct {
		CertificateID string
	}

	// GetCertificateResponse contains the response for retrieving a certificate.
	GetCertificateResponse = Certificate

	// RenameCertificateRequest represents the parameters for renaming a certificate.
	RenameCertificateRequest struct {
		CertificateID   string
		CertificateName *string
	}

	// RenameCertificateResponse contains the response for renaming a certificate.
	RenameCertificateResponse = Certificate

	// UploadSignedCertificateRequest represents the parameters for uploading a signed certificate.
	UploadSignedCertificateRequest struct {
		CertificateID         string
		SignedCertificatePEM  string
		TrustChainPEM         *string
		AcknowledgeWarnings   bool
		UpdateCertificateData bool
	}

	// UploadSignedCertificateResponse contains the response for uploading a signed certificate.
	UploadSignedCertificateResponse = Certificate

	// UpdateCertificateRequest represents the parameters for updating a certificate.
	UpdateCertificateRequest = Certificate

	// UpdateCertificateResponse contains the response for updating a certificate.
	UpdateCertificateResponse = Certificate

	// DeleteCertificateRequest represents the parameters for deleting a certificate.
	DeleteCertificateRequest struct {
		CertificateID string
	}

	// GetCertificateBindingsRequest represents the parameters for retrieving certificate bindings.
	GetCertificateBindingsRequest struct {
		CertificateID string
	}

	// GetCertificateBindingsResponse contains the bindings for a certificate.
	GetCertificateBindingsResponse struct {
		Bindings []CertificateBinding `json:"bindings"`
		Links    Links                `json:"links"`
	}

	// ListCertificatesRequest represents the parameters for listing certificates.
	ListCertificatesRequest struct {
		CertificateName   string
		CertificateStatus string
		CertificateType   string
		ContractID        string
		Domain            string
		ExpiringInDays    *int64
		GroupID           int64
		Issuer            string
		KeyType           string

		IncludeCertificateMaterials bool
		PageSize                    int64
		Page                        int64
		Sort                        string
	}

	// ListCertificatesResponse contains a list of certificates and metadata.
	ListCertificatesResponse struct {
		Certificates []Certificate `json:"certificates"`
		Links        Links         `json:"links"`
		Metadata     ListMetadata  `json:"metadata"`
	}

	// ListBindingsRequest represents the parameters for listing certificate bindings.
	ListBindingsRequest struct {
		CertificateType string
		ContractID      string
		Domain          string
		ExpiringInDays  *int64
		GroupID         int64
		Network         string

		PageSize int64
		Page     int64
		Sort     string
	}

	// ListBindingsResponse contains a list of certificate bindings.
	ListBindingsResponse struct {
		Bindings []CertificateBinding `json:"bindings"`
		Links    Links                `json:"links"`
	}

	// CertificateRequest contains the details for requesting a certificate.
	CertificateRequest struct {
		CertificateName *string  `json:"certificateName,omitempty"`
		CertificateType *string  `json:"certificateType,omitempty"`
		KeyType         string   `json:"keyType"`
		KeySize         int64    `json:"keySize"`
		SecureNetwork   string   `json:"secureNetwork"`
		SANs            []string `json:"sans"`
		Subject         *Subject `json:"subject,omitempty"`
	}

	// Certificate represents a certificate and its metadata.
	Certificate struct {
		AccountID                           string     `json:"accountId,omitempty"`
		CertificateID                       string     `json:"certificateId,omitempty"`
		CertificateName                     string     `json:"certificateName"`
		CertificateStatus                   string     `json:"certificateStatus,omitempty"`
		CertificateType                     string     `json:"certificateType,omitempty"`
		ContractID                          string     `json:"contractId,omitempty"`
		CreatedBy                           string     `json:"createdBy,omitempty"`
		CreatedDate                         time.Time  `json:"createdDate,omitempty"`
		CsrExpirationDate                   time.Time  `json:"csrExpirationDate,omitempty"`
		CsrPEM                              string     `json:"csrPem,omitempty"`
		KeySize                             int64      `json:"keySize,omitempty"`
		KeyType                             string     `json:"keyType,omitempty"`
		ModifiedBy                          string     `json:"modifiedBy,omitempty"`
		ModifiedDate                        time.Time  `json:"modifiedDate,omitempty"`
		SANs                                []string   `json:"sans,omitempty"`
		SecureNetwork                       string     `json:"secureNetwork,omitempty"`
		SignedCertificateIssuer             *string    `json:"signedCertificateIssuer,omitempty"`
		SignedCertificateNotValidAfterDate  *time.Time `json:"signedCertificateNotValidAfterDate,omitempty"`
		SignedCertificateNotValidBeforeDate *time.Time `json:"signedCertificateNotValidBeforeDate,omitempty"`
		SignedCertificatePEM                *string    `json:"signedCertificatePem"`
		SignedCertificateSHA256Fingerprint  *string    `json:"signedCertificateSHA256Fingerprint,omitempty"`
		SignedCertificateSerialNumber       *string    `json:"signedCertificateSerialNumber,omitempty"`
		Subject                             *Subject   `json:"subject,omitempty"`
		TrustChainPEM                       *string    `json:"trustChainPem"`
	}

	// Subject contains the subject details for a certificate.
	Subject struct {
		CommonName   *string `json:"commonName,omitempty"`
		Organization *string `json:"organization,omitempty"`
		Country      *string `json:"country,omitempty"`
		State        *string `json:"state,omitempty"`
		Locality     *string `json:"locality,omitempty"`
	}

	// CertificateBinding represents a binding between a certificate and a resource.
	CertificateBinding struct {
		ResourceType  string `json:"resourceType"`
		CertificateID string `json:"certificateId"`
		Hostname      string `json:"hostname"`
		Network       string `json:"network"`
		Active        bool   `json:"active"`
	}

	// Links contains pagination and navigation links.
	Links struct {
		Self     string  `json:"self"`
		Next     *string `json:"next"`
		Previous *string `json:"previous"`
	}

	// ListMetadata contains metadata for paginated lists.
	ListMetadata struct {
		TotalItems int64 `json:"totalItems"`
		TotalPages int64 `json:"totalPages"`
	}

	// ValidationResult contains validation results for certificate operations.
	ValidationResult struct {
		Errors   []ValidationDetail `json:"errors"`
		Notices  []ValidationDetail `json:"notices"`
		Warnings []ValidationDetail `json:"warnings"`
	}

	// ValidationDetail provides details about a validation message.
	ValidationDetail struct {
		Detail   string `json:"detail"`
		Instance string `json:"instance"`
		Message  string `json:"message"`
		Name     string `json:"name"`
		Status   string `json:"status"`
		Title    string `json:"title"`
		Type     string `json:"type"`
	}

	// Quota contains information about certificate quotas.
	Quota struct {
		CertificateLimitTotal     int64
		CertificateLimitRemaining int64
	}
)
