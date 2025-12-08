package papi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// SortOrder represents SortOrder enum.
	SortOrder string

	// CertType represents CertType enum.
	CertType string

	// ListActivePropertyHostnamesRequest contains parameters required to list active property hostnames.
	ListActivePropertyHostnamesRequest struct {
		PropertyID        string
		Offset            int
		Limit             int
		Sort              SortOrder
		Hostname          string
		CnameTo           string
		Network           ActivationNetwork
		ContractID        string
		GroupID           string
		IncludeCertStatus bool
	}

	// GetActivePropertyHostnamesDiffRequest contains parameters required to list active property hostnames diff.
	GetActivePropertyHostnamesDiffRequest struct {
		// PropertyID is the unique identifier for the property.
		PropertyID string

		// Offset specifies the page of results you want to navigate to, starting from 0.
		Offset int

		// Limit specifies the number of hostnames objects to include on each page.
		Limit int

		// ContractID is the unique identifier for the contract.
		ContractID string

		// GroupID is the unique identifier for the group.
		GroupID string
	}

	// ListActivePropertyHostnamesResponse contains information about each of the active property hostnames.
	ListActivePropertyHostnamesResponse struct {
		AccountID     string                 `json:"accountId"`
		AvailableSort []SortOrder            `json:"availableSort"`
		ContractID    string                 `json:"contractId"`
		CurrentSort   SortOrder              `json:"currentSort"`
		DefaultSort   SortOrder              `json:"defaultSort"`
		GroupID       string                 `json:"groupId"`
		PropertyID    string                 `json:"propertyId"`
		PropertyName  string                 `json:"propertyName"`
		Hostnames     HostnamesResponseItems `json:"hostnames"`
	}

	// GetActivePropertyHostnamesDiffResponse contains information about each of the active property hostnames that differ in staging and production networks.
	GetActivePropertyHostnamesDiffResponse struct {
		// AccountID identifies the prevailing account under which you requested the data.
		AccountID string `json:"accountId"`

		// ContractID identifies the prevailing contract under which you requested the data.
		ContractID string `json:"contractId"`

		// GroupID identifies the prevailing group under which you requested the data.
		GroupID string `json:"groupId"`

		// PropertyID is the unique identifier for a property.
		PropertyID string `json:"propertyId"`

		// Hostnames is the active property hostnames that differ in staging and production networks.
		Hostnames HostnamesDiffResponseItems `json:"hostnames"`
	}

	// HostnamesResponseItems contains the response body for ListActivePropertyHostnamesResponse.
	HostnamesResponseItems struct {
		Items            []HostnameItem `json:"items"`
		CurrentItemCount int            `json:"currentItemCount"`
		NextLink         *string        `json:"nextLink"`
		PreviousLink     *string        `json:"previousLink"`
		TotalItems       int            `json:"totalItems"`
	}

	// HostnamesDiffResponseItems contains the response body for GetActivePropertyHostnamesDiffResponse.
	HostnamesDiffResponseItems struct {
		// Items are the details of the active property hostnames that differ in staging and production networks.
		Items []HostnameDiffItem `json:"items"`

		// CurrentItemCount is the total count of items present in the current response body for requested criteria.
		CurrentItemCount int `json:"currentItemCount"`

		// NextLink is the link to next set of response items for paginated response.
		NextLink *string `json:"nextLink"`

		// PreviousLink is the link to previous set of response items for paginated response.
		PreviousLink *string `json:"previousLink"`

		// TotalItems is the total count of items for requested criteria.
		TotalItems int `json:"totalItems"`
	}

	// HostnameItem contains information about each of the HostnamesResponseItems.
	HostnameItem struct {
		// CCMCertStatus is deployment status for the RSA and ECDSA certificates created with Cloud Certificate Manager (CCM).
		CCMCertStatus *CCMCertStatus `json:"ccmCertStatus,omitempty"`

		// CCMCertificates is certificate identifiers and links for the CCM-managed certificates.
		CCMCertificates *CCMCertificates `json:"ccmCertificates,omitempty"`

		// CertStatus with the `includeCertStatus` parameter set to `true`,
		// determines whether a hostname is capable of serving secure content over the staging or production network.
		CertStatus *CertStatusItem `json:"certStatus"`

		// CnameFrom is hostname that your end users see, indicated by the `Host` header in end user requests.
		CnameFrom string `json:"cnameFrom"`

		// CnameType has one supported `EDGE_HOSTNAME` value.
		CnameType HostnameCnameType `json:"cnameType"`

		// MTLS is mutual TLS configuration settings applicable to the Cloud Certificate Manager (CCM) hostnames.
		MTLS *MTLS `json:"mtls,omitempty"`

		// ProductionCertProvisioningType indicates the certificate's provisioning type.
		// Either `CPS_MANAGED` type for the certificates you create with the Certificate Provisioning System API (CPS),
		// `DEFAULT` for the Default Domain Validation (DV) certificates created automatically,
		// or `CCM` type for the third party certificates you create with the Cloud Certificate Manager.
		// Note that you can't specify the `DEFAULT` value if your property hostname uses the `akamaized.net` domain suffix.
		ProductionCertType CertType `json:"productionCertType"`

		// ProductionCnameTo is the edge hostname you point the property hostname to so that you can start serving traffic through Akamai servers.
		// This member corresponds to the edge hostname object's `edgeHostnameDomain` member.
		ProductionCnameTo string `json:"productionCnameTo"`

		// ProductionEdgeHostnameID identifies each edge hostname.
		ProductionEdgeHostnameID string `json:"productionEdgeHostnameId"`

		// StagingCertType indicates the certificate's provisioning type.
		// Either `CPS_MANAGED` type for the certificates you create with the Certificate Provisioning System API (CPS),
		// `DEFAULT` for the Default Domain Validation (DV) certificates created automatically,
		// or `CCM` type for the third party certificates you create with the Cloud Certificate Manager.
		// Note that you can't specify the `DEFAULT` value if your property hostname uses the `akamaized.net` domain suffix.
		StagingCertType CertType `json:"stagingCertType"`

		// StagingCnameTo is the edge hostname you point the property hostname to so that you can start serving traffic through Akamai servers.
		// This member corresponds to the edge hostname object's `edgeHostnameDomain` member.
		StagingCnameTo string `json:"StagingCnameTo"`

		// StagingEdgeHostnameID identifies each edge hostname.
		StagingEdgeHostnameID string `json:"stagingEdgeHostnameId"`

		// TLSConfiguration is optional TLS configuration settings applicable to the Cloud Certificate Manager (CCM) hostnames.
		TLSConfiguration *TLSConfiguration `json:"tlsConfiguration,omitempty"`
	}

	// HostnameDiffItem contains information about each of the HostnamesDiffResponseItems.
	HostnameDiffItem struct {
		// CnameFrom is the hostname that your end users see, indicated by the Host header in end user requests.
		CnameFrom string `json:"cnameFrom"`

		// ProductionCertProvisioningType indicates the type of the certificate used in the property hostname.
		ProductionCertProvisioningType CertType `json:"productionCertProvisioningType"`

		// ProductionCnameTo is the edge hostname you point the property hostname to so that you can start serving traffic through Akamai servers.
		ProductionCnameTo string `json:"productionCnameTo"`

		// ProductionCnameType indicates the type of CNAME you used in the production network, either `EDGE_HOSTNAME` or `CUSTOM`.
		ProductionCnameType HostnameCnameType `json:"productionCnameType"`

		// ProductionEdgeHostnameID identifies the edge hostname you mapped your traffic to on the production network.
		ProductionEdgeHostnameID string `json:"productionEdgeHostnameId"`

		// StagingCertProvisioningType indicates the type of the certificate used in the property hostname.
		StagingCertProvisioningType CertType `json:"stagingCertProvisioningType"`

		// StagingCnameTo is the edge hostname you point the property hostname to so that you can start serving traffic through Akamai servers.
		StagingCnameTo string `json:"stagingCnameTo"`

		// StagingCnameType indicates the type of CNAME you used in the staging network, either `EDGE_HOSTNAME` or `CUSTOM`.
		StagingCnameType HostnameCnameType `json:"stagingCnameType"`

		// StagingEdgeHostnameID identifies the edge hostname you mapped your traffic to on the production network.
		StagingEdgeHostnameID string `json:"stagingEdgeHostnameId"`
	}
)

const (
	// SortAscending represents ascending sorting by hostname.
	SortAscending SortOrder = "hostname:a"
	// SortDescending represents descending sorting by hostname.
	SortDescending SortOrder = "hostname:d"
	// CertTypeCPSManaged indicates that the certificate is provisioned using the Certificate Provisioning System (CPS).
	CertTypeCPSManaged CertType = "CPS_MANAGED"
	// CertTypeDefault indicates that the certificate is a Default Domain Validation (DV) certificate.
	CertTypeDefault CertType = "DEFAULT"
	// CertTypeCCM indicates that the certificate is a Cloud Controller Manager (CCM) certificate.
	CertTypeCCM CertType = "CCM"
	// maxHostnamesPerPage indicates the maximum possible value for 'limit' parameter for Get and List active property hostnames.
	maxHostnamesPerPage int = 999
)

var (
	// ErrListActivePropertyHostnames represents error when fetching active property hostnames fails.
	ErrListActivePropertyHostnames = errors.New("fetching active property hostnames")

	// ErrGetActivePropertyHostnamesDiff represents error when fetching active property hostnames diff fails.
	ErrGetActivePropertyHostnamesDiff = errors.New("fetching active property hostnames diff")
)

// Validate validates SortOrder.
func (o SortOrder) Validate() validation.InRule {
	return validation.In(SortAscending, SortDescending).
		Error(fmt.Sprintf("value '%s' is invalid. Must be one of: '%s' or '%s'",
			o, SortAscending, SortDescending))
}

// Validate validates CertType.
func (t CertType) Validate() validation.InRule {
	return validation.In(CertTypeCPSManaged, CertTypeDefault, CertTypeCCM).
		Error(fmt.Sprintf("value '%s' is invalid. Must be one of: '%s', '%s' or '%s'",
			t, CertTypeCPSManaged, CertTypeDefault, CertTypeCCM))
}

// Validate validates ListActivePropertyHostnamesRequest.
func (r ListActivePropertyHostnamesRequest) Validate() error {
	return validation.Errors{
		"PropertyID": validation.Validate(r.PropertyID, validation.Required),
		"Network":    validation.Validate(r.Network, r.Network.Validate()),
		"Sort":       validation.Validate(r.Sort, r.Sort.Validate()),
		"Offset":     validation.Validate(r.Offset, validation.Min(0)),
		"Limit":      validation.Validate(r.Limit, validation.Min(1), validation.Max(maxHostnamesPerPage)),
	}.Filter()
}

// Validate validates GetActivePropertyHostnamesDiffRequest.
func (r GetActivePropertyHostnamesDiffRequest) Validate() error {
	return validation.Errors{
		"PropertyID": validation.Validate(r.PropertyID, validation.Required),
		"Offset":     validation.Validate(r.Offset, validation.Min(0)),
		"Limit":      validation.Validate(r.Limit, validation.Min(1), validation.Max(maxHostnamesPerPage)),
	}.Filter()
}

func (p *papi) ListActivePropertyHostnames(ctx context.Context, params ListActivePropertyHostnamesRequest) (*ListActivePropertyHostnamesResponse, error) {
	logger := p.Log(ctx)
	logger.Debug("ListActivePropertyHostnames")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrListActivePropertyHostnames, ErrStructValidation, err)
	}

	baseURL := fmt.Sprintf("/papi/v1/properties/%s/hostnames", params.PropertyID)

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse base URL: %s", ErrListActivePropertyHostnames, err)
	}

	query := parsedURL.Query()
	if params.ContractID != "" {
		query.Set("contractId", params.ContractID)
	}
	if params.GroupID != "" {
		query.Set("groupId", params.GroupID)
	}
	if params.Sort != "" {
		query.Set("sort", string(params.Sort))
	}
	if params.Hostname != "" {
		query.Set("hostname", params.Hostname)
	}
	if params.CnameTo != "" {
		query.Set("cnameTo", params.CnameTo)
	}
	if params.Network != "" {
		query.Set("network", string(params.Network))
	}
	if params.IncludeCertStatus {
		query.Set("includeCertStatus", fmt.Sprintf("%t", params.IncludeCertStatus))
	}
	if params.Limit != 0 {
		query.Set("limit", fmt.Sprintf("%d", params.Limit))
	}
	if params.Offset != 0 {
		query.Set("offset", fmt.Sprintf("%d", params.Offset))
	}

	parsedURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrListActivePropertyHostnames, err)
	}

	var hostnames ListActivePropertyHostnamesResponse
	resp, err := p.Exec(req, &hostnames)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrListActivePropertyHostnames, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %w", ErrListActivePropertyHostnames, p.Error(resp))
	}

	return &hostnames, nil
}

func (p *papi) GetActivePropertyHostnamesDiff(ctx context.Context, params GetActivePropertyHostnamesDiffRequest) (*GetActivePropertyHostnamesDiffResponse, error) {
	logger := p.Log(ctx)
	logger.Debug("GetActivePropertyHostnamesDiff")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrGetActivePropertyHostnamesDiff, ErrStructValidation, err)
	}

	baseURL := fmt.Sprintf("/papi/v1/properties/%s/hostnames/diff", params.PropertyID)

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse base URL: %s", ErrGetActivePropertyHostnamesDiff, err)
	}

	query := parsedURL.Query()
	if params.ContractID != "" {
		query.Set("contractId", params.ContractID)
	}
	if params.GroupID != "" {
		query.Set("groupId", params.GroupID)
	}
	if params.Limit != 0 {
		query.Set("limit", fmt.Sprintf("%d", params.Limit))
	}
	if params.Offset != 0 {
		query.Set("offset", fmt.Sprintf("%d", params.Offset))
	}

	parsedURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrGetActivePropertyHostnamesDiff, err)
	}

	var hostnamesDiff GetActivePropertyHostnamesDiffResponse
	resp, err := p.Exec(req, &hostnamesDiff)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrGetActivePropertyHostnamesDiff, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %w", ErrGetActivePropertyHostnamesDiff, p.Error(resp))
	}

	return &hostnamesDiff, nil
}
