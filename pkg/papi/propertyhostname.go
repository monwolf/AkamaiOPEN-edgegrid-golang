package papi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/edgegriderr"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// GetPropertyVersionHostnamesRequest contains parameters required to list property version hostnames
	GetPropertyVersionHostnamesRequest struct {
		PropertyID        string
		PropertyVersion   int
		ContractID        string
		GroupID           string
		ValidateHostnames bool
		IncludeCertStatus bool
	}

	// GetPropertyVersionHostnamesResponse contains all property version hostnames associated to the given parameters
	GetPropertyVersionHostnamesResponse struct {
		AccountID       string                `json:"accountId"`
		ContractID      string                `json:"contractId"`
		GroupID         string                `json:"groupId"`
		PropertyID      string                `json:"propertyId"`
		PropertyVersion int                   `json:"propertyVersion"`
		Etag            string                `json:"etag"`
		Hostnames       HostnameResponseItems `json:"hostnames"`
	}

	// HostnameResponseItems contains the response body for GetPropertyVersionHostnamesResponse
	HostnameResponseItems struct {
		Items []Hostname `json:"items"`
	}

	// Hostname contains information about each of the HostnameResponseItems
	Hostname struct {
		CnameType            HostnameCnameType `json:"cnameType"`
		EdgeHostnameID       string            `json:"edgeHostnameId,omitempty"`
		CnameFrom            string            `json:"cnameFrom"`
		CnameTo              string            `json:"cnameTo,omitempty"`
		CertProvisioningType string            `json:"certProvisioningType"`
		CertStatus           CertStatusItem    `json:"certStatus,omitempty"`
	}

	// CertStatusItem contains information about certificate status for specific Hostname
	CertStatusItem struct {
		ValidationCname ValidationCname `json:"validationCname,omitempty"`
		Staging         []StatusItem    `json:"staging,omitempty"`
		Production      []StatusItem    `json:"production,omitempty"`
	}

	// ValidationCname is the CNAME record used to validate the certificate’s domain
	ValidationCname struct {
		Hostname string `json:"hostname,omitempty"`
		Target   string `json:"target,omitempty"`
	}

	// StatusItem determines whether a hostname is capable of serving secure content over the staging or production network.
	StatusItem struct {
		Status string `json:"status,omitempty"`
	}

	// UpdatePropertyVersionHostnamesRequest contains parameters required to update the set of hostname entries for a property version
	UpdatePropertyVersionHostnamesRequest struct {
		PropertyID        string
		PropertyVersion   int
		ContractID        string
		GroupID           string
		ValidateHostnames bool
		IncludeCertStatus bool
		Hostnames         []Hostname
	}

	// UpdatePropertyVersionHostnamesResponse contains information about each of the HostnameRequestItems
	UpdatePropertyVersionHostnamesResponse struct {
		AccountID       string                `json:"accountId"`
		ContractID      string                `json:"contractId"`
		GroupID         string                `json:"groupId"`
		PropertyID      string                `json:"propertyId"`
		PropertyVersion int                   `json:"propertyVersion"`
		Etag            string                `json:"etag"`
		Hostnames       HostnameResponseItems `json:"hostnames"`
	}

	// PatchPropertyVersionHostnamesRequest contains parameters for patch property version hostnames
	PatchPropertyVersionHostnamesRequest struct {
		PropertyID        string
		PropertyVersion   int
		ContractID        string
		GroupID           string
		ValidateHostnames bool
		IncludeCertStatus bool
		Body              PatchPropertyVersionHostnamesRequestBody
	}

	// PatchPropertyVersionHostnamesRequestBody contains the request body for patching property version hostnames
	PatchPropertyVersionHostnamesRequestBody struct {
		Add    []HostnameAdd `json:"add,omitempty"`
		Remove []string      `json:"remove,omitempty"`
	}

	// HostnameAdd contains information about the hostname to be added in patch property version hostnames
	HostnameAdd struct {
		CnameFrom            string            `json:"cnameFrom"`
		CnameType            HostnameCnameType `json:"cnameType,omitempty"`
		CnameTo              string            `json:"cnameTo,omitempty"`
		CertProvisioningType CertType          `json:"certProvisioningType,omitempty"`
		EdgeHostnameID       string            `json:"edgeHostnameId,omitempty"`
	}

	// PatchPropertyVersionHostnamesResponse contains response from patch property version hostnames
	PatchPropertyVersionHostnamesResponse struct {
		AccountID       string                `json:"accountId"`
		ContractID      string                `json:"contractId"`
		GroupID         string                `json:"groupId"`
		Etag            string                `json:"etag"`
		PropertyID      string                `json:"propertyId"`
		PropertyName    string                `json:"propertyName"`
		PropertyVersion int                   `json:"propertyVersion"`
		Hostnames       HostnameResponseItems `json:"hostnames"`
	}

	// HostnameCnameType represents HostnameCnameType enum
	HostnameCnameType string
)

const (
	// HostnameCnameTypeEdgeHostname const
	HostnameCnameTypeEdgeHostname HostnameCnameType = "EDGE_HOSTNAME"
)

// Validate validates HostnameCnameType.
func (t HostnameCnameType) Validate() validation.InRule {
	return validation.In(HostnameCnameTypeEdgeHostname).
		Error(fmt.Sprintf("value '%s' is invalid. There is only one supported value of: %s",
			t, HostnameCnameTypeEdgeHostname))
}

// Validate validates GetPropertyVersionHostnamesRequest
func (ph GetPropertyVersionHostnamesRequest) Validate() error {
	return validation.Errors{
		"PropertyID":      validation.Validate(ph.PropertyID, validation.Required),
		"PropertyVersion": validation.Validate(ph.PropertyVersion, validation.Required),
	}.Filter()
}

// Validate validates UpdatePropertyVersionHostnamesRequest
func (ch UpdatePropertyVersionHostnamesRequest) Validate() error {
	return validation.Errors{
		"PropertyID":      validation.Validate(ch.PropertyID, validation.Required),
		"PropertyVersion": validation.Validate(ch.PropertyVersion, validation.Required),
	}.Filter()
}

// Validate validates PatchPropertyVersionHostnamesRequest
func (r PatchPropertyVersionHostnamesRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"PropertyID":      validation.Validate(r.PropertyID, validation.Required),
		"PropertyVersion": validation.Validate(r.PropertyVersion, validation.Required),
		"Body":            validation.Validate(r.Body, validation.Required),
	})
}

// Validate validates PatchPropertyVersionHostnamesRequestBody
func (b PatchPropertyVersionHostnamesRequestBody) Validate() error {
	return validation.Errors{
		"Add": validation.Validate(b.Add),
	}.Filter()
}

// Validate validates HostnameAdd
func (b HostnameAdd) Validate() error {
	return validation.Errors{
		"CnameFrom": validation.Validate(b.CnameFrom, validation.Required),
		"CnameType": validation.Validate(b.CnameType,
			validation.When(b.CnameType != "", b.CnameType.Validate())),
		"CertProvisioningType": validation.Validate(b.CertProvisioningType,
			validation.When(b.CertProvisioningType != "", b.CertProvisioningType.Validate())),
		"required parameters": validation.Validate(nil,
			validation.By(func(interface{}) error {
				if b.CnameTo == "" && b.EdgeHostnameID == "" {
					return fmt.Errorf("either CnameTo or EdgeHostnameID must be provided")
				}
				return nil
			})),
	}.Filter()
}

var (
	// ErrGetPropertyVersionHostnames represents error when fetching hostnames fails
	ErrGetPropertyVersionHostnames = errors.New("fetching hostnames")
	// ErrUpdatePropertyVersionHostnames represents error when updating hostnames fails
	ErrUpdatePropertyVersionHostnames = errors.New("updating hostnames")
	// ErrPatchPropertyVersionHostnames represents error when patching hostnames fails
	ErrPatchPropertyVersionHostnames = errors.New("patching hostnames")
)

func (p *papi) GetPropertyVersionHostnames(ctx context.Context, params GetPropertyVersionHostnamesRequest) (*GetPropertyVersionHostnamesResponse, error) {
	logger := p.Log(ctx)
	logger.Debug("GetPropertyVersionHostnames")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrGetPropertyVersionHostnames, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf("/papi/v1/properties/%s/versions/%d/hostnames", params.PropertyID, params.PropertyVersion))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %s", ErrGetPropertyVersionHostnames, err)
	}
	q := url.Values{}
	if params.GroupID != "" {
		q.Set("groupId", params.GroupID)
	}
	if params.ContractID != "" {
		q.Set("contractId", params.ContractID)
	}
	q.Set("validateHostnames", strconv.FormatBool(params.ValidateHostnames))
	q.Set("includeCertStatus", strconv.FormatBool(params.IncludeCertStatus))
	uri.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrGetPropertyVersionHostnames, err)
	}

	var hostnames GetPropertyVersionHostnamesResponse
	resp, err := p.Exec(req, &hostnames)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrGetPropertyVersionHostnames, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %w", ErrGetPropertyVersionHostnames, p.Error(resp))
	}

	return &hostnames, nil
}

func (p *papi) UpdatePropertyVersionHostnames(ctx context.Context, params UpdatePropertyVersionHostnamesRequest) (*UpdatePropertyVersionHostnamesResponse, error) {
	logger := p.Log(ctx)
	logger.Debug("UpdatePropertyVersionHostnames")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrUpdatePropertyVersionHostnames, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf("/papi/v1/properties/%s/versions/%v/hostnames", params.PropertyID, params.PropertyVersion))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %s", ErrUpdatePropertyVersionHostnames, err)
	}

	q := url.Values{}
	if params.GroupID != "" {
		q.Set("groupId", params.GroupID)
	}
	if params.ContractID != "" {
		q.Set("contractId", params.ContractID)
	}
	q.Set("validateHostnames", strconv.FormatBool(params.ValidateHostnames))
	q.Set("includeCertStatus", strconv.FormatBool(params.IncludeCertStatus))
	uri.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrUpdatePropertyVersionHostnames, err)
	}

	var hostnames UpdatePropertyVersionHostnamesResponse
	newHostnames := params.Hostnames
	if newHostnames == nil {
		newHostnames = []Hostname{}
	}
	resp, err := p.Exec(req, &hostnames, newHostnames)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrUpdatePropertyVersionHostnames, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %w", ErrUpdatePropertyVersionHostnames, p.Error(resp))
	}

	return &hostnames, nil
}

func (p *papi) PatchPropertyVersionHostnames(ctx context.Context, params PatchPropertyVersionHostnamesRequest) (*PatchPropertyVersionHostnamesResponse, error) {
	logger := p.Log(ctx)
	logger.Debug("PatchPropertyVersionHostnames")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrPatchPropertyVersionHostnames, ErrStructValidation, err)
	}

	query := url.Values{}
	if params.ContractID != "" {
		query.Set("contractId", params.ContractID)
	}
	if params.GroupID != "" {
		query.Set("groupId", params.GroupID)
	}
	if params.ValidateHostnames {
		query.Set("validateHostnames", fmt.Sprintf("%t", params.ValidateHostnames))
	}
	if params.IncludeCertStatus {
		query.Set("includeCertStatus", fmt.Sprintf("%t", params.IncludeCertStatus))
	}

	uri, err := url.Parse(fmt.Sprintf(
		"/papi/v1/properties/%s/versions/%v/hostnames",
		params.PropertyID,
		params.PropertyVersion,
	))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %w", ErrPatchPropertyVersionHostnames, err)
	}
	uri.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %w", ErrPatchPropertyVersionHostnames, err)
	}

	var result PatchPropertyVersionHostnamesResponse
	resp, err := p.Exec(req, &result, params.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %w", ErrPatchPropertyVersionHostnames, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %w", ErrPatchPropertyVersionHostnames, p.Error(resp))
	}

	return &result, nil
}
