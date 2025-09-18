package ccm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/internal/texts"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
)

type patch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value"`
}

func (c *ccm) ListCertificates(ctx context.Context, params ListCertificatesRequest) (*ListCertificatesResponse, error) {
	logger := c.Log(ctx)
	logger.Debug("ListCertificates")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrListCertificates, ErrStructValidation, err)
	}

	uri, err := url.Parse("/ccm/v1/certificates")
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse URL: %w", ErrListCertificates, err)
	}

	query := url.Values{}
	if params.ContractID != "" {
		query.Set("contractId", params.ContractID)
	}
	if params.GroupID != "" {
		query.Set("groupId", params.GroupID)
	}
	if len(params.CertificateStatus) > 0 {
		query.Set("certificateStatus", texts.JoinStringBased(params.CertificateStatus, ","))
	}
	if params.ExpiringInDays != nil {
		query.Set("expiringInDays", strconv.FormatInt(*params.ExpiringInDays, 10))
	}
	if params.Domain != "" {
		query.Set("domain", params.Domain)
	}
	if params.CertificateName != "" {
		query.Set("certificateName", params.CertificateName)
	}
	if params.KeyType != "" {
		query.Set("keyType", string(params.KeyType))
	}
	if params.Issuer != "" {
		query.Set("issuer", params.Issuer)
	}
	if params.IncludeCertificateMaterials {
		query.Set("includeCertificateMaterials", strconv.FormatBool(params.IncludeCertificateMaterials))
	}
	if params.PageSize > 0 {
		query.Set("pageSize", strconv.FormatInt(params.PageSize, 10))
	}
	if params.Page > 0 {
		query.Set("page", strconv.FormatInt(params.Page, 10))
	}
	if params.Sort != "" {
		query.Set("sort", params.Sort)
	}
	uri.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %w", ErrListCertificates, err)
	}

	var result ListCertificatesResponse

	resp, err := c.Exec(req, &result, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %w", ErrListCertificates, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %w", ErrListCertificates, c.Error(resp))
	}
	return &result, nil
}

func (c *ccm) PatchCertificate(ctx context.Context, params PatchCertificateRequest) (*PatchCertificateResponse, error) {
	logger := c.Log(ctx)
	logger.Debug("PatchCertificate")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrPatchCertificate, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf("/ccm/v1/certificates/%s", params.CertificateID))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse URL: %w", ErrPatchCertificate, err)
	}

	query := url.Values{}
	if params.AcknowledgeWarnings {
		query.Set("acknowledgeWarnings", strconv.FormatBool(params.AcknowledgeWarnings))
	}
	uri.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %w", ErrPatchCertificate, err)
	}
	req.Header.Set("Content-Type", "application/json-patch+json")

	reqBody := buildPatchRequestBody(params)
	var result PatchCertificateResponse

	resp, err := c.Exec(req, &result, reqBody)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %w", ErrPatchCertificate, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %w", ErrPatchCertificate, c.Error(resp))
	}
	return &result, nil
}

func buildPatchRequestBody(params PatchCertificateRequest) []patch {
	var reqBody []patch

	if params.SignedCertificatePEM != "" {
		reqBody = append(reqBody, patch{
			Op:    "add",
			Path:  "/signedCertificatePem",
			Value: params.SignedCertificatePEM,
		})
	}
	if params.TrustChainPEM != "" {
		reqBody = append(reqBody, patch{
			Op:    "add",
			Path:  "/trustChainPem",
			Value: params.TrustChainPEM,
		})
	}
	if params.CertificateName != nil {
		reqBody = append(reqBody, patch{
			Op:    "replace",
			Path:  "/certificateName",
			Value: *params.CertificateName,
		})
	}

	return reqBody
}

func (c *ccm) CreateCertificate(ctx context.Context, params CreateCertificateRequest) (*CreateCertificateResponse, error) {
	logger := c.Log(ctx)
	logger.Debug("CreateCertificate")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrCreateCertificate, ErrStructValidation, err)
	}

	uri, err := url.Parse("/ccm/v1/certificates")
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %w", ErrCreateCertificate, err)
	}

	query := url.Values{}

	query.Set("contractId", params.ContractID)
	query.Set("groupId", params.GroupID)

	uri.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %w", ErrCreateCertificate, err)
	}

	var result CreateCertificateResponse
	resp, err := c.Exec(req, &result.Certificate, params.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: request execution failed: %w", ErrCreateCertificate, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("%w: %w", ErrCreateCertificate, c.Error(resp))
	}
	if resp.Header.Get("Akamai-Limit-Certificates") != "" {
		limitTotal, err := strconv.ParseInt(resp.Header.Get("Akamai-Limit-Certificates"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse Akamai-Limit-Certificates header: %w",
				ErrCreateCertificate, err)
		}
		result.ResourceLimits.CertificateLimitTotal = limitTotal
	}
	if resp.Header.Get("Akamai-Limit-Certificates-Remaining") != "" {
		limitRemaining, err := strconv.ParseInt(resp.Header.Get("Akamai-Limit-Certificates-Remaining"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse Akamai-Limit-Certificates-Remaining header: %w",
				ErrCreateCertificate, err)
		}
		result.ResourceLimits.CertificateLimitRemaining = limitRemaining
	}

	return &result, nil
}

func (c *ccm) GetCertificate(ctx context.Context, params GetCertificateRequest) (*GetCertificateResponse, error) {
	logger := c.Log(ctx)
	logger.Debug("GetCertificate")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrGetCertificate, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf("/ccm/v1/certificates/%s", params.CertificateID))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %w", ErrGetCertificate, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %w", ErrGetCertificate, err)
	}

	var result GetCertificateResponse
	resp, err := c.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: request execution failed: %w", ErrGetCertificate, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %w", ErrGetCertificate, c.Error(resp))
	}

	return &result, nil
}

func (c *ccm) DeleteCertificate(ctx context.Context, params DeleteCertificateRequest) error {
	logger := c.Log(ctx)
	logger.Debug("DeleteCertificate")

	if err := params.Validate(); err != nil {
		return fmt.Errorf("%w: %w: %w", ErrDeleteCertificate, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf("/ccm/v1/certificates/%s", params.CertificateID))
	if err != nil {
		return fmt.Errorf("%w: failed to parse url: %w", ErrDeleteCertificate, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri.String(), nil)
	if err != nil {
		return fmt.Errorf("%w: failed to create request: %w", ErrDeleteCertificate, err)
	}

	resp, err := c.Exec(req, nil)
	if err != nil {
		return fmt.Errorf("%w: request execution failed: %w", ErrDeleteCertificate, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("%w: %w", ErrDeleteCertificate, c.Error(resp))
	}

	return nil
}
