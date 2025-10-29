package ccm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/internal/request"
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

	req, err := request.NewGet(ctx, "/ccm/v1/certificates").
		AddQueryParamIf("contractId", params.ContractID, params.ContractID != "").
		AddQueryParamIf("groupId", params.GroupID, params.GroupID != "").
		AddQueryParamsFunc("certificateStatus", func() []string {
			return texts.ToStrings(params.CertificateStatus)
		}, len(params.CertificateStatus) > 0).
		AddQueryParamFunc("expiringInDays", func() string {
			return strconv.FormatInt(*params.ExpiringInDays, 10)
		}, params.ExpiringInDays != nil).
		AddQueryParamIf("domain", params.Domain, params.Domain != "").
		AddQueryParamIf("certificateName", params.CertificateName, params.CertificateName != "").
		AddQueryParamIf("keyType", string(params.KeyType), params.KeyType != "").
		AddQueryParamIf("issuer", params.Issuer, params.Issuer != "").
		AddQueryParamIf("includeCertificateMaterials", strconv.FormatBool(params.IncludeCertificateMaterials), params.IncludeCertificateMaterials).
		AddQueryParamIf("pageSize", strconv.FormatInt(params.PageSize, 10), params.PageSize > 0).
		AddQueryParamIf("page", strconv.FormatInt(params.Page, 10), params.Page > 0).
		AddQueryParamIf("sort", params.Sort, params.Sort != "").
		UseCommaSeparatedQuery().
		Build()
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

	req, err := request.NewPatch(ctx, "/ccm/v1/certificates/%s", params.CertificateID).
		AddQueryParamIf("acknowledgeWarnings", strconv.FormatBool(params.AcknowledgeWarnings), params.AcknowledgeWarnings).
		AddHeader("Content-Type", "application/json-patch+json").
		Build()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %w", ErrPatchCertificate, err)
	}

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

func (c *ccm) UpdateCertificate(ctx context.Context, params UpdateCertificateRequest) (*UpdateCertificateResponse, error) {
	logger := c.Log(ctx)
	logger.Debug("UpdateCertificate")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrUpdateCertificate, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf("/ccm/v1/certificates/%s", params.CertificateID))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse URL: %w", ErrUpdateCertificate, err)
	}

	query := url.Values{}
	if params.AcknowledgeWarnings {
		query.Set("acknowledgeWarnings", strconv.FormatBool(params.AcknowledgeWarnings))
	}
	uri.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %w", ErrUpdateCertificate, err)
	}

	var result UpdateCertificateResponse

	resp, err := c.Exec(req, &result, params)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %w", ErrUpdateCertificate, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %w", ErrUpdateCertificate, c.Error(resp))
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

	req, err := request.NewPost(ctx, "/ccm/v1/certificates").
		AddQueryParam("contractId", params.ContractID).
		AddQueryParam("groupId", params.GroupID).
		Build()
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

	req, err := request.NewGet(ctx, "/ccm/v1/certificates/%s", params.CertificateID).
		Build()
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

	req, err := request.NewDelete(ctx, "/ccm/v1/certificates/%s", params.CertificateID).
		Build()
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
