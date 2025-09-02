package ccm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
)

type patch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value"`
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
