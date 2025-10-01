package ccm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
)

func (c *ccm) ListCertificateBindings(ctx context.Context, params ListCertificateBindingsRequest) (*ListCertificateBindingsResponse, error) {
	logger := c.Log(ctx)
	logger.Debug("ListCertificateBindings")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrListCertificateBindings, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf("/ccm/v1/certificates/%s/certificate-bindings", params.CertificateID))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %w", ErrListCertificateBindings, err)
	}
	query := url.Values{}
	if params.PageSize > 0 {
		query.Set("pageSize", strconv.FormatInt(params.PageSize, 10))
	}
	if params.Page > 0 {
		query.Set("page", strconv.FormatInt(params.Page, 10))
	}
	uri.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %w", ErrListCertificateBindings, err)
	}

	var result ListCertificateBindingsResponse
	resp, err := c.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: request execution failed: %w", ErrListCertificateBindings, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %w", ErrListCertificateBindings, c.Error(resp))
	}

	return &result, nil
}

func (c *ccm) ListBindings(ctx context.Context, params ListBindingsRequest) (*ListBindingsResponse, error) {
	logger := c.Log(ctx)
	logger.Debug("ListBindings")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrListBindings, ErrStructValidation, err)
	}

	uri, err := url.Parse("/ccm/v1/certificate-bindings")
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %w", ErrListBindings, err)
	}
	query := url.Values{}
	if params.ContractID != "" {
		query.Set("contractId", params.ContractID)
	}
	if params.GroupID != "" {
		query.Set("groupId", params.GroupID)
	}
	if params.ExpiringInDays != nil {
		query.Set("expiringInDays", strconv.FormatInt(*params.ExpiringInDays, 10))
	}
	if params.Domain != "" {
		query.Set("domain", params.Domain)
	}
	if params.Network != "" {
		query.Set("network", string(params.Network))
	}
	if params.PageSize > 0 {
		query.Set("pageSize", strconv.FormatInt(params.PageSize, 10))
	}
	if params.Page > 0 {
		query.Set("page", strconv.FormatInt(params.Page, 10))
	}
	uri.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %w", ErrListBindings, err)
	}

	var result ListBindingsResponse
	resp, err := c.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: request execution failed: %w", ErrListBindings, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %w", ErrListBindings, c.Error(resp))
	}

	return &result, nil
}
