package domainownership

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/edgegriderr"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/session"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// ValidationScope represents the scope of domain validation.
	ValidationScope string

	// ListDomainsRequest represents the request parameters for listing domains.
	ListDomainsRequest struct {
		// Paginate indicates whether to paginate the results.
		Paginate *bool

		// Page specifies the page number for pagination.
		Page *int64

		// PageSize specifies the number of items per page for pagination.
		PageSize *int64
	}

	// ListDomainsResponse represents the response from listing domains.
	ListDomainsResponse struct {
		// Domains contains the list of returned domains.
		Domains []DomainItem `json:"domains"`

		// Metadata represents the metadata section of a paginated API response.
		Metadata Metadata `json:"metadata"`

		// Links to navigate between pages.
		Links []Link `json:"links"`
	}

	// DomainItem represents a single domain in the list response.
	DomainItem struct {
		// AccountID is the ID of an account.
		AccountID string `json:"accountId"`

		// DomainName is the name of the domain.
		DomainName string `json:"domainName"`

		// DomainStatus is the status of the domain. Either REQUEST_ACCEPTED, VALIDATION_IN_PROGRESS, VALIDATED, TOKEN_EXPIRED, or INVALIDATED.
		DomainStatus string `json:"domainStatus"`

		// ValidationChallenge contains the validation challenge details for the domain.
		ValidationChallenge *ValidationChallenge `json:"validationChallenge"`

		// ValidationCompletedDate is the timestamp when the validation was completed.
		ValidationCompletedDate *time.Time `json:"validationCompletedDate"`

		// ValidationMethod is method of the domain validation, either DNS_CNAME, DNS_TXT, HTTP, SYSTEM, or MANUAL.
		ValidationMethod *string `json:"validationMethod"`

		// ValidationRequestedBy is the user who requested the validation.
		ValidationRequestedBy string `json:"validationRequestedBy"`

		// ValidationRequestedDate is the timestamp when the validation was requested.
		ValidationRequestedDate time.Time `json:"validationRequestedDate"`

		// ValidationScope indicates the scope of the validation, either HOST, DOMAIN, or WILDCARD.
		ValidationScope string `json:"validationScope"`
	}

	// ValidationChallenge contains the details of the validation challenge for a domain.
	ValidationChallenge struct {
		// ChallengeToken is the challenge token you need to use for domain validation.
		ChallengeToken string `json:"challengeToken"`

		// ChallengeTokenExpiresDate is an ISO 8601 timestamp indicating when the domain validation token expires.
		ChallengeTokenExpiresDate time.Time `json:"challengeTokenExpiresDate"`

		// DNSCname is DNS CNAME you need to use for DNS CNAME domain validation.
		DNSCname string `json:"dnsCname"`

		// HTTPRedirectFrom is the HTTP URL for checking the challenge token during HTTP validation.
		HTTPRedirectFrom *string `json:"httpRedirectFrom"`

		// HTTPRedirectTo is the HTTP redirect URL for HTTP validation.
		HTTPRedirectTo *string `json:"httpRedirectTo"`
	}

	// Metadata represents the metadata section of a paginated API response.
	Metadata struct {
		// HasNext indicates whether the next page is available.
		HasNext bool `json:"hasNext"`

		// HasPrevious indicates whether the previous page is available.
		HasPrevious bool `json:"hasPrevious"`

		// Page is the current page number.
		Page int64 `json:"page"`

		// PageSize is the number of items per page.
		PageSize int64 `json:"pageSize"`

		// TotalPages is the total number of items available.
		TotalItems int64 `json:"totalItems"`
	}

	// Link represents a data to navigate between pages.
	Link struct {
		// Href is Hyperlink reference of the page.
		Href string `json:"href"`

		// Rel is type of link. Either prev, next, or self.
		Rel string `json:"rel"`
	}

	// GetDomainRequest represents the request parameters for getting a specific domain.
	GetDomainRequest struct {
		// DomainName is the name of the domain to retrieve.
		DomainName string

		// ValidationScope indicates the scope of the validation, either HOST, DOMAIN, or WILDCARD.
		ValidationScope ValidationScope

		// IncludeDomainStatusHistory indicates whether to include the domain status history in the response.
		IncludeDomainStatusHistory bool
	}

	// GetDomainResponse represents the response from getting a specific domain.
	GetDomainResponse struct {
		// AccountID is the ID of an account.
		AccountID string `json:"accountId"`

		// DomainName is the name of the domain.
		DomainName string `json:"domainName"`

		// DomainStatus is the status of the domain. Either REQUEST_ACCEPTED, VALIDATION_IN_PROGRESS, VALIDATED, TOKEN_EXPIRED, or INVALIDATED.
		DomainStatus string `json:"domainStatus"`

		// DomainStatusHistory contains the history of domain status changes.
		DomainStatusHistory []DomainStatusHistory `json:"domainStatusHistory"`

		// ValidationChallenge contains the validation challenge details for the domain.
		ValidationChallenge *ValidationChallenge `json:"validationChallenge"`

		// ValidationCompletedDate is the timestamp when the validation was completed.
		ValidationCompletedDate *time.Time `json:"validationCompletedDate"`

		// ValidationMethod is method of the domain validation, either DNS_CNAME, DNS_TXT, HTTP, SYSTEM, or MANUAL.
		ValidationMethod *string `json:"validationMethod"`

		// ValidationRequestedBy is the user who requested the validation.
		ValidationRequestedBy string `json:"validationRequestedBy"`

		// ValidationRequestedDate is the timestamp when the validation was requested.
		ValidationRequestedDate time.Time `json:"validationRequestedDate"`

		// ValidationScope indicates the scope of the validation, either HOST, DOMAIN, or WILDCARD.
		ValidationScope string `json:"validationScope"`
	}

	// DomainStatusHistory represents the event of history of domain status changes.
	DomainStatusHistory struct {
		// DomainStatus is the status of the domain. Either REQUEST_ACCEPTED, VALIDATION_IN_PROGRESS, VALIDATED, TOKEN_EXPIRED, or INVALIDATED.
		DomainStatus string `json:"domainStatus"`

		// ModifiedDate is an ISO 8601 timestamp indicating when the domain status changed.
		ModifiedDate time.Time `json:"modifiedDate"`

		// ModifiedUser is the user who modified the domain status.
		ModifiedUser string `json:"modifiedUser"`

		// Message is an information about the status change.
		Message *string `json:"message"`
	}

	// SearchDomainsRequest represents the request parameters for searching domains.
	SearchDomainsRequest struct {
		// IncludeAll indicates whether to return a detailed response.
		IncludeAll bool

		// Body contains the search criteria for domains.
		Body SearchDomainsBody
	}

	// SearchDomainsBody represents the body of the search domains request.
	SearchDomainsBody struct {
		// Domains is a list of domains to search for.
		Domains []SearchDomain `json:"domains"`
	}

	// SearchDomain represents a domain to search for in the search domains request.
	SearchDomain struct {
		// DomainName is the name of the domain to search for.
		DomainName string `json:"domainName"`

		// ValidationScope indicates the scope of the validation, either HOST, DOMAIN, or WILDCARD.
		ValidationScope ValidationScope `json:"validationScope"`
	}

	// SearchDomainsResponse represents the response from searching domains.
	SearchDomainsResponse struct {
		// Domains contains the list of domains that match the search criteria with their details.
		Domains []SearchDomainItem `json:"domains"`
	}

	// SearchDomainItem represents a single domain in the search response.
	SearchDomainItem struct {
		// DomainName is the name of the domain.
		DomainName string `json:"domainName"`

		// DomainStatus is the status of the domain. Either REQUEST_ACCEPTED, VALIDATION_IN_PROGRESS, VALIDATED, TOKEN_EXPIRED, or INVALIDATED.
		DomainStatus string `json:"domainStatus"`

		// ValidationScope indicates the scope of the validation, either HOST, DOMAIN, or WILDCARD.
		ValidationScope string `json:"validationScope"`

		// ValidationLevel is level of the domain validation, either FQDN or WILDCARD.
		ValidationLevel string `json:"validationLevel"`

		// AccountID is the ID of an account.
		AccountID *string `json:"accountId"`

		// ValidationMethod is method of the domain validation, either DNS_CNAME, DNS_TXT, HTTP, SYSTEM, or MANUAL.
		ValidationMethod *string `json:"validationMethod"`

		// ValidationRequestedBy is the user who requested the validation.
		ValidationRequestedBy *string `json:"validationRequestedBy"`

		// ValidationRequestedDate is the timestamp when the validation was requested.
		ValidationRequestedDate *time.Time `json:"validationRequestedDate"`

		// ValidationCompletedDate is the timestamp when the validation was completed.
		ValidationCompletedDate *time.Time `json:"validationCompletedDate"`

		// ValidationChallenge contains the validation challenge details for the domain.
		ValidationChallenge *ValidationChallenge `json:"validationChallenge"`
	}
)

const (
	// ValidationScopeHost represents the scope of validation for only the exactly specified domain.
	ValidationScopeHost ValidationScope = "HOST"

	// ValidationScopeDomain represents the scope of validation for any hostnames under the domain, regardless of the level of subdomains.
	ValidationScopeDomain ValidationScope = "DOMAIN"

	// ValidationScopeWildcard represents the scope of validation for any hostname within one subdomain level.
	ValidationScopeWildcard ValidationScope = "WILDCARD"
)

// Validate validates the ListDomainsRequest parameters.
func (r ListDomainsRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"PageSize": validation.Validate(r.PageSize, validation.When(r.PageSize != nil, validation.By(emptyOrTrue(r.Paginate)), validation.Min(10), validation.Max(1000))),
		"Page":     validation.Validate(r.Page, validation.When(r.Page != nil, validation.By(emptyOrTrue(r.Paginate)))),
	})
}

// Validate validates the GetDomainRequest parameters.
func (r GetDomainRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"DomainName":      domainNameValidation(r.DomainName),
		"ValidationScope": scopeValidation(r.ValidationScope),
	})
}

// Validate validates the SearchDomainsRequest parameters.
func (r SearchDomainsRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"Body": validation.Validate(r.Body, validation.Required),
	})
}

// Validate validates the SearchDomainsBody parameters.
func (b SearchDomainsBody) Validate() error {
	return validation.Errors{
		"Domains": validation.Validate(b.Domains, validation.Required),
	}.Filter()
}

// Validate validates the SearchDomain parameters.
func (d SearchDomain) Validate() error {
	return validation.Errors{
		"DomainName":      domainNameValidation(d.DomainName),
		"ValidationScope": scopeValidation(d.ValidationScope),
	}.Filter()
}

func domainNameValidation(domainName string) error {
	return validation.Validate(domainName, validation.Required)
}

func scopeValidation(scope ValidationScope) error {
	return validation.Validate(scope, validation.Required, validation.In(ValidationScopeHost, ValidationScopeDomain, ValidationScopeWildcard).
		Error(fmt.Sprintf("value '%s' is invalid. Must be one of: '%s', '%s' or '%s'", scope, ValidationScopeHost, ValidationScopeDomain, ValidationScopeWildcard)))
}

func emptyOrTrue(paginate *bool) validation.RuleFunc {
	return func(_ interface{}) error {
		if paginate != nil && !*paginate {
			return fmt.Errorf("must be empty when Paginate is false")
		}
		return nil
	}
}

var (
	// ErrListDomains is returned when there is an error listing domains.
	ErrListDomains = errors.New("list domains")

	// ErrGetDomain is returned when there is an error getting a specific domain.
	ErrGetDomain = errors.New("get domain")

	// ErrSearchDomains is returned when there is an error searching for domains.
	ErrSearchDomains = errors.New("search domains")
)

func (d *domainownership) ListDomains(ctx context.Context, params ListDomainsRequest) (*ListDomainsResponse, error) {
	logger := d.Log(ctx)
	logger.Debug("ListDomains")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w:\n%s", ErrListDomains, ErrStructValidation, err)
	}

	uri, err := url.Parse("/domain-validation/v1/domains")
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrListDomains, err)
	}

	q := uri.Query()
	if params.Paginate != nil {
		q.Add("paginate", fmt.Sprintf("%t", *params.Paginate))
	}

	if params.Page != nil {
		q.Add("page", fmt.Sprintf("%d", *params.Page))
	}

	if params.PageSize != nil {
		q.Add("pageSize", fmt.Sprintf("%d", *params.PageSize))
	}
	uri.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrListDomains, err)
	}

	var result ListDomainsResponse
	resp, err := d.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrListDomains, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %w", ErrListDomains, d.Error(resp))
	}

	return &result, nil
}

func (d *domainownership) GetDomain(ctx context.Context, params GetDomainRequest) (*GetDomainResponse, error) {
	logger := d.Log(ctx)
	logger.Debug("GetDomain")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w:\n%s", ErrGetDomain, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf("/domain-validation/v1/domains/%s", params.DomainName))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrGetDomain, err)
	}

	q := uri.Query()
	q.Add("validationScope", string(params.ValidationScope))

	if params.IncludeDomainStatusHistory {
		q.Add("includeDomainStatusHistory", fmt.Sprintf("%t", params.IncludeDomainStatusHistory))
	}

	uri.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrGetDomain, err)
	}

	var result GetDomainResponse
	resp, err := d.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrGetDomain, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %w", ErrGetDomain, d.Error(resp))
	}

	return &result, nil
}

func (d *domainownership) SearchDomains(ctx context.Context, params SearchDomainsRequest) (*SearchDomainsResponse, error) {
	logger := d.Log(ctx)
	logger.Debug("SearchDomains")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w:\n%s", ErrSearchDomains, ErrStructValidation, err)
	}

	uri, err := url.Parse("/domain-validation/v1/domains/search")
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrSearchDomains, err)
	}

	q := uri.Query()

	if params.IncludeAll {
		q.Add("includeAll", fmt.Sprintf("%t", params.IncludeAll))
	}

	uri.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrSearchDomains, err)
	}

	var result SearchDomainsResponse
	resp, err := d.Exec(req, &result, params.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrSearchDomains, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %w", ErrSearchDomains, d.Error(resp))
	}

	return &result, nil
}
