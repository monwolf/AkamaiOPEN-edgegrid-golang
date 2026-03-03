package appsec

import (
	"context"
	"fmt"
	"net/http"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v13/pkg/edgegriderr"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v13/pkg/session"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// The URLProtection interface supports creating, retrieving, updating and removing url protection rules.
	URLProtection interface {
		// ListURLProtectionRules returns url protection rules for a specific security configuration version.
		//
		// See: https://techdocs.akamai.com/application-security/reference/get-url-protection-policies
		ListURLProtectionRules(ctx context.Context, params ListURLProtectionRulesRequest) (*ListURLProtectionRulesResponse, error)

		// GetURLProtectionRule returns the specified url protection rule.
		//
		// See: https://techdocs.akamai.com/application-security/reference/get-url-protection-policy
		GetURLProtectionRule(ctx context.Context, params GetURLProtectionRuleRequest) (*GetURLProtectionRuleResponse, error)

		// CreateURLProtectionRule creates a new url protection rule for a specific configuration version.
		//
		// See: https://techdocs.akamai.com/application-security/reference/post-url-protection-policies
		CreateURLProtectionRule(ctx context.Context, params CreateURLProtectionRuleRequest) (*CreateURLProtectionRuleResponse, error)

		// UpdateURLProtectionRule updates details for a specific url protection rule.
		//
		// See: https://techdocs.akamai.com/application-security/reference/put-url-protection-policy
		UpdateURLProtectionRule(ctx context.Context, params UpdateURLProtectionRuleRequest) (*UpdateURLProtectionRuleResponse, error)

		// RemoveURLProtectionRule deletes the specified url protection rule.
		//
		// See: https://techdocs.akamai.com/application-security/reference/delete-url-protection-policy
		RemoveURLProtectionRule(ctx context.Context, params RemoveURLProtectionRuleRequest) error
	}

	// HostnamePath is used to specify hostname and path combinations for URL protection.
	HostnamePath struct {

		// Hostname is the hostname to match on (e.g., "example.com")
		Hostname string `json:"hostname"`

		// Paths is the list of URL paths to match on for this hostname (e.g., ["/api", "/admin"])
		Paths []string `json:"paths"`
	}

	// APIDefinition is used to specify API definitions for URL protection rules.
	APIDefinition struct {

		// APIDefinitionID is the unique identifier for the API definition
		APIDefinitionID int64 `json:"apiDefinitionId"`

		// DefinedResources indicates whether to protect defined resources in the API definition
		DefinedResources bool `json:"definedResources"`

		// ResourceIDs lists the specific resource IDs to protect within the API definition
		ResourceIDs []int64 `json:"resourceIds"`

		// UndefinedResources indicates whether to protect undefined resources in the API definition
		UndefinedResources bool `json:"undefinedResources"`
	}

	// Category on which load shedding is performed when the origin traffic rate exceeds the load shedding threshold. If intelligentLoadShedding is set to true, specify one or more categories.
	Category struct {

		// Type determines the category type (e.g., "CLIENT_LIST","BOTS","CLOUD_PROVIDERS")
		Type string `json:"type"`

		// PositiveMatch indicates whether this is a positive match (true) or negative match (false)
		PositiveMatch *bool `json:"positiveMatch"`

		//ListIDs is the list of IDs associated with the category
		ListIDs []string `json:"listIds,omitempty"`
	}

	// AtomicCondition is used to add bypass conditions for URL protection rules.
	// Specify one or more types of conditions to match on. You can match on client lists, request headers, or both.
	AtomicCondition struct {

		// Type specifies the class name of the condition (e.g., "MatchConditionClientList", "MatchConditionHeader")
		Type string `json:"className"`

		// Name specifies the name(s) to match against (e.g., header names, query parameter names)
		Names []string `json:"name,omitempty"`

		// NameWildcard indicates whether wildcard matching is enabled for the Name field
		NameWildcard *bool `json:"nameWildcard,omitempty"`

		// Value specifies the value(s) to match against (e.g., header values, client list IDs)
		Values []string `json:"value"`

		// ValueCase indicates whether value matching is case-sensitive
		ValueCase *bool `json:"valueCase,omitempty"`

		// ValueWildcard indicates whether wildcard matching is enabled for the Value field
		ValueWildcard *bool `json:"valueWildcard,omitempty"`
	}

	// AtomicConditionResp is used to add bypass conditions for URL protection rules.
	// Specify one or more types of conditions to match on. You can match on client lists, request headers, or both.
	AtomicConditionResp struct {

		// CheckIPs specifies the IPs to check (e.g., "REMOTE_ADDR", "X_FORWARDED_FOR")
		CheckIPs *string `json:"checkIps"`

		// Type specifies the class name of the condition (e.g., "MatchConditionClientList", "MatchConditionHeader")
		Type string `json:"className"`

		// Index specifies the index position of this condition in the list
		Index int64 `json:"index"`

		// Name specifies the name(s) to match against (e.g., header names, query parameter names)
		Names []string `json:"name"`

		// NameWildcard indicates whether wildcard matching is enabled for the Name field
		NameWildcard *bool `json:"nameWildcard"`

		// PositiveMatch indicates whether this is a positive match (true) or negative match (false)
		PositiveMatch bool `json:"positiveMatch"`

		// Value specifies the value(s) to match against (e.g., header values, client list IDs)
		Values []string `json:"value"`

		// ValueCase indicates whether value matching is case-sensitive
		ValueCase *bool `json:"valueCase"`

		// ValueWildcard indicates whether wildcard matching is enabled for the Value field
		ValueWildcard *bool `json:"valueWildcard"`
	}

	// BypassCondition is used to define bypass conditions for URL protection rules.
	BypassCondition struct {

		// AtomicConditions lists the individual conditions to evaluate for bypass
		AtomicConditions []AtomicCondition `json:"atomicConditions,omitempty"`
	}

	// BypassConditionResp is used to define bypass conditions for URL protection rules.
	BypassConditionResp struct {

		// AtomicConditions lists the individual conditions to evaluate for bypass
		AtomicConditions []AtomicConditionResp `json:"atomicConditions"`
	}

	// URLProtectionRuleRequestBody is used to create or update a url protection rule.
	URLProtectionRuleRequestBody struct {

		// Name is the name of the URL protection rule
		Name string `json:"name"`

		// Description provides details about the URL protection rule
		Description *string `json:"description,omitempty"`

		// BypassCondition contains conditions under which the URL protection rule is bypassed
		BypassCondition *BypassCondition `json:"bypassCondition,omitempty"`

		// MaxRateThreshold specifies the maximum number of requests per second before rate limiting is applied
		MaxRateThreshold int64 `json:"rateThreshold"`

		// APIDefinitions lists the API definitions to which this rule applies
		APIDefinitions []APIDefinition `json:"apiDefinitions,omitempty"`

		// HostnamePaths lists the hostname and path combinations to which this rule applies
		HostnamePaths []HostnamePath `json:"hostnamePaths,omitempty"`

		// ProtectionType specifies the type of protection (e.g., "rate", "slowPost")
		ProtectionType *string `json:"protectionType,omitempty"`

		// IntelligentLoadShedding enables intelligent load shedding when traffic exceeds thresholds
		IntelligentLoadShedding bool `json:"intelligentLoadShedding"`

		// SheddingThresholdHitsPerSec specifies the threshold in hits per second for load shedding
		SheddingThresholdHitsPerSec *int64 `json:"sheddingThresholdHitsPerSec,omitempty"`

		// Categories lists the categories to which this rule applies
		Categories []Category `json:"categories,omitempty"`
	}

	// GetURLProtectionRuleRequest is used to retrieve information about a specific url protection rule.
	GetURLProtectionRuleRequest struct {

		// ConfigID is the unique identifier of the security configuration
		ConfigID int64

		// ConfigVersion is the version number of the security configuration
		ConfigVersion int64

		// URLProtectionRuleID is the unique identifier of the URL protection rule to retrieve
		URLProtectionRuleID int64
	}

	// GetURLProtectionRuleResponse is returned from a call to GetURLProtectionRule.
	GetURLProtectionRuleResponse struct {

		// URLProtectionRuleID is the unique identifier for the URL protection policy
		URLProtectionRuleID int64 `json:"policyId"`

		// ConfigID is the unique identifier of the security configuration
		ConfigID int64 `json:"configId"`

		// ConfigVersion is the version number of the security configuration
		ConfigVersion int64 `json:"configVersion"`

		// Name is the name of the URL protection rule
		Name string `json:"name"`

		// Description provides details about the URL protection rule
		Description *string `json:"description"`

		// BypassCondition contains conditions under which the URL protection rule is bypassed
		BypassCondition *BypassConditionResp `json:"bypassCondition"`

		// MaxRateThreshold specifies the maximum number of requests per second before rate limiting is applied
		MaxRateThreshold int64 `json:"rateThreshold"`

		// APIDefinitions lists the API definitions to which this rule applies
		APIDefinitions []APIDefinition `json:"apiDefinitions"`

		// HostnamePaths lists the hostname and path combinations to which this rule applies
		HostnamePaths []HostnamePath `json:"hostnamePaths"`

		// ProtectionType specifies the type of protection (e.g., "rate", "slowPost")
		ProtectionType *string `json:"protectionType"`

		// IntelligentLoadShedding enables intelligent load shedding when traffic exceeds thresholds
		IntelligentLoadShedding bool `json:"intelligentLoadShedding"`

		// SheddingThresholdHitsPerSec specifies the threshold in hits per second for load shedding
		SheddingThresholdHitsPerSec *int64 `json:"sheddingThresholdHitsPerSec"`

		// Categories lists the categories to which this rule applies
		Categories []Category `json:"categories"`

		// Used indicates whether the rule is currently in use
		Used bool `json:"used"`

		// CreateDate is the timestamp when the rule was created
		CreateDate string `json:"createDate"`

		// CreatedBy is the user who created the rule
		CreatedBy string `json:"createdBy"`

		// UpdateDate is the timestamp when the rule was last updated
		UpdateDate string `json:"updateDate"`

		// UpdatedBy is the user who last updated the rule
		UpdatedBy string `json:"updatedBy"`
	}

	// ListURLProtectionRulesRequest is used to retrieve the url protection rules for a configuration.
	ListURLProtectionRulesRequest struct {

		// ConfigID is the unique identifier of the security configuration
		ConfigID int64

		// ConfigVersion is the version number of the security configuration
		ConfigVersion int64
	}

	// ListURLProtectionRulesResponse is returned from a call to ListURLProtectionRules.
	ListURLProtectionRulesResponse struct {

		// URLProtectionRules is the list of URL protection rules
		URLProtectionRules []GetURLProtectionRuleResponse `json:"urlProtectionPolicies"`
	}

	// CreateURLProtectionRuleRequest is used to create a url protection rule.
	CreateURLProtectionRuleRequest struct {

		// ConfigID is the unique identifier of the security configuration
		ConfigID int64

		// ConfigVersion is the version number of the security configuration
		ConfigVersion int64

		// Body contains the details of the URL protection rule to create
		Body URLProtectionRuleRequestBody
	}

	// CreateURLProtectionRuleResponse is returned from a call to CreateURLProtectionRule.
	CreateURLProtectionRuleResponse GetURLProtectionRuleResponse

	// UpdateURLProtectionRuleRequest is used to modify an existing url protection rule.
	UpdateURLProtectionRuleRequest struct {

		// ConfigID is the unique identifier of the security configuration
		ConfigID int64

		// ConfigVersion is the version number of the security configuration
		ConfigVersion int64

		// URLProtectionRuleID is the unique identifier for the URL protection policy
		URLProtectionRuleID int64

		// Body contains the details of the URL protection rule to update
		Body URLProtectionRuleRequestBody
	}

	// UpdateURLProtectionRuleResponse is returned from a call to UpdateURLProtectionRule.
	UpdateURLProtectionRuleResponse GetURLProtectionRuleResponse

	// RemoveURLProtectionRuleRequest is used to remove a url protection rule.
	RemoveURLProtectionRuleRequest struct {

		// ConfigID is the unique identifier of the security configuration
		ConfigID int64

		// ConfigVersion is the version number of the security configuration
		ConfigVersion int64

		// URLProtectionRuleID is the unique identifier of the URL protection rule to remove
		URLProtectionRuleID int64
	}
)

// Validate validates a GetURLProtectionRuleRequest.
func (v GetURLProtectionRuleRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"ConfigID":            validation.Validate(v.ConfigID, validation.Required),
		"ConfigVersion":       validation.Validate(v.ConfigVersion, validation.Required),
		"URLProtectionRuleID": validation.Validate(v.URLProtectionRuleID, validation.Required),
	})
}

// Validate validates a ListURLProtectionRulesRequest.
func (v ListURLProtectionRulesRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"ConfigID":      validation.Validate(v.ConfigID, validation.Required),
		"ConfigVersion": validation.Validate(v.ConfigVersion, validation.Required),
	})
}

// Validate validates a Create/Update-URLProtectionRuleRequest.
func (v URLProtectionRuleRequestBody) Validate() error {
	return validation.Errors{
		"Name":             validation.Validate(v.Name, validation.Required),
		"MaxRateThreshold": validation.Validate(v.MaxRateThreshold, validation.Required),
	}.Filter()
}

// Validate validates a CreateURLProtectionRuleRequest.
func (v CreateURLProtectionRuleRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"ConfigID":      validation.Validate(v.ConfigID, validation.Required),
		"ConfigVersion": validation.Validate(v.ConfigVersion, validation.Required),
		"Body":          validation.Validate(v.Body, validation.Required),
	})
}

// Validate validates an UpdateURLProtectionRuleRequest.
func (v UpdateURLProtectionRuleRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"ConfigID":            validation.Validate(v.ConfigID, validation.Required),
		"ConfigVersion":       validation.Validate(v.ConfigVersion, validation.Required),
		"URLProtectionRuleID": validation.Validate(v.URLProtectionRuleID, validation.Required),
		"Body":                validation.Validate(v.Body, validation.Required),
	})
}

// Validate validates a RemoveURLProtectionRuleRequest.
func (v RemoveURLProtectionRuleRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"ConfigID":            validation.Validate(v.ConfigID, validation.Required),
		"ConfigVersion":       validation.Validate(v.ConfigVersion, validation.Required),
		"URLProtectionRuleID": validation.Validate(v.URLProtectionRuleID, validation.Required),
	})
}

func (p *appsec) GetURLProtectionRule(ctx context.Context, params GetURLProtectionRuleRequest) (*GetURLProtectionRuleResponse, error) {
	logger := p.Log(ctx)
	logger.Debug("GetURLProtectionRule")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStructValidation, err)
	}

	uri := fmt.Sprintf(
		"/appsec/v1/configs/%d/versions/%d/url-protections/%d",
		params.ConfigID,
		params.ConfigVersion,
		params.URLProtectionRuleID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GetURLProtectionRule request: %w", err)
	}

	var result GetURLProtectionRuleResponse
	resp, err := p.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("get url protection rule response failed: %w", err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &result, nil
}

func (p *appsec) ListURLProtectionRules(ctx context.Context, params ListURLProtectionRulesRequest) (*ListURLProtectionRulesResponse, error) {
	logger := p.Log(ctx)
	logger.Debug("ListURLProtectionRules")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStructValidation, err)
	}

	uri := fmt.Sprintf(
		"/appsec/v1/configs/%d/versions/%d/url-protections",
		params.ConfigID,
		params.ConfigVersion,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ListURLProtectionRules request: %w", err)
	}

	var result ListURLProtectionRulesResponse
	resp, err := p.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("get url protection rules request failed: %w", err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &result, nil
}

func (p *appsec) UpdateURLProtectionRule(ctx context.Context, params UpdateURLProtectionRuleRequest) (*UpdateURLProtectionRuleResponse, error) {
	logger := p.Log(ctx)
	logger.Debug("UpdateURLProtectionRule")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStructValidation, err)
	}

	uri := fmt.Sprintf(
		"/appsec/v1/configs/%d/versions/%d/url-protections/%d",
		params.ConfigID,
		params.ConfigVersion,
		params.URLProtectionRuleID,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create updateURLProtectionRule request: %w", err)
	}

	var result UpdateURLProtectionRuleResponse
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.Exec(req, &result, params.Body)
	if err != nil {
		return nil, fmt.Errorf("update url protection rule request failed: %w", err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &result, nil
}

func (p *appsec) CreateURLProtectionRule(ctx context.Context, params CreateURLProtectionRuleRequest) (*CreateURLProtectionRuleResponse, error) {
	logger := p.Log(ctx)
	logger.Debug("CreateURLProtectionRule")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStructValidation, err)
	}

	uri := fmt.Sprintf(
		"/appsec/v1/configs/%d/versions/%d/url-protections",
		params.ConfigID,
		params.ConfigVersion,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create CreateURLProtectionRule request: %w", err)
	}

	var result CreateURLProtectionRuleResponse
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.Exec(req, &result, params.Body)
	if err != nil {
		return nil, fmt.Errorf("create url protection rule request failed: %w", err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusCreated {
		return nil, p.Error(resp)
	}

	return &result, nil
}

func (p *appsec) RemoveURLProtectionRule(ctx context.Context, params RemoveURLProtectionRuleRequest) error {
	logger := p.Log(ctx)
	logger.Debug("RemoveURLProtectionRule")

	if err := params.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrStructValidation, err)
	}

	uri := fmt.Sprintf("/appsec/v1/configs/%d/versions/%d/url-protections/%d", params.ConfigID, params.ConfigVersion, params.URLProtectionRuleID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, nil)
	if err != nil {
		return fmt.Errorf("failed to create RemoveURLProtectionRule request: %w", err)
	}

	resp, err := p.Exec(req, nil)
	if err != nil {
		return fmt.Errorf("remove url protection rule request failed: %w", err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusNoContent {
		return p.Error(resp)
	}

	return nil
}
