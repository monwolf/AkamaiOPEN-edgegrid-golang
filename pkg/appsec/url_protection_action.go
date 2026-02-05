package appsec

import (
	"context"
	"fmt"
	"net/http"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/edgegriderr"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// The URLProtectionRuleAction interface supports retrieving and modifying the actions associated with
	// a specified url protection rule, or with all url protection rules in a security policy.
	URLProtectionRuleAction interface {
		// ListURLProtectionRulesActions returns a list of all url protections rules currently in use with the actions each policy takes.
		//
		// See: https://techdocs.akamai.com/application-security/reference/get-url-protection-policies-actions
		ListURLProtectionRulesActions(ctx context.Context, params ListURLProtectionRulesActionsRequest) (*ListURLProtectionRulesActionsResponse, error)

		// GetURLProtectionRuleActions returns a specific url protections rule currently in use with the actions.
		GetURLProtectionRuleActions(ctx context.Context, params GetURLProtectionRuleActionsRequest) (*GetURLProtectionRuleActionsResponse, error)

		// UpdateURLProtectionRuleActions updates the actions for a url protection rule.
		//
		// See: https://techdocs.akamai.com/application-security/reference/put-url-protection-policy-action
		UpdateURLProtectionRuleActions(ctx context.Context, params UpdateURLProtectionRuleActionsRequest) (*UpdateURLProtectionRuleActionsResponse, error)
	}

	// URLProtectionRuleActions represents the actions associated with a specific URL protection rule.
	URLProtectionRuleActions struct {

		// MaxRateThresholdAction specifies the action to take when the max rate threshold is exceeded (e.g., "alert", "deny", "none", "challenge_{id}", "deny_custom_{id}")
		MaxRateThresholdAction string `json:"action"`

		// LoadSheddingAction specifies the action to take for load shedding (e.g., "alert", "deny", "challenge_{id}", "deny_custom_{id}")
		LoadSheddingAction string `json:"loadSheddingAction,omitempty"`
	}

	// ListURLProtectionRulesActionsRequest is used to retrieve a configuration's url protection rules and their associated actions.
	ListURLProtectionRulesActionsRequest struct {

		// ConfigID is the unique identifier of the security configuration
		ConfigID int64

		// ConfigVersion is the ConfigVersion number of the security configuration
		ConfigVersion int64

		// PolicyID is the unique identifier of the security policy
		PolicyID string
	}

	// URLProtectionActionResp URLProtectionAction represents the action associated with a specific URL protection rule.
	URLProtectionActionResp struct {

		// URLProtectionRuleID is the unique identifier for the URL protection rule
		URLProtectionRuleID int64 `json:"policyId"`

		// MaxRateThresholdAction specifies the action to take when the max rate threshold is exceeded (e.g., "alert", "deny", "none", "challenge_{id}", "deny_custom_{id}")
		MaxRateThresholdAction string `json:"action"`

		// LoadSheddingAction specifies the action to take for load shedding (e.g., "alert", "deny","challenge_{id}","deny_custom_{id}")
		LoadSheddingAction string `json:"loadSheddingAction"`
	}

	// ListURLProtectionRulesActionsResponse is returned from a call to ListURLProtectionRulesActions.
	ListURLProtectionRulesActionsResponse struct {

		// URLProtectionRulesActions is the list of URL protection rules with their associated actions
		URLProtectionRulesActions []URLProtectionActionResp `json:"urlProtectionActions"`
	}

	// GetURLProtectionRuleActionsRequest is used to retrieve the actions associated with the particular url protection of specific policy in a config ConfigVersion.
	GetURLProtectionRuleActionsRequest struct {

		// ConfigID is the unique identifier of the security configuration
		ConfigID int64

		// ConfigVersion is the ConfigVersion number of the security configuration
		ConfigVersion int64

		// PolicyID is the unique identifier of the security policy
		PolicyID string

		// URLProtectionRuleID is the unique identifier of the URL protection rule
		URLProtectionRuleID int64
	}

	// GetURLProtectionRuleActionsResponse is returned from a call to GetURLProtectionRuleActions.
	GetURLProtectionRuleActionsResponse URLProtectionRuleActions

	// UpdateURLProtectionRuleActionsRequest is used to update the actions for a url protection rule.
	UpdateURLProtectionRuleActionsRequest struct {

		// ConfigID is the unique identifier of the security configuration
		ConfigID int64

		// ConfigVersion is the ConfigVersion number of the security configuration
		ConfigVersion int64

		// PolicyID is the unique identifier of the security policy
		PolicyID string

		// URLProtectionRuleID is the unique identifier of the URL protection rule
		URLProtectionRuleID int64

		// Body contains the URL protection rule actions to be updated
		Body URLProtectionRuleActions
	}

	// UpdateURLProtectionRuleActionsResponse is returned from a call to UpdateURLProtectionRuleActions.
	UpdateURLProtectionRuleActionsResponse URLProtectionRuleActions
)

// Validate validates a ListURLProtectionRulesActionsRequest.
func (v ListURLProtectionRulesActionsRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"ConfigID":      validation.Validate(v.ConfigID, validation.Required),
		"ConfigVersion": validation.Validate(v.ConfigVersion, validation.Required),
		"PolicyID":      validation.Validate(v.PolicyID, validation.Required),
	})
}

// Validate validates a GetURLProtectionRuleActionsRequest.
func (v GetURLProtectionRuleActionsRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"ConfigID":            validation.Validate(v.ConfigID, validation.Required),
		"ConfigVersion":       validation.Validate(v.ConfigVersion, validation.Required),
		"PolicyID":            validation.Validate(v.PolicyID, validation.Required),
		"URLProtectionRuleID": validation.Validate(v.URLProtectionRuleID, validation.Required),
	})
}

// Validate validates an UpdateURLProtectionRuleActions.
func (v URLProtectionRuleActions) Validate() error {
	return (validation.Errors{
		"MaxRateThresholdAction": validation.Validate(v.MaxRateThresholdAction, validation.Required),
	}).Filter()
}

// Validate validates an UpdateURLProtectionRuleActionRequest.
func (v UpdateURLProtectionRuleActionsRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"ConfigID":            validation.Validate(v.ConfigID, validation.Required),
		"ConfigVersion":       validation.Validate(v.ConfigVersion, validation.Required),
		"PolicyID":            validation.Validate(v.PolicyID, validation.Required),
		"URLProtectionRuleID": validation.Validate(v.URLProtectionRuleID, validation.Required),
		"Body":                validation.Validate(v.Body, validation.Required),
	})
}

func (p *appsec) ListURLProtectionRulesActions(ctx context.Context, params ListURLProtectionRulesActionsRequest) (*ListURLProtectionRulesActionsResponse, error) {
	logger := p.Log(ctx)
	logger.Debug("ListURLProtectionRulesActions")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStructValidation, err)
	}

	uri := fmt.Sprintf(
		"/appsec/v1/configs/%d/versions/%d/security-policies/%s/url-protections",
		params.ConfigID,
		params.ConfigVersion,
		params.PolicyID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ListURLProtectionRulesActions request: %w", err)
	}

	var result ListURLProtectionRulesActionsResponse
	resp, err := p.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("get url protection rules actions request failed: %w", err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &result, nil
}

func (p *appsec) GetURLProtectionRuleActions(ctx context.Context, params GetURLProtectionRuleActionsRequest) (*GetURLProtectionRuleActionsResponse, error) {
	logger := p.Log(ctx)
	logger.Debug("GetURLProtectionRuleActions")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStructValidation, err)
	}

	uri := fmt.Sprintf(
		"/appsec/v1/configs/%d/versions/%d/security-policies/%s/url-protections",
		params.ConfigID,
		params.ConfigVersion,
		params.PolicyID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GetURLProtectionRuleActions request: %w", err)
	}

	var result ListURLProtectionRulesActionsResponse
	resp, err := p.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("get url protection rule actions request failed: %w", err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	var filteredResult GetURLProtectionRuleActionsResponse
	for _, val := range result.URLProtectionRulesActions {
		if val.URLProtectionRuleID == params.URLProtectionRuleID {
			filteredResult.MaxRateThresholdAction = val.MaxRateThresholdAction
			filteredResult.LoadSheddingAction = val.LoadSheddingAction
			return &filteredResult, nil
		}
	}
	return nil, fmt.Errorf("incorrect URLProtectionRuleID %d or no actions found for the specified rule", params.URLProtectionRuleID)
}

func (p *appsec) UpdateURLProtectionRuleActions(ctx context.Context, params UpdateURLProtectionRuleActionsRequest) (*UpdateURLProtectionRuleActionsResponse, error) {
	logger := p.Log(ctx)
	logger.Debug("UpdateURLProtectionRuleActions")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStructValidation, err)
	}

	uri := fmt.Sprintf(
		"/appsec/v1/configs/%d/versions/%d/security-policies/%s/url-protections/%d",
		params.ConfigID,
		params.ConfigVersion,
		params.PolicyID,
		params.URLProtectionRuleID,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create UpdateURLProtectionRuleActions request: %w", err)
	}

	var result UpdateURLProtectionRuleActionsResponse
	resp, err := p.Exec(req, &result, params.Body)
	if err != nil {
		return nil, fmt.Errorf("update url protection rule action request failed: %w", err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &result, nil
}
