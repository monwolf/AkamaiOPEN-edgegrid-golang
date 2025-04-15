package mtlstruststore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v10/pkg/edgegriderr"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v10/pkg/session"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// CreateCASetRequest holds request body for CreateCASet.
	CreateCASetRequest struct {
		// CASetName is a descriptive name for the set.
		CASetName string `json:"caSetName"`
		// Description is an optional description for the set.
		Description string `json:"description"`
	}

	// CASetResponse contains response from create, list operations.
	CASetResponse struct {
		// AccountID is the ID of the account under which this CA set was created.
		AccountID string `json:"accountId"`
		// CASetID is a unique identifier representing the CA set.
		CASetID int64 `json:"caSetId"`
		// CASetLink is the hypermedia link to the CA set.
		CASetLink string `json:"caSetLink"`
		// CASetName is the name of the CA set.
		CASetName string `json:"caSetName"`
		// CASetStatus is the status of the CA set - NOT_DELETED, DELETING, DELETED.
		CASetStatus string `json:"caSetStatus"`
		// Description is a description of the CA set.
		Description string `json:"description"`
		// LatestVersionLink is the hypermedia link for newly created / cloned version in a CA set.
		LatestVersionLink *string `json:"latestVersionLink"`
		// LatestVersion is the version number for newly created / cloned version in a CA set.
		LatestVersion *int64 `json:"latestVersion"`
		// StagingVersionLink is the hypermedia link for the version of the CA set that is active on staging.
		// This field could be `nil` if no version of the CA set was activated on staging.
		StagingVersionLink *string `json:"stagingVersionLink"`
		// StagingVersion is the version number of the CA set that is active on staging.
		StagingVersion *int64 `json:"stagingVersion"`
		// ProductionVersionLink is the hypermedia link for the version of the CA set that is active on production.
		// This field could be `nil` if no version of the set was activated on production.
		ProductionVersionLink *string `json:"productionVersionLink"`
		// ProductionVersion is the version number of the CA set that is active on production.
		ProductionVersion *int64 `json:"productionVersion"`
		// VersionsLink is the hypermedia link to the list of versions in the CA set.
		VersionsLink string `json:"versionsLink"`
		// CreatedDate is the date the set was created.
		CreatedDate time.Time `json:"createdDate"`
		// CreatedBy is the user who created the set.
		CreatedBy string `json:"createdBy"`
		// DeletedDate is the date the CA set was deleted if the CA set has been archived, `nil` otherwise.
		DeletedDate *time.Time `json:"deletedDate"`
		// DeletedBy is the user who deleted the CA set if the CA set has been deleted, `nil` otherwise.
		DeletedBy *string `json:"deletedBy"`
	}

	// CreateCASetResponse contains response from CreateCASet.
	CreateCASetResponse CASetResponse

	// Network represents the network type: 'staging' or 'production'.
	Network string

	// ListCASetsRequest holds request body for ListCASets.
	ListCASetsRequest struct {
		// CASetName is the name prefix to filter out marching CA sets.
		CASetName string
		// ActivatedOn is the network type to filter out matching CA sets.
		// A CA set is included in the response if any version of it is active on that network.
		// The values that could be provided are `staging`, `production` or `staging,production`.
		// A CA set will not be included if it was created but none of its versions was ever activated.
		ActivatedOn Network
	}

	// ListCASetsResponse contains response from ListCASets.
	ListCASetsResponse struct {
		// CASets is a list of CA set objects with each object representing the details of one CA set.
		CASets []CASetResponse `json:"caSets"`
	}

	// GetCASetRequest holds request body for GetCASet.
	GetCASetRequest struct {
		// CASetID is a unique identifier representing the CA set.
		CASetID int64 `json:"caSetId"`
	}

	// GetCASetResponse contains response from GetCASet.
	GetCASetResponse CASetResponse

	// DeleteCASetRequest holds request body for DeleteCASet.
	DeleteCASetRequest struct {
		// CASetID is a unique identifier representing the CA set.
		CASetID int64 `json:"caSetId"`
	}
)

const (
	// NetworkStaging represents staging network.
	NetworkStaging Network = "staging"
	// NetworkProduction represents production network.
	NetworkProduction Network = "production"
	// NetworkStagingAndProduction represents staging and production networks.
	NetworkStagingAndProduction Network = "staging+production"
)

var (
	caSetNameRegex = regexp.MustCompile(`^([%.a-zA-Z0-9_-])+$`)

	// ErrCreateCASet is returned when the request to create a CA set fails.
	ErrCreateCASet = errors.New("create ca set failed")
	// ErrGetCASet is returned when the request to get a CA set fails.
	ErrGetCASet = errors.New("get ca set failed")
	// ErrListCASets is returned when the request to list CA sets fails.
	ErrListCASets = errors.New("list ca sets failed")
	// ErrDeleteCASet is returned when the request to delete a CA set fails.
	ErrDeleteCASet = errors.New("delete ca set failed")
)

// Validate validates CreateCASetRequest.
// Allowed characters are alphanumerics (a-z, A-Z, 0-9), underscore (_), hyphen (-), percent (%) and period (.) with no three consecutive periods (…).
// Length must be between 3 and 64 characters.
func (r CreateCASetRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"CASetName": validation.Validate(r.CASetName,
			validation.Required,
			validation.Length(3, 64),
			validation.Match(caSetNameRegex).Error("allowed characters are alphanumerics (a-z, A-Z, 0-9), underscore (_), hyphen (-), percent (%) and period (.)"),
			validateCASetName()),
	})
}

// Validate validates GetCASetRequest.
func (r GetCASetRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"CASetID": validation.Validate(r.CASetID, validation.Required),
	})
}

// Validate validates ListCASetsRequest.
func (r ListCASetsRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"CASetName": validation.Validate(r.CASetName,
			validation.Length(3, 64),
			validation.Match(caSetNameRegex).Error("allowed characters are alphanumerics (a-z, A-Z, 0-9), underscore (_), hyphen (-), percent (%) and period (.)"),
			validateCASetName()),
		"ActivatedOn": validation.Validate(r.ActivatedOn, r.ActivatedOn.Validate()),
	})
}

// Validate validates DeleteCASetsRequest.
func (r DeleteCASetRequest) Validate() error {
	return edgegriderr.ParseValidationErrors(validation.Errors{
		"CASetID": validation.Validate(r.CASetID, validation.Required),
	})
}

// Validate validates ActivationNetwork.
func (n Network) Validate() validation.InRule {
	return validation.In(NetworkStaging, NetworkProduction, NetworkStagingAndProduction).
		Error(fmt.Sprintf("value '%s' is invalid. Must be one of: '%s', '%s' or '%s'",
			n, NetworkStaging, NetworkProduction, NetworkStagingAndProduction))
}

func validateCASetName() validation.StringRule {
	return validation.NewStringRule(func(s string) bool {
		return !strings.Contains(s, "...")
	}, "CA Set name cannot contain three consecutive periods (...)")
}

func (m *mtlstruststore) CreateCASet(ctx context.Context, params CreateCASetRequest) (*CreateCASetResponse, error) {
	logger := m.Log(ctx)
	logger.Debug("CreateCASet")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrCreateCASet, ErrStructValidation, err)
	}

	uri, err := url.Parse("/mtls-edge-truststore/v2/ca-sets")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrCreateCASet, err)
	}

	var result CreateCASetResponse
	resp, err := m.Exec(req, &result, params)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrCreateCASet, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusCreated {
		return nil, m.Error(resp)
	}

	return &result, nil
}

func (m *mtlstruststore) GetCASet(ctx context.Context, params GetCASetRequest) (*GetCASetResponse, error) {
	logger := m.Log(ctx)
	logger.Debug("GetCASet")

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrGetCASet, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf("/mtls-edge-truststore/v2/ca-sets/%d", params.CASetID))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %s", ErrGetCASet, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrGetCASet, err)
	}

	var result GetCASetResponse
	resp, err := m.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrGetCASet, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, m.Error(resp)
	}

	return &result, nil
}

func (m *mtlstruststore) ListCASets(ctx context.Context, params ListCASetsRequest) (*ListCASetsResponse, error) {
	logger := m.Log(ctx)
	logger.Debug("ListCASets")

	params.ActivatedOn = Network(strings.ToLower(string(params.ActivatedOn)))

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", ErrListCASets, ErrStructValidation, err)
	}

	uri, err := url.Parse("/mtls-edge-truststore/v2/ca-sets")
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse url: %s", ErrListCASets, err)
	}
	q := uri.Query()
	if params.CASetName != "" {
		q.Add("caSetName", params.CASetName)
	}
	if params.ActivatedOn != "" {
		q.Add("activatedOn", string(params.ActivatedOn))
	}
	uri.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %s", ErrListCASets, err)
	}

	var result ListCASetsResponse
	resp, err := m.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrListCASets, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, m.Error(resp)
	}

	return &result, nil
}

func (m *mtlstruststore) DeleteCASet(ctx context.Context, params DeleteCASetRequest) error {
	logger := m.Log(ctx)
	logger.Debug("DeleteCASet")

	if err := params.Validate(); err != nil {
		return fmt.Errorf("%s: %w: %s", ErrDeleteCASet, ErrStructValidation, err)
	}

	uri, err := url.Parse(fmt.Sprintf("/mtls-edge-truststore/v2/ca-sets/%d", params.CASetID))
	if err != nil {
		return fmt.Errorf("%w: failed to parse url: %s", ErrDeleteCASet, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri.String(), nil)
	if err != nil {
		return fmt.Errorf("%w: failed to create request: %s", ErrDeleteCASet, err)
	}

	resp, err := m.Exec(req, nil)
	if err != nil {
		return fmt.Errorf("%w: request failed: %s", ErrDeleteCASet, err)
	}
	defer session.CloseResponseBody(resp)

	if resp.StatusCode != http.StatusAccepted {
		return m.Error(resp)
	}

	return nil
}
