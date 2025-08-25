package apidefinitions

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

type (
	// SearchResourceOperationsResponse represents the response structure for searching resource operations
	SearchResourceOperationsResponse struct {
		APIEndpoints []APIEndpoint `json:"apiEndPoints"`
		Operations   []Operation   `json:"operations"`
		Resources    []Resource    `json:"resources"`
	}

	// APIEndpoint represents the structure of an API endpoint
	APIEndpoint struct {
		APIEndpointHosts  []string       `json:"apiEndPointHosts"`
		APIEndpointID     int64          `json:"apiEndPointId"`
		APIEndpointName   string         `json:"apiEndPointName"`
		BasePath          string         `json:"basePath"`
		CaseSensitive     bool           `json:"caseSensitive"`
		Link              string         `json:"link"`
		ProductionVersion *VersionDetail `json:"productionVersion"`
		StagingVersion    *VersionDetail `json:"stagingVersion"`
	}

	// VersionDetail represents the version details of an API endpoint
	VersionDetail struct {
		Status        string `json:"status"`
		Timestamp     string `json:"timestamp"`
		VersionNumber int64  `json:"versionNumber"`
	}

	// Operation represents the structure of an operation
	Operation struct {
		APIEndpointID      int64               `json:"apiEndPointId"`
		APIResourceID      int64               `json:"apiResourceId"`
		APIResourceLogicID int64               `json:"apiResourceLogicId"`
		Conditions         []Condition         `json:"conditions,omitempty"`
		Link               string              `json:"link"`
		Metadata           OperationMetadata   `json:"metadata"`
		Method             string              `json:"method"`
		OperationID        string              `json:"operationId"`
		OperationName      string              `json:"operationName"`
		OperationPurpose   string              `json:"operationPurpose"`
		OperationParameter *OperationParameter `json:"operationParameter,omitempty"`
	}

	// Condition represents a condition in an operation
	Condition struct {
		APIParameterID int64  `json:"apiParameterId"`
		Value          string `json:"value,omitempty"`
	}

	// OperationMetadata represents metadata for an operation
	OperationMetadata struct {
		IsActive bool `json:"isActive"`
	}

	// OperationParameter represents parameters for an operation
	OperationParameter struct {
		Username ParameterDetail `json:"username"`
	}

	// ParameterDetail represents details of a parameter
	ParameterDetail struct {
		ParameterID  int64       `json:"parameterId"`
		UsedForLogin interface{} `json:"usedForLogin"`
	}

	// Resource represents the structure of a resource
	Resource struct {
		APIEndpointID      int64            `json:"apiEndPointId"`
		APIResourceID      int64            `json:"apiResourceId"`
		APIResourceLogicID int64            `json:"apiResourceLogicId"`
		APIResourceMethods []ResourceMethod `json:"apiResourceMethods"`
		APIResourceName    string           `json:"apiResourceName"`
		CreateDate         string           `json:"createDate"`
		CreatedBy          string           `json:"createdBy"`
		Link               string           `json:"link"`
		LockVersion        int              `json:"lockVersion"`
		Metadata           ResourceMetadata `json:"metadata"`
		ResourcePath       string           `json:"resourcePath"`
		UpdateDate         string           `json:"updateDate"`
		UpdatedBy          string           `json:"updatedBy"`
	}

	// ResourceMethod represents a method in a resource
	ResourceMethod struct {
		APIParameters            []APIParameter `json:"apiParameters"`
		APIResourceMethod        string         `json:"apiResourceMethod"`
		APIResourceMethodID      int64          `json:"apiResourceMethodId"`
		APIResourceMethodLogicID int64          `json:"apiResourceMethodLogicId"`
		MethodRestrictions       interface{}    `json:"methodRestrictions"`
	}

	// ResourceMetadata represents metadata for a resource
	ResourceMetadata struct {
		MethodsEnabled        int `json:"methodsEnabled"`
		MethodsWithOperations int `json:"methodsWithOperations"`
		OperationCount        int `json:"operationCount"`
	}
)

var (
	// ErrSearchResourceAndOperations is returned in case an error occurs on SearchResourceAndOperations operation
	ErrSearchResourceAndOperations = errors.New("list resources and operations")
)

func (a *apidefinitions) SearchResourceOperations(ctx context.Context) (*SearchResourceOperationsResponse, error) {
	logger := a.Log(ctx)
	logger.Debug("Search operations")

	uri := "/api-definitions/v2/search-operations"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to search request: %s", ErrSearchResourceAndOperations, err)
	}

	var result SearchResourceOperationsResponse
	resp, err := a.Exec(req, &result)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %s", ErrSearchResourceAndOperations, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %w", ErrSearchResourceAndOperations, a.Error(resp))
	}
	return &result, nil
}
