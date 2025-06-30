package v0

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type (
	// Error is an apidefinitions error interface
	Error struct {
		Type            string       `json:"type"`
		Title           string       `json:"title"`
		Detail          string       `json:"detail"`
		Instance        string       `json:"instance,omitempty"`
		Status          int64        `json:"status,omitempty"`
		RequestInstance *string      `json:"requestInstance,omitempty"`
		Method          *string      `json:"method,omitempty"`
		RequestTime     *string      `json:"requestTime,omitempty"`
		BehaviorName    *string      `json:"behaviorName,omitempty"`
		ErrorLocation   *string      `json:"errorLocation,omitempty"`
		DomainPrefix    *string      `json:"domainPrefix,omitempty"`
		DomainSuffix    *string      `json:"domainSuffix,omitempty"`
		Severity        *string      `json:"severity,omitempty"`
		Field           *string      `json:"field,omitempty"`
		RejectedValue   *interface{} `json:"rejectedValue,omitempty"`
		AuthzRealm      *string      `json:"authzRealm,omitempty"`
		ServerIP        *string      `json:"serverIp,omitempty"`
		ClientIP        *string      `json:"clientIp,omitempty"`
		RequestID       *string      `json:"requestId,omitempty"`
		Network         *string      `json:"network,omitempty"`
		VersionNumber   *int64       `json:"versionNumber,omitempty"`
		EndpointID      *int64       `json:"endpointId,omitempty"`
		EndpointName    *string      `json:"endpointName,omitempty"`
		Errors          []Error      `json:"errors,omitempty"`
	}
)

// Error parses an error from the response
func (a *apidefinitions) Error(r *http.Response) error {
	var e Error

	var body []byte

	body, err := io.ReadAll(r.Body)
	if err != nil {
		a.Log(r.Request.Context()).Errorf("reading error response body: %s", err)
		e.Status = int64(r.StatusCode)
		e.Title = "Failed to read error body"
		e.Detail = err.Error()
		return &e
	}

	if err := json.Unmarshal(body, &e); err != nil {
		a.Log(r.Request.Context()).Errorf("could not unmarshal API error: %s", err)
		e.Title = "Failed to unmarshal error body"
		e.Detail = err.Error()
	}

	e.Status = int64(r.StatusCode)

	return &e
}

func (e *Error) Error() string {
	msg, err := json.MarshalIndent(e, "", "\t")
	if err != nil {
		return fmt.Sprintf("error marshaling API error: %s", err)
	}
	return fmt.Sprintf("API error: \n%s", msg)
}

// Is handles error comparisons
func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) {
		return false
	}

	if e == t {
		return true
	}

	if e.Status != t.Status {
		return false
	}

	return e.Error() == t.Error()
}
