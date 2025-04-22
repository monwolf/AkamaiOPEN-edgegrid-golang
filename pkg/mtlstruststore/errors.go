package mtlstruststore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v10/pkg/errs"
)

type (
	// Error is a mtlstruststore error interface.
	Error struct {
		Type        string         `json:"type"`
		Title       string         `json:"title"`
		Detail      string         `json:"detail"`
		Status      int64          `json:"status"`
		ContextInfo map[string]any `json:"contextInfo"`
		Instance    string         `json:"instance"`
		Errors      []ErrorItem    `json:"errors"`
	}

	// ErrorItem contains details about the error.
	ErrorItem struct {
		Detail  string `json:"detail"`
		Pointer string `json:"pointer"`
	}
)

const caSetNotFoundType = "/mtls-edge-truststore/v2/error-types/ca-set-not-found"
const caSetDeleteRequestInProgress = "/mtls-edge-truststore/v2/error-types/delete-ca-set-request-in-progress"
const caSetVersionDuplicate = "/mtls-edge-truststore/v2/error-types/duplicate-ca-set-version"
const caSetVersionNotFoundType = "/mtls-edge-truststore/v2/error-types/ca-set-version-not-found"
const caSetVersionLimitReached = "/mtls-edge-truststore/v2/error-types/ca-set-version-limit-reached"
const caSetVersionIsActive = "/mtls-edge-truststore/v2/error-types/ca-set-version-is-active"
const caSetVersionWasPreviouslyActive = "/mtls-edge-truststore/v2/error-types/ca-set-version-was-previously-active"
const certificateValidationFailedForCreate = "/mtls-edge-truststore/v2/error-types/certificate-validation-failure-create"
const certificateValidationFailedForUpdate = "/mtls-edge-truststore/v2/error-types/certificate-validation-failure-update"
const certificateLimitReached = "/mtls-edge-truststore/v2/error-types/certificate-limit-reached"

// ErrGetCASetNotFound is returned when the CA set was not found.
var ErrGetCASetNotFound = errors.New("ca set not found")

// ErrGetCASetVersionNotFound is returned when the CA set was not found.
var ErrGetCASetVersionNotFound = errors.New("ca set version not found")

// ErrCaSetDeleteRequestInProgress is returned when the CA set deletion request is in progress.
var ErrCaSetDeleteRequestInProgress = errors.New("delete ca set request in progress")

// ErrCaSetVersionIsActive is returned when the CA set Version is active on one or more networks.
var ErrCaSetVersionIsActive = errors.New("ca set version is currently active")

// ErrCaSetVersionWasPreviouslyActive is returned when the CA set Version was previously active on one or more networks.
var ErrCaSetVersionWasPreviouslyActive = errors.New("ca set version was previously active")

// ErrCertificateValidationFailedForCreate is returned during Create of the CA set Version if one or more certificates is invalid.
var ErrCertificateValidationFailedForCreate = errors.New("one or more certificates is invalid")

// ErrCertificateValidationFailedForUpdate is returned during Update of the CA set Version if one or more certificates is invalid.
var ErrCertificateValidationFailedForUpdate = errors.New("one or more certificates is invalid")

// ErrCertificateLimitReached is returned when the count of certificates submitted in the request body exceeds the limit allowed for the Version.
var ErrCertificateLimitReached = errors.New("submitted certificates exceed the maximum allowed certificates limit")

// ErrCaSetVersionLimitReached is returned when the number of ca set versions has reached the limit.
var ErrCaSetVersionLimitReached = errors.New("maximum allowed ca set version's limit has been reached")

// ErrCaSetVersionIsDuplicate is returned when a version with same certificates exists in the ca set.
var ErrCaSetVersionIsDuplicate = errors.New("a version with same certificates exists in the ca set")

// Error parses an error from the response.
func (m *mtlstruststore) Error(r *http.Response) error {
	var e Error
	var body []byte
	body, err := io.ReadAll(r.Body)
	if err != nil {
		m.Log(r.Request.Context()).Errorf("reading error response body: %s", err)
		e.Status = int64(r.StatusCode)
		e.Title = "Failed to read error body"
		e.Detail = err.Error()
		return &e
	}

	if err := json.Unmarshal(body, &e); err != nil {
		m.Log(r.Request.Context()).Errorf("could not unmarshal API error: %s", err)
		e.Title = "Failed to unmarshal error body. mTLS Truststore API failed. Check details for more information."
		e.Detail = errs.UnescapeContent(string(body))
	}

	e.Status = int64(r.StatusCode)

	return &e
}

// Error returns a string formatted using a given title, type, and detail information.
func (e *Error) Error() string {
	msg, err := json.MarshalIndent(e, "", "\t")
	if err != nil {
		return fmt.Sprintf("error marshaling API error: %s", err)
	}
	return fmt.Sprintf("API error: \n%s", msg)
}

// Is handles error comparisons.
func (e *Error) Is(target error) bool {
	if errors.Is(target, ErrGetCASetNotFound) {
		return e.Status == http.StatusNotFound && e.Type == caSetNotFoundType
	}

	if errors.Is(target, ErrGetCASetVersionNotFound) {
		return e.Status == http.StatusNotFound && e.Type == caSetVersionNotFoundType
	}

	if errors.Is(target, ErrCaSetDeleteRequestInProgress) {
		return e.Status == http.StatusConflict && e.Type == caSetDeleteRequestInProgress
	}

	if errors.Is(target, ErrCaSetVersionIsActive) {
		return e.Status == http.StatusUnprocessableEntity && e.Type == caSetVersionIsActive
	}

	if errors.Is(target, ErrCaSetVersionWasPreviouslyActive) {
		return e.Status == http.StatusUnprocessableEntity && e.Type == caSetVersionWasPreviouslyActive
	}

	if errors.Is(target, ErrCertificateValidationFailedForCreate) {
		return e.Status == http.StatusBadRequest && e.Type == certificateValidationFailedForCreate
	}

	if errors.Is(target, ErrCertificateValidationFailedForUpdate) {
		return e.Status == http.StatusBadRequest && e.Type == certificateValidationFailedForUpdate
	}

	if errors.Is(target, ErrCertificateLimitReached) {
		return e.Status == http.StatusUnprocessableEntity && e.Type == certificateLimitReached
	}

	if errors.Is(target, ErrCaSetVersionLimitReached) {
		return e.Status == http.StatusUnprocessableEntity && e.Type == caSetVersionLimitReached
	}

	if errors.Is(target, ErrCaSetVersionIsDuplicate) {
		return e.Status == http.StatusUnprocessableEntity && e.Type == caSetVersionDuplicate
	}

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
