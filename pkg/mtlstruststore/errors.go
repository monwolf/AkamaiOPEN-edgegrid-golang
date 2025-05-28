package mtlstruststore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/errs"
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
		Detail      string         `json:"detail"`
		Pointer     string         `json:"pointer"`
		ContextInfo map[string]any `json:"contextInfo"`
	}
)

const (
	caSetNotFoundType                    = "/mtls-edge-truststore/v2/error-types/ca-set-not-found"
	caSetActivationNotFoundType          = "/mtls-edge-truststore/v2/error-types/activation-or-deactivation-request-not-found"
	caSetDeleteRequestInProgress         = "/mtls-edge-truststore/v2/error-types/delete-ca-set-request-in-progress"
	caSetVersionDuplicate                = "/mtls-edge-truststore/v2/error-types/duplicate-ca-set-version"
	caSetVersionNotFoundType             = "/mtls-edge-truststore/v2/error-types/ca-set-version-not-found"
	caSetVersionLimitReached             = "/mtls-edge-truststore/v2/error-types/ca-set-version-limit-reached"
	caSetVersionIsActive                 = "/mtls-edge-truststore/v2/error-types/ca-set-version-is-active"
	caSetVersionWasPreviouslyActive      = "/mtls-edge-truststore/v2/error-types/ca-set-version-was-previously-active"
	certificateValidationFailedForCreate = "/mtls-edge-truststore/v2/error-types/certificate-validation-failure-create"
	certificateValidationFailedForUpdate = "/mtls-edge-truststore/v2/error-types/certificate-validation-failure-update"
	certificateLimitReached              = "/mtls-edge-truststore/v2/error-types/certificate-limit-reached"
	caSetBoundToSlotInCPS                = "/mtls-edge-truststore/v2/error-types/ca-set-bound-to-slot-in-cps"
	caSetBoundToHostname                 = "/mtls-edge-truststore/v2/error-types/ca-set-bound-to-hostname"
	anotherActivationInProgress          = "/mtls-edge-truststore/v2/error-types/another-activation-request-in-progress-in-the-ca-set"
	anotherDeactivationInProgress        = "/mtls-edge-truststore/v2/error-types/another-deactivation-request-in-progress-in-the-ca-set"
	caSetVersionNotActiveOnNetwork       = "/mtls-edge-truststore/v2/error-types/ca-set-version-not-active-on-network"
	fetchAssociationsTimeout             = "/mtls-edge-truststore/v2/error-types/cannot-get-ca-set-associations-timeout"
	missingCaCertVersion                 = "/mtls-edge-truststore/v2/error-types/missing-caset-version"
	caSetNameNotUnique                   = "/mtls-edge-truststore/v2/error-types/ca-set-name-is-not-unique"
	caSetLimitReached                    = "/mtls-edge-truststore/v2/error-types/ca-set-limit-reached"
	noActiveCertDeletions                = "/mtls-edge-truststore/v2/error-types/no-active-cert-deletions"
	certValidationFailure                = "/mtls-edge-truststore/v2/error-types/certificate-validation-failure"
)

var (
	// ErrGetCASetNotFound is returned when the CA set was not found.
	ErrGetCASetNotFound = errors.New("ca set not found")

	// ErrGetCASetVersionNotFound is returned when the CA set was not found.
	ErrGetCASetVersionNotFound = errors.New("ca set version not found")

	// ErrGetCASetActivationNotFound is returned when the CA set activation was not found.
	ErrGetCASetActivationNotFound = errors.New("ca set activation not found")

	// ErrCASetDeleteRequestInProgress is returned when the CA set deletion request is in progress.
	ErrCASetDeleteRequestInProgress = errors.New("delete ca set request in progress")

	// ErrCASetVersionIsActive is returned when the CA set version is active on one or more networks.
	ErrCASetVersionIsActive = errors.New("ca set version is currently active")

	// ErrCASetVersionWasPreviouslyActive is returned when the CA set version was previously active on one or more networks.
	ErrCASetVersionWasPreviouslyActive = errors.New("ca set version was previously active")

	// ErrCertificateValidationFailedForCreate is returned during Create of the CA set Version if one or more certificates is invalid.
	ErrCertificateValidationFailedForCreate = errors.New("one or more certificates is invalid")

	// ErrCertificateValidationFailedForUpdate is returned during Update of the CA set Version if one or more certificates is invalid.
	ErrCertificateValidationFailedForUpdate = errors.New("one or more certificates is invalid")

	// ErrCertificateLimitReached is returned when the count of certificates submitted in the request body exceeds the limit allowed for the Version.
	ErrCertificateLimitReached = errors.New("submitted certificates exceed the maximum allowed certificates limit")

	// ErrCaSetVersionLimitReached is returned when the number of ca set versions has reached the limit.
	ErrCaSetVersionLimitReached = errors.New("maximum allowed ca set version's limit has been reached")

	// ErrCaSetVersionIsDuplicate is returned when a version with same certificates exists in the ca set.
	ErrCaSetVersionIsDuplicate = errors.New("a version with same certificates exists in the ca set")

	// ErrCASetBoundToSlotInCPS is returned when the CA set is bound to a slot in CPS.
	ErrCASetBoundToSlotInCPS = errors.New("ca set bound to slot in CPS")

	// ErrCASetBoundToHostname is returned when the CA set is bound to a hostname.
	ErrCASetBoundToHostname = errors.New("ca set bound to hostname")

	// ErrAnotherActivationInProgress is returned when another activation request is in progress for the CA set.
	ErrAnotherActivationInProgress = errors.New("another activation request in progress in the ca set")

	// ErrAnotherDeactivationInProgress is returned when another deactivation request is in progress in the CA set.
	ErrAnotherDeactivationInProgress = errors.New("another deactivation request in progress in the ca set")

	// ErrCASetVersionNotActiveOnNetwork is returned when the CA set version is not active on the network.
	ErrCASetVersionNotActiveOnNetwork = errors.New("ca set version not active on network")

	// ErrFetchAssociationsTimeout is returned when ListCASetAssociations fails on timeout.
	ErrFetchAssociationsTimeout = errors.New("fetching associations for ca set got timed out")

	// ErrMissingCaCertVersion is returned when attempting to clone a ca set without any version.
	ErrMissingCaCertVersion = errors.New("ca set does not contain any version")

	// ErrCaSetNameNotUnique is returned when provided ca set name already exists.
	ErrCaSetNameNotUnique = errors.New("ca set name is not unique")

	// ErrCASetLimitReached is returned when ca set limit is reached.
	ErrCASetLimitReached = errors.New("reached ca set limit")

	// ErrNoActiveCertDeletions is returned when attempting to check deletion status of CA Set that was not requested for delete.
	ErrNoActiveCertDeletions = errors.New("no active ca set deletion")

	// ErrCertValidationFailure is returned when certificates provided in ValidateCertificates are not valid.
	ErrCertValidationFailure = errors.New("certificates validation failed")
)

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
//
//nolint:gocyclo
func (e *Error) Is(target error) bool {
	if errors.Is(target, ErrGetCASetNotFound) {
		return e.Status == http.StatusNotFound && e.Type == caSetNotFoundType
	}

	if errors.Is(target, ErrGetCASetVersionNotFound) {
		return e.Status == http.StatusNotFound && e.Type == caSetVersionNotFoundType
	}

	if errors.Is(target, ErrGetCASetActivationNotFound) {
		return e.Status == http.StatusNotFound && e.Type == caSetActivationNotFoundType
	}

	if errors.Is(target, ErrGetCASetVersionNotFound) {
		return e.Status == http.StatusNotFound && e.Type == caSetVersionNotFoundType
	}

	if errors.Is(target, ErrCASetDeleteRequestInProgress) {
		return e.Status == http.StatusConflict && e.Type == caSetDeleteRequestInProgress
	}

	if errors.Is(target, ErrCASetVersionIsActive) {
		return e.Status == http.StatusUnprocessableEntity && e.Type == caSetVersionIsActive
	}

	if errors.Is(target, ErrCASetVersionWasPreviouslyActive) {
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

	if errors.Is(target, ErrCASetBoundToSlotInCPS) {
		return e.Status == http.StatusConflict && e.Type == caSetBoundToSlotInCPS
	}

	if errors.Is(target, ErrCASetBoundToHostname) {
		return e.Status == http.StatusConflict && e.Type == caSetBoundToHostname
	}

	if errors.Is(target, ErrAnotherActivationInProgress) {
		return e.Status == http.StatusConflict && e.Type == anotherActivationInProgress
	}

	if errors.Is(target, ErrAnotherDeactivationInProgress) {
		return e.Status == http.StatusConflict && e.Type == anotherDeactivationInProgress
	}

	if errors.Is(target, ErrCASetVersionNotActiveOnNetwork) {
		return e.Status == http.StatusConflict && e.Type == caSetVersionNotActiveOnNetwork
	}

	if errors.Is(target, ErrFetchAssociationsTimeout) {
		return e.Status == http.StatusGatewayTimeout && e.Type == fetchAssociationsTimeout
	}

	if errors.Is(target, ErrMissingCaCertVersion) {
		return e.Status == http.StatusBadRequest && e.Type == missingCaCertVersion
	}

	if errors.Is(target, ErrCaSetNameNotUnique) {
		return e.Status == http.StatusConflict && e.Type == caSetNameNotUnique
	}

	if errors.Is(target, ErrCASetLimitReached) {
		return e.Status == http.StatusUnprocessableEntity && e.Type == caSetLimitReached
	}

	if errors.Is(target, ErrNoActiveCertDeletions) {
		return e.Status == http.StatusBadRequest && e.Type == noActiveCertDeletions
	}

	if errors.Is(target, ErrCertValidationFailure) {
		return e.Status == http.StatusBadRequest && e.Type == certValidationFailure
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
