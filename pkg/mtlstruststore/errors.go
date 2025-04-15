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

// ErrGetCASetNotFound is returned when the CA set was not found.
var ErrGetCASetNotFound = errors.New("ca set not found")

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
