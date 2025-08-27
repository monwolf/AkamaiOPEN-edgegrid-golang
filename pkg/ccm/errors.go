// Package ccm provides access to the Akamai CCM API.
package ccm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/errs"
)

type (
	// Error is a CCM error interface.
	Error struct {
		Type     string `json:"type"`
		Title    string `json:"title"`
		Status   int    `json:"status"`
		Detail   string `json:"detail"`
		Instance string `json:"instance"`

		CertificateIdentifier      string `json:"certificateIdentifier,omitempty"`
		CertificateIdentifierValue string `json:"certificateIdentifierValue,omitempty"`
		Explanation                string `json:"explanation,omitempty"`
		InvalidParameterValue      string `json:"invalidParameterValue,omitempty"`
		ParameterName              string `json:"parameterName,omitempty"`
	}
)

// Error parses an error from the CCM API response.
func (m *ccm) Error(r *http.Response) error {
	var e Error
	var body []byte
	body, err := io.ReadAll(r.Body)
	if err != nil {
		m.Log(r.Request.Context()).Errorf("reading error response body: %s", err)
		e.Status = r.StatusCode
		e.Title = "Failed to read error body"
		e.Detail = err.Error()
		return &e
	}

	if err := json.Unmarshal(body, &e); err != nil {
		m.Log(r.Request.Context()).Errorf("could not unmarshal API error: %s", err)
		e.Title = "Failed to unmarshal error body. CCM API failed. Check details for more information."
		e.Detail = errs.UnescapeContent(string(body))
	}

	e.Status = r.StatusCode

	return &e
}

// Error returns the string representation of the error.
func (e *Error) Error() string {
	msg, err := json.MarshalIndent(e, "", "\t")
	if err != nil {
		return fmt.Sprintf("error marshaling API error: %s ", err)
	}
	return fmt.Sprintf("API error: \n%s", msg)
}

// Is handles error comparisons.
func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) {
		return false
	}

	ignoreType := t.Type == ""
	ignoreStatus := t.Status == 0
	ignoreTitle := t.Title == ""
	matchType := t.Type == e.Type
	matchStatus := t.Status == e.Status
	matchTitle := t.Title == e.Title

	return (matchType || ignoreType) &&
		(matchStatus || ignoreStatus) &&
		(matchTitle || ignoreTitle)
}
