package appsec

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v13/pkg/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test ListURLProtectionRulesActionsRequest Validate
func TestListURLProtectionRulesActionsRequest_Validate(t *testing.T) {
	tests := map[string]struct {
		req           ListURLProtectionRulesActionsRequest
		errorExpected bool
	}{
		"valid request - all fields populated": {
			req: ListURLProtectionRulesActionsRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				PolicyID:      "AAAA_81230",
			},
			errorExpected: false,
		},
		"missing ConfigID": {
			req: ListURLProtectionRulesActionsRequest{
				ConfigVersion: 15,
				PolicyID:      "AAAA_81230",
			},
			errorExpected: true,
		},
		"missing Version": {
			req: ListURLProtectionRulesActionsRequest{
				ConfigID: 43253,
				PolicyID: "AAAA_81230",
			},
			errorExpected: true,
		},
		"missing PolicyID": {
			req: ListURLProtectionRulesActionsRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
			},
			errorExpected: true,
		},
		"missing all required fields": {
			req:           ListURLProtectionRulesActionsRequest{},
			errorExpected: true,
		},
		"missing ConfigID and Version": {
			req: ListURLProtectionRulesActionsRequest{
				PolicyID: "AAAA_81230",
			},
			errorExpected: true,
		},
		"missing ConfigID and PolicyID": {
			req: ListURLProtectionRulesActionsRequest{
				ConfigVersion: 15,
			},
			errorExpected: true,
		},
		"missing Version and PolicyID": {
			req: ListURLProtectionRulesActionsRequest{
				ConfigID: 43253,
			},
			errorExpected: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.req.Validate()
			if test.errorExpected {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// Test GetURLProtectionRuleActionsRequest Validate
func TestGetURLProtectionRuleActionsRequest_Validate(t *testing.T) {
	tests := map[string]struct {
		req           GetURLProtectionRuleActionsRequest
		errorExpected bool
	}{
		"valid request - all fields populated": {
			req: GetURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
			},
			errorExpected: false,
		},
		"missing ConfigID": {
			req: GetURLProtectionRuleActionsRequest{
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing Version": {
			req: GetURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing PolicyID": {
			req: GetURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing URLProtectionRuleID": {
			req: GetURLProtectionRuleActionsRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				PolicyID:      "AAAA_81230",
			},
			errorExpected: true,
		},
		"missing all required fields": {
			req:           GetURLProtectionRuleActionsRequest{},
			errorExpected: true,
		},
		"missing ConfigID and Version": {
			req: GetURLProtectionRuleActionsRequest{
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing ConfigID and PolicyID": {
			req: GetURLProtectionRuleActionsRequest{
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing ConfigID and URLProtectionRuleID": {
			req: GetURLProtectionRuleActionsRequest{
				ConfigVersion: 15,
				PolicyID:      "AAAA_81230",
			},
			errorExpected: true,
		},
		"missing Version and PolicyID": {
			req: GetURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing Version and URLProtectionRuleID": {
			req: GetURLProtectionRuleActionsRequest{
				ConfigID: 43253,
				PolicyID: "AAAA_81230",
			},
			errorExpected: true,
		},
		"missing PolicyID and URLProtectionRuleID": {
			req: GetURLProtectionRuleActionsRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
			},
			errorExpected: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.req.Validate()
			if test.errorExpected {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// Test UpdateURLProtectionRuleActionsRequest Validate
func TestUpdateURLProtectionRuleActionsRequest_Validate(t *testing.T) {
	tests := map[string]struct {
		req           UpdateURLProtectionRuleActionsRequest
		errorExpected bool
	}{
		"valid request - all fields populated": {
			req: UpdateURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleActions{
					MaxRateThresholdAction: "alert",
					LoadSheddingAction:     "deny",
				},
			},
			errorExpected: false,
		},
		"valid request - missing MaxRateThresholdAction": {
			req: UpdateURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleActions{
					LoadSheddingAction: "deny",
				},
			},
			errorExpected: true,
		},
		"missing ConfigID": {
			req: UpdateURLProtectionRuleActionsRequest{
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing Version": {
			req: UpdateURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing PolicyID": {
			req: UpdateURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing URLProtectionRuleID": {
			req: UpdateURLProtectionRuleActionsRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				PolicyID:      "AAAA_81230",
			},
			errorExpected: true,
		},
		"missing all required fields": {
			req:           UpdateURLProtectionRuleActionsRequest{},
			errorExpected: true,
		},
		"missing ConfigID and Version": {
			req: UpdateURLProtectionRuleActionsRequest{
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing ConfigID and PolicyID": {
			req: UpdateURLProtectionRuleActionsRequest{
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing ConfigID and URLProtectionRuleID": {
			req: UpdateURLProtectionRuleActionsRequest{
				ConfigVersion: 15,
				PolicyID:      "AAAA_81230",
			},
			errorExpected: true,
		},
		"missing Version and PolicyID": {
			req: UpdateURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing Version and URLProtectionRuleID": {
			req: UpdateURLProtectionRuleActionsRequest{
				ConfigID: 43253,
				PolicyID: "AAAA_81230",
			},
			errorExpected: true,
		},
		"missing PolicyID and URLProtectionRuleID": {
			req: UpdateURLProtectionRuleActionsRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
			},
			errorExpected: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.req.Validate()
			if test.errorExpected {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// Test ListURLProtectionRulesActions.
func TestAppSec_ListURLProtectionRulesActions(t *testing.T) {
	result := ListURLProtectionRulesActionsResponse{}

	respData := compactJSON(loadFixtureBytes("testdata/TestURLProtectionActions/URLProtectionRulesActions.json"))
	err := json.Unmarshal([]byte(respData), &result)
	require.NoError(t, err)

	tests := map[string]struct {
		params           ListURLProtectionRulesActionsRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *ListURLProtectionRulesActionsResponse
		withError        error
		headers          http.Header
	}{
		"200 Success": {
			params: ListURLProtectionRulesActionsRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				PolicyID:      "AAAA_81230",
			},
			headers: http.Header{
				"Content-Type": []string{"application/json;charset=UTF-8"},
			},
			responseStatus:   http.StatusOK,
			responseBody:     respData,
			expectedResponse: &result,
			expectedPath:     "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections",
		},
		"400 bad request": {
			params: ListURLProtectionRulesActionsRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				PolicyID:      "AAAA_81230",
			},
			responseStatus: http.StatusBadRequest,
			responseBody:   badRequestResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/BAD-REQUEST",
				Title:      "Bad Request",
				Detail:     "The request could not be understood by the server due to malformed syntax.",
				StatusCode: http.StatusBadRequest,
			},
		},
		"403 Forbidden": {
			params: ListURLProtectionRulesActionsRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				PolicyID:      "AAAA_81230",
			},
			responseStatus: http.StatusForbidden,
			responseBody:   forbiddenResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec-resource/error-types/ACCESS-DENIED",
				Title:      "Forbidden",
				Detail:     "You do not have the necessary access to perform this operation or the requested resource cannot be modified",
				StatusCode: http.StatusForbidden,
			},
		},
		"404 Not Found": {
			params: ListURLProtectionRulesActionsRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				PolicyID:      "AAAA_81230",
			},
			responseStatus: http.StatusNotFound,
			responseBody:   notFoundResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/NOT-FOUND",
				Title:      "Not Found",
				Detail:     "The requested resource is not found",
				StatusCode: http.StatusNotFound,
			},
		},
		"500 internal server error": {
			params: ListURLProtectionRulesActionsRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				PolicyID:      "AAAA_81230",
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
			{
				"type": "internal_error",
				"title": "Internal Server Error",
				"detail": "Error creating zone"
			}`,
			expectedPath: "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections",
			withError: &Error{
				Type:       "internal_error",
				Title:      "Internal Server Error",
				Detail:     "Error creating zone",
				StatusCode: http.StatusInternalServerError,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				w.WriteHeader(test.responseStatus)
				if len(test.responseBody) > 0 {
					_, err := w.Write([]byte(test.responseBody))
					assert.NoError(t, err)
				}
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.ListURLProtectionRulesActions(
				session.ContextWithOptions(
					context.Background(),
					session.WithContextHeaders(test.headers)), test.params)
			if test.withError != nil {
				assert.True(t, errors.Is(err, test.withError), "want: %s; got: %s", test.withError, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

// Test GetURLProtectionRuleActions.
func TestAppSec_GetURLProtectionRuleActions(t *testing.T) {
	result := GetURLProtectionRuleActionsResponse{}

	respData := compactJSON(loadFixtureBytes("testdata/TestURLProtectionActions/URLProtectionRuleActions.json"))
	err := json.Unmarshal([]byte(respData), &result)
	require.NoError(t, err)

	tests := map[string]struct {
		params           GetURLProtectionRuleActionsRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *GetURLProtectionRuleActionsResponse
		withError        error
		headers          http.Header
	}{
		"200 Success": {
			params: GetURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
			},
			headers: http.Header{
				"Content-Type": []string{"application/json;charset=UTF-8"},
			},
			responseStatus:   http.StatusOK,
			responseBody:     compactJSON(loadFixtureBytes("testdata/TestURLProtectionActions/URLProtectionRulesActions.json")),
			expectedResponse: &result,
			expectedPath:     "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections",
		},
		"400 bad request": {
			params: GetURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 123,
			},
			responseStatus: http.StatusBadRequest,
			responseBody:   badRequestResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/BAD-REQUEST",
				Title:      "Bad Request",
				Detail:     "The request could not be understood by the server due to malformed syntax.",
				StatusCode: http.StatusBadRequest,
			},
		},
		"403 Forbidden": {
			params: GetURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 234,
			},
			responseStatus: http.StatusForbidden,
			responseBody:   forbiddenResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec-resource/error-types/ACCESS-DENIED",
				Title:      "Forbidden",
				Detail:     "You do not have the necessary access to perform this operation or the requested resource cannot be modified",
				StatusCode: http.StatusForbidden,
			},
		},
		"404 Not Found": {
			params: GetURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 234,
			},
			responseStatus: http.StatusNotFound,
			responseBody:   notFoundResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/NOT-FOUND",
				Title:      "Not Found",
				Detail:     "The requested resource is not found",
				StatusCode: http.StatusNotFound,
			},
		},
		"500 internal server error": {
			params: GetURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 234,
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
			{
				"type": "internal_error",
				"title": "Internal Server Error",
				"detail": "Error creating zone"
			}`,
			expectedPath: "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections",
			withError: &Error{
				Type:       "internal_error",
				Title:      "Internal Server Error",
				Detail:     "Error creating zone",
				StatusCode: http.StatusInternalServerError,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				w.WriteHeader(test.responseStatus)
				if len(test.responseBody) > 0 {
					_, err := w.Write([]byte(test.responseBody))
					assert.NoError(t, err)
				}
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.GetURLProtectionRuleActions(
				session.ContextWithOptions(
					context.Background(),
					session.WithContextHeaders(test.headers)), test.params)
			if test.withError != nil {
				assert.True(t, errors.Is(err, test.withError), "want: %s; got: %s", test.withError, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

// Test UpdateURLProtectionRulesAction.
func TestAppSec_UpdateURLProtectionRulesActions(t *testing.T) {
	result := UpdateURLProtectionRuleActionsResponse{}

	respData := compactJSON(loadFixtureBytes("testdata/TestURLProtectionActions/URLProtectionRuleActions.json"))
	err := json.Unmarshal([]byte(respData), &result)
	require.NoError(t, err)

	tests := map[string]struct {
		params           UpdateURLProtectionRuleActionsRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *UpdateURLProtectionRuleActionsResponse
		withError        error
		headers          http.Header
	}{
		"200 Success": {
			params: UpdateURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleActions{
					MaxRateThresholdAction: "alert",
					LoadSheddingAction:     "deny",
				},
			},
			headers: http.Header{
				"Content-Type": []string{"application/json;charset=UTF-8"},
			},
			responseStatus:   http.StatusOK,
			responseBody:     respData,
			expectedResponse: &result,
			expectedPath:     "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections/134644",
		},
		"400 bad request": {
			params: UpdateURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleActions{
					MaxRateThresholdAction: "alert",
					LoadSheddingAction:     "deny",
				},
			},
			responseStatus: http.StatusBadRequest,
			responseBody:   badRequestResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections/134644",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/BAD-REQUEST",
				Title:      "Bad Request",
				Detail:     "The request could not be understood by the server due to malformed syntax.",
				StatusCode: http.StatusBadRequest,
			},
		},
		"403 Forbidden": {
			params: UpdateURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleActions{
					MaxRateThresholdAction: "alert",
					LoadSheddingAction:     "deny",
				},
			},
			responseStatus: http.StatusForbidden,
			responseBody:   forbiddenResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections/134644",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec-resource/error-types/ACCESS-DENIED",
				Title:      "Forbidden",
				Detail:     "You do not have the necessary access to perform this operation or the requested resource cannot be modified",
				StatusCode: http.StatusForbidden,
			},
		},
		"404 Not Found": {
			params: UpdateURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleActions{
					MaxRateThresholdAction: "alert",
					LoadSheddingAction:     "deny",
				},
			},
			responseStatus: http.StatusNotFound,
			responseBody:   notFoundResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections/134644",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/NOT-FOUND",
				Title:      "Not Found",
				Detail:     "The requested resource is not found",
				StatusCode: http.StatusNotFound,
			},
		},
		"500 internal server error": {
			params: UpdateURLProtectionRuleActionsRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				PolicyID:            "AAAA_81230",
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleActions{
					MaxRateThresholdAction: "alert",
					LoadSheddingAction:     "deny",
				},
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
			{
				"type": "internal_error",
				"title": "Internal Server Error",
				"detail": "Error creating zone"
			}`,
			expectedPath: "/appsec/v1/configs/43253/versions/15/security-policies/AAAA_81230/url-protections/134644",
			withError: &Error{
				Type:       "internal_error",
				Title:      "Internal Server Error",
				Detail:     "Error creating zone",
				StatusCode: http.StatusInternalServerError,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPut, r.Method)
				w.WriteHeader(test.responseStatus)
				if len(test.responseBody) > 0 {
					_, err := w.Write([]byte(test.responseBody))
					assert.NoError(t, err)
				}
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.UpdateURLProtectionRuleActions(
				session.ContextWithOptions(
					context.Background(),
					session.WithContextHeaders(test.headers)), test.params)
			if test.withError != nil {
				assert.True(t, errors.Is(err, test.withError), "want: %s; got: %s", test.withError, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}
