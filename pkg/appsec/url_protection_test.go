package appsec

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var badRequestResp = `
{
    "type": "https://problems.luna.akamaiapis.net/appsec/error-types/BAD-REQUEST",
    "title": "Bad Request",
    "detail": "The request could not be understood by the server due to malformed syntax.",
	"status": 400
}`

var forbiddenResp = `
{
  "detail": "You do not have the necessary access to perform this operation or the requested resource cannot be modified",
  "status": 403,
  "title": "Forbidden",
  "type": "https://problems.luna.akamaiapis.net/appsec-resource/error-types/ACCESS-DENIED"
}`

var notFoundResp = `
{
  "detail": "The requested resource is not found",
  "status": 404,
  "title": "Not Found",
  "type": "https://problems.luna.akamaiapis.net/appsec/error-types/NOT-FOUND"
}`

// Test GET URLProtectionRules
func TestAppSec_ListURLProtectionRules(t *testing.T) {

	result := ListURLProtectionRulesResponse{}

	respData := compactJSON(loadFixtureBytes("testdata/TestURLProtection/URLProtectionRules.json"))
	err := json.Unmarshal([]byte(respData), &result)
	require.NoError(t, err)

	tests := map[string]struct {
		params           ListURLProtectionRulesRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *ListURLProtectionRulesResponse
		withError        error
		headers          http.Header
	}{
		"200 OK": {
			params: ListURLProtectionRulesRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
			},
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			responseStatus:   http.StatusOK,
			responseBody:     string(respData),
			expectedPath:     "/appsec/v1/configs/43253/versions/15/url-protections",
			expectedResponse: &result,
		},
		"400 bad request": {
			params: ListURLProtectionRulesRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
			},
			headers:        http.Header{},
			responseStatus: http.StatusBadRequest,
			responseBody:   badRequestResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/BAD-REQUEST",
				Title:      "Bad Request",
				Detail:     "The request could not be understood by the server due to malformed syntax.",
				StatusCode: http.StatusBadRequest,
			},
		},
		"403 Forbidden": {
			params: ListURLProtectionRulesRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
			},
			headers:        http.Header{},
			responseStatus: http.StatusForbidden,
			responseBody:   forbiddenResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec-resource/error-types/ACCESS-DENIED",
				Title:      "Forbidden",
				Detail:     "You do not have the necessary access to perform this operation or the requested resource cannot be modified",
				StatusCode: http.StatusForbidden,
			},
		},
		"404 Not Found": {
			params: ListURLProtectionRulesRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
			},
			headers:        http.Header{},
			responseStatus: http.StatusNotFound,
			responseBody:   notFoundResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/NOT-FOUND",
				Title:      "Not Found",
				Detail:     "The requested resource is not found",
				StatusCode: http.StatusNotFound,
			},
		},
		"500 internal server error": {
			params: ListURLProtectionRulesRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
			},
			headers:        http.Header{},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
				{
					"type": "internal_error",
					"title": "Internal Server Error",
					"detail": "Error fetching propertys",
					"status": 500
				}`,
			expectedPath: "/appsec/v1/configs/43253/versions/15/url-protections",
			withError: &Error{
				Type:       "internal_error",
				Title:      "Internal Server Error",
				Detail:     "Error fetching propertys",
				StatusCode: http.StatusInternalServerError,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodGet, r.Method)
				w.WriteHeader(test.responseStatus)
				_, err := w.Write([]byte(test.responseBody))
				assert.NoError(t, err)
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.ListURLProtectionRules(
				session.ContextWithOptions(
					context.Background(),
					session.WithContextHeaders(test.headers),
				),
				test.params)
			if test.withError != nil {
				assert.True(t, errors.Is(err, test.withError), "want: %s; got: %s", test.withError, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

// Test GET URLProtectionRule
func TestAppSec_GetURLProtectionRule(t *testing.T) {

	result := GetURLProtectionRuleResponse{}

	respData := compactJSON(loadFixtureBytes("testdata/TestURLProtection/URLProtectionRule.json"))
	err := json.Unmarshal([]byte(respData), &result)
	require.NoError(t, err)

	tests := map[string]struct {
		params           GetURLProtectionRuleRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *GetURLProtectionRuleResponse
		withError        error
	}{
		"200 OK": {
			params: GetURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			responseStatus:   http.StatusOK,
			responseBody:     respData,
			expectedPath:     "/appsec/v1/configs/43253/versions/15/url-protections/134644",
			expectedResponse: &result,
		},
		"400 bad request": {
			params: GetURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			responseStatus: http.StatusBadRequest,
			responseBody:   badRequestResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections/134644",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/BAD-REQUEST",
				Title:      "Bad Request",
				Detail:     "The request could not be understood by the server due to malformed syntax.",
				StatusCode: http.StatusBadRequest,
			},
		},
		"403 Forbidden": {
			params: GetURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			responseStatus: http.StatusForbidden,
			responseBody:   forbiddenResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections/134644",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec-resource/error-types/ACCESS-DENIED",
				Title:      "Forbidden",
				Detail:     "You do not have the necessary access to perform this operation or the requested resource cannot be modified",
				StatusCode: http.StatusForbidden,
			},
		},
		"404 Not Found": {
			params: GetURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			responseStatus: http.StatusNotFound,
			responseBody:   notFoundResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections/134644",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/NOT-FOUND",
				Title:      "Not Found",
				Detail:     "The requested resource is not found",
				StatusCode: http.StatusNotFound,
			},
		},
		"500 internal server error": {
			params: GetURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
			{
				"type": "internal_error",
				"title": "Internal Server Error",
				"detail": "Error fetching match target"
			}`,
			expectedPath: "/appsec/v1/configs/43253/versions/15/url-protections/134644",
			withError: &Error{
				Type:       "internal_error",
				Title:      "Internal Server Error",
				Detail:     "Error fetching match target",
				StatusCode: http.StatusInternalServerError,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodGet, r.Method)
				w.WriteHeader(test.responseStatus)
				_, err := w.Write([]byte(test.responseBody))
				assert.NoError(t, err)
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.GetURLProtectionRule(context.Background(), test.params)
			if test.withError != nil {
				assert.True(t, errors.Is(err, test.withError), "want: %s; got: %s", test.withError, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

// Test Create URLProtectionRule with Hostname Paths and APIDefinitions Separately
func TestAppSec_CreateURLProtectionRuleHostnamePaths(t *testing.T) {

	resultHostnamePath := CreateURLProtectionRuleResponse{}
	resultAPIDefinition := CreateURLProtectionRuleResponse{}

	respDataForHostnamePath := compactJSON(loadFixtureBytes("testdata/TestURLProtection/URLProtectionRuleHostnamePaths.json"))
	err := json.Unmarshal([]byte(respDataForHostnamePath), &resultHostnamePath)
	require.NoError(t, err)

	respDataForAPIDefinition := compactJSON(loadFixtureBytes("testdata/TestURLProtection/URLProtectionRuleApiDefinitions.json"))
	err = json.Unmarshal([]byte(respDataForAPIDefinition), &resultAPIDefinition)
	require.NoError(t, err)

	tests := map[string]struct {
		params           CreateURLProtectionRuleRequest
		prop             *CreateURLProtectionRuleRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *CreateURLProtectionRuleResponse
		withError        error
		headers          http.Header
	}{

		"201 Created with HostnamePaths": {
			params: CreateURLProtectionRuleRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 400,
					HostnamePaths: []HostnamePath{
						{
							Hostname: "custom.com",
							Paths:    []string{"/asd", "/my-test-path"},
						},
					},
					Categories: []Category{
						{
							Type: "BOTS",
						},
						{
							Type:          "CLIENT_LIST",
							PositiveMatch: func() *bool { b := true; return &b }(),
							ListIDs: []string{"12345_10CLIENTLIST",
								"54321_123"},
						},
					},
					BypassCondition: &BypassCondition{
						AtomicConditions: []AtomicCondition{
							{
								Type: "NetworkListCondition",
								Values: []string{
									"12345_10CLIENTLIST",
									"54321_123",
								},
							},
							{
								Type: "RequestHeaderCondition",
								Names: []string{
									"my-custom-header",
								},
								NameWildcard: func() *bool { b := true; return &b }(),
								Values: []string{
									"my-custom-value",
								},
								ValueCase:     func() *bool { b := false; return &b }(),
								ValueWildcard: func() *bool { b := false; return &b }(),
							},
						},
					},
				},
			},
			headers: http.Header{
				"Content-Type": []string{"application/json;charset=UTF-8"},
			},
			responseStatus:   http.StatusCreated,
			responseBody:     respDataForHostnamePath,
			expectedResponse: &resultHostnamePath,
			expectedPath:     "/appsec/v1/configs/43253/versions/15/url-protections",
		},
		"201 Created with APIDefinitions": {
			params: CreateURLProtectionRuleRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 195,
					APIDefinitions: []APIDefinition{
						{
							APIDefinitionID:    3216157,
							DefinedResources:   true,
							ResourceIDs:        []int64{},
							UndefinedResources: true,
						},
					},
					Categories: []Category{
						{
							Type: "BOTS",
						},
						{
							Type:          "CLIENT_LIST",
							PositiveMatch: func() *bool { b := true; return &b }(),
							ListIDs: []string{"12345_10CLIENTLIST",
								"54321_123"},
						},
					},
					BypassCondition: &BypassCondition{
						AtomicConditions: []AtomicCondition{
							{
								Type: "NetworkListCondition",
								Values: []string{
									"12345_10CLIENTLIST",
									"54321_123",
								},
							},
							{
								Type: "RequestHeaderCondition",
								Names: []string{
									"my-custom-header",
								},
								NameWildcard: func() *bool { b := true; return &b }(),
								Values: []string{
									"my-custom-value",
								},
								ValueCase:     func() *bool { b := false; return &b }(),
								ValueWildcard: func() *bool { b := false; return &b }(),
							},
						},
					},
				},
			},
			headers: http.Header{
				"Content-Type": []string{"application/json;charset=UTF-8"},
			},
			responseStatus:   http.StatusCreated,
			responseBody:     respDataForAPIDefinition,
			expectedResponse: &resultAPIDefinition,
			expectedPath:     "/appsec/v1/configs/43253/versions/15/url-protections",
		},
		"400 bad request": {
			params: CreateURLProtectionRuleRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 200,
					HostnamePaths: []HostnamePath{
						{
							Hostname: "custom.com",
							Paths:    []string{"/asd", "/my-test-path"},
						},
					},
				},
			},
			responseStatus: http.StatusBadRequest,
			responseBody:   badRequestResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/BAD-REQUEST",
				Title:      "Bad Request",
				Detail:     "The request could not be understood by the server due to malformed syntax.",
				StatusCode: http.StatusBadRequest,
			},
		},
		"403 Forbidden": {
			params: CreateURLProtectionRuleRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 200,
					HostnamePaths: []HostnamePath{
						{
							Hostname: "custom.com",
							Paths:    []string{"/asd", "/my-test-path"},
						},
					},
				},
			},
			responseStatus: http.StatusForbidden,
			responseBody:   forbiddenResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec-resource/error-types/ACCESS-DENIED",
				Title:      "Forbidden",
				Detail:     "You do not have the necessary access to perform this operation or the requested resource cannot be modified",
				StatusCode: http.StatusForbidden,
			},
		},
		"404 Not Found": {
			params: CreateURLProtectionRuleRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 200,
					HostnamePaths: []HostnamePath{
						{
							Hostname: "custom.com",
							Paths:    []string{"/asd", "/my-test-path"},
						},
					},
				},
			},
			responseStatus: http.StatusNotFound,
			responseBody:   notFoundResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/NOT-FOUND",
				Title:      "Not Found",
				Detail:     "The requested resource is not found",
				StatusCode: http.StatusNotFound,
			},
		},
		"500 internal server error": {
			params: CreateURLProtectionRuleRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 200,
					HostnamePaths: []HostnamePath{
						{
							Hostname: "custom.com",
							Paths:    []string{"/asd", "/my-test-path"},
						},
					},
				},
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
			{
				"type": "internal_error",
				"title": "Internal Server Error",
				"detail": "Error creating domain"
			}`,
			expectedPath: "/appsec/v1/configs/43253/versions/15/url-protections",
			withError: &Error{
				Type:       "internal_error",
				Title:      "Internal Server Error",
				Detail:     "Error creating domain",
				StatusCode: http.StatusInternalServerError,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				w.WriteHeader(test.responseStatus)
				if len(test.responseBody) > 0 {
					_, err := w.Write([]byte(test.responseBody))
					assert.NoError(t, err)
				}
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.CreateURLProtectionRule(
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

// Test Update URLProtectionRule
func TestAppSec_UpdateURLProtectionRule(t *testing.T) {
	result := UpdateURLProtectionRuleResponse{}

	respData := compactJSON(loadFixtureBytes("testdata/TestURLProtection/URLProtectionRule.json"))
	err := json.Unmarshal([]byte(respData), &result)
	require.NoError(t, err)

	req := UpdateURLProtectionRuleRequest{}

	reqData := compactJSON(loadFixtureBytes("testdata/TestURLProtection/URLProtectionRule.json"))
	err = json.Unmarshal([]byte(reqData), &req)
	require.NoError(t, err)

	tests := map[string]struct {
		params           UpdateURLProtectionRuleRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *UpdateURLProtectionRuleResponse
		withError        error
		headers          http.Header
	}{
		"200 Success": {
			params: UpdateURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 400,
				},
			},
			headers: http.Header{
				"Content-Type": []string{"application/json;charset=UTF-8"},
			},
			responseStatus:   http.StatusOK,
			responseBody:     respData,
			expectedResponse: &result,
			expectedPath:     "/appsec/v1/configs/43253/versions/15/url-protections/134644",
		},
		"400 bad request": {
			params: UpdateURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 400,
				},
			},
			responseStatus: http.StatusBadRequest,
			responseBody:   badRequestResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections/134644",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/BAD-REQUEST",
				Title:      "Bad Request",
				Detail:     "The request could not be understood by the server due to malformed syntax.",
				StatusCode: http.StatusBadRequest,
			},
		},
		"403 Forbidden": {
			params: UpdateURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 400,
				},
			},
			responseStatus: http.StatusForbidden,
			responseBody:   forbiddenResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections/134644",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec-resource/error-types/ACCESS-DENIED",
				Title:      "Forbidden",
				Detail:     "You do not have the necessary access to perform this operation or the requested resource cannot be modified",
				StatusCode: http.StatusForbidden,
			},
		},
		"404 Not Found": {
			params: UpdateURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 400,
				},
			},
			responseStatus: http.StatusNotFound,
			responseBody:   notFoundResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections/134644",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/NOT-FOUND",
				Title:      "Not Found",
				Detail:     "The requested resource is not found",
				StatusCode: http.StatusNotFound,
			},
		},
		"500 internal server error": {
			params: UpdateURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 400,
				},
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
			{
				"type": "internal_error",
				"title": "Internal Server Error",
				"detail": "Error creating zone"
			}`,
			expectedPath: "/appsec/v1/configs/43253/versions/15/url-protections/134644",
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
			result, err := client.UpdateURLProtectionRule(
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

// Test Remove URLProtectionRule
func TestAppSec_RemoveURLProtectionRule(t *testing.T) {

	tests := map[string]struct {
		params         RemoveURLProtectionRuleRequest
		responseStatus int
		responseBody   string
		expectedPath   string
		withError      error
		headers        http.Header
	}{
		"204 No Content": {
			params: RemoveURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			headers: http.Header{
				"Content-Type": []string{"application/json;charset=UTF-8"},
			},
			responseStatus: http.StatusNoContent,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections/134644",
		},
		"400 bad request": {
			params: RemoveURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			responseStatus: http.StatusBadRequest,
			responseBody:   badRequestResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/BAD-REQUEST",
				Title:      "Bad Request",
				Detail:     "The request could not be understood by the server due to malformed syntax.",
				StatusCode: http.StatusBadRequest,
			},
		},
		"403 Forbidden": {
			params: RemoveURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			responseStatus: http.StatusForbidden,
			responseBody:   forbiddenResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections/134644",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec-resource/error-types/ACCESS-DENIED",
				Title:      "Forbidden",
				Detail:     "You do not have the necessary access to perform this operation or the requested resource cannot be modified",
				StatusCode: http.StatusForbidden,
			},
		},
		"404 Not Found": {
			params: RemoveURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			responseStatus: http.StatusNotFound,
			responseBody:   notFoundResp,
			expectedPath:   "/appsec/v1/configs/43253/versions/15/url-protections/134644",
			withError: &Error{
				Type:       "https://problems.luna.akamaiapis.net/appsec/error-types/NOT-FOUND",
				Title:      "Not Found",
				Detail:     "The requested resource is not found",
				StatusCode: http.StatusNotFound,
			},
		},
		"500 internal server error": {
			params: RemoveURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
			{
				"type": "internal_error",
				"title": "Internal Server Error",
				"detail": "Error deleting url protection rule"
			}`,
			expectedPath: "/appsec/v1/configs/43253/versions/15/url-protections/134644",
			withError: &Error{
				Type:       "internal_error",
				Title:      "Internal Server Error",
				Detail:     "Error deleting url protection rule",
				StatusCode: http.StatusInternalServerError,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodDelete, r.Method)
				w.WriteHeader(test.responseStatus)
				if len(test.responseBody) > 0 {
					_, err := w.Write([]byte(test.responseBody))
					assert.NoError(t, err)
				}
			}))
			client := mockAPIClient(t, mockServer)
			err := client.RemoveURLProtectionRule(
				session.ContextWithOptions(
					context.Background(),
					session.WithContextHeaders(test.headers)), test.params)
			if test.withError != nil {
				assert.True(t, errors.Is(err, test.withError), "want: %s; got: %s", test.withError, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// Test RemoveURLProtectionRuleRequest Validate
func TestRemoveURLProtectionRuleRequest_Validate(t *testing.T) {
	tests := map[string]struct {
		req           RemoveURLProtectionRuleRequest
		errorExpected bool
	}{
		"valid request - all fields populated": {
			req: RemoveURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			errorExpected: false,
		},
		"missing ConfigID": {
			req: RemoveURLProtectionRuleRequest{
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing ConfigVersion": {
			req: RemoveURLProtectionRuleRequest{
				ConfigID:            43253,
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing URLProtectionRuleID": {
			req: RemoveURLProtectionRuleRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
			},
			errorExpected: true,
		},
		"missing all required fields": {
			req:           RemoveURLProtectionRuleRequest{},
			errorExpected: true,
		},
		"missing ConfigID and ConfigVersion": {
			req: RemoveURLProtectionRuleRequest{
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing ConfigID and URLProtectionRuleID": {
			req: RemoveURLProtectionRuleRequest{
				ConfigVersion: 15,
			},
			errorExpected: true,
		},
		"missing ConfigVersion and URLProtectionRuleID": {
			req: RemoveURLProtectionRuleRequest{
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

// Test GetURLProtectionRuleRequest Validate
func TestGetURLProtectionRuleRequest_Validate(t *testing.T) {
	tests := map[string]struct {
		req           GetURLProtectionRuleRequest
		errorExpected bool
	}{
		"valid request - all fields populated": {
			req: GetURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			errorExpected: false,
		},
		"missing ConfigID": {
			req: GetURLProtectionRuleRequest{
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing ConfigVersion": {
			req: GetURLProtectionRuleRequest{
				ConfigID:            43253,
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing URLProtectionRuleID": {
			req: GetURLProtectionRuleRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
			},
			errorExpected: true,
		},
		"missing all required fields": {
			req:           GetURLProtectionRuleRequest{},
			errorExpected: true,
		},
		"missing ConfigID and ConfigVersion": {
			req: GetURLProtectionRuleRequest{
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing ConfigID and URLProtectionRuleID": {
			req: GetURLProtectionRuleRequest{
				ConfigVersion: 15,
			},
			errorExpected: true,
		},
		"missing ConfigVersion and URLProtectionRuleID": {
			req: GetURLProtectionRuleRequest{
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

// Test ListURLProtectionRulesRequest Validate
func TestListURLProtectionRulesRequest_Validate(t *testing.T) {
	tests := map[string]struct {
		req           ListURLProtectionRulesRequest
		errorExpected bool
	}{
		"valid request - all fields populated": {
			req: ListURLProtectionRulesRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
			},
			errorExpected: false,
		},
		"missing ConfigID": {
			req: ListURLProtectionRulesRequest{
				ConfigVersion: 15,
			},
			errorExpected: true,
		},
		"missing ConfigVersion": {
			req: ListURLProtectionRulesRequest{
				ConfigID: 43253,
			},
			errorExpected: true,
		},
		"missing all required fields": {
			req:           ListURLProtectionRulesRequest{},
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

// Test CreateURLProtectionRuleRequest Validate
func TestCreateURLProtectionRuleRequest_Validate(t *testing.T) {
	tests := map[string]struct {
		req           CreateURLProtectionRuleRequest
		errorExpected bool
	}{
		"valid request - all fields populated": {
			req: CreateURLProtectionRuleRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 400,
				},
			},
			errorExpected: false,
		},
		"missing ConfigID": {
			req: CreateURLProtectionRuleRequest{
				ConfigVersion: 15,
			},
			errorExpected: true,
		},
		"missing ConfigVersion": {
			req: CreateURLProtectionRuleRequest{
				ConfigID: 43253,
			},
			errorExpected: true,
		},
		"missing Body": {
			req: CreateURLProtectionRuleRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
			},
			errorExpected: true,
		},
		"missing all required fields": {
			req:           CreateURLProtectionRuleRequest{},
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

// Test UpdateURLProtectionRuleRequest Validate
func TestUpdateURLProtectionRuleRequest_Validate(t *testing.T) {
	tests := map[string]struct {
		req           UpdateURLProtectionRuleRequest
		errorExpected bool
	}{
		"valid request - all fields populated": {
			req: UpdateURLProtectionRuleRequest{
				ConfigID:            43253,
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 400,
				},
			},
			errorExpected: false,
		},
		"missing ConfigID": {
			req: UpdateURLProtectionRuleRequest{
				ConfigVersion:       15,
				URLProtectionRuleID: 134644,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 400,
				},
			},
			errorExpected: true,
		},
		"missing ConfigVersion": {
			req: UpdateURLProtectionRuleRequest{
				ConfigID:            43253,
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing URLProtectionRuleID": {
			req: UpdateURLProtectionRuleRequest{
				ConfigID:      43253,
				ConfigVersion: 15,
				Body: URLProtectionRuleRequestBody{
					Name:             "Test URL Protection Rule with Hostname Paths",
					MaxRateThreshold: 400,
				},
			},
			errorExpected: true,
		},
		"missing all required fields": {
			req:           UpdateURLProtectionRuleRequest{},
			errorExpected: true,
		},
		"missing ConfigID and ConfigVersion": {
			req: UpdateURLProtectionRuleRequest{
				URLProtectionRuleID: 134644,
			},
			errorExpected: true,
		},
		"missing ConfigID and URLProtectionRuleID": {
			req: UpdateURLProtectionRuleRequest{
				ConfigVersion: 15,
			},
			errorExpected: true,
		},
		"missing ConfigVersion and URLProtectionRuleID": {
			req: UpdateURLProtectionRuleRequest{
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
