package mtlstruststore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v10/internal/test"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v10/pkg/ptr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateCASet(t *testing.T) {
	tests := map[string]struct {
		request          CreateCASetRequest
		expectedPath     string
		responseStatus   int
		responseBody     string
		expectedResponse *CreateCASetResponse
		responseHeaders  map[string]string
		withError        func(*testing.T, error)
	}{
		"201 Created": {
			request: CreateCASetRequest{
				CASetName:   "test",
				Description: "description",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets",
			responseStatus: http.StatusCreated,
			responseBody: `
				{
					"accountId": "A-CCOUNT",
					"caSetId": 199,
					"caSetLink": "/mtls-edge-truststore/v2/ca-sets/199",
					"caSetName": "test",
					"caSetStatus": "NOT_DELETED",
					"createdBy": "jdoe",
					"createdDate": "2025-04-01T15:33:48.464941911Z",
					"deletedBy": null,
					"deletedDate": null,
					"description": "",
					"latestVersion": null,
					"latestVersionLink": null,
					"productionVersion": null,
					"productionVersionLink": null,
					"stagingVersion": null,
					"stagingVersionLink": null,
					"versionsLink": "/mtls-edge-truststore/v2/ca-sets/199/versions/"
				}`,
			expectedResponse: &CreateCASetResponse{
				AccountID:             "A-CCOUNT",
				CASetID:               199,
				CASetLink:             "/mtls-edge-truststore/v2/ca-sets/199",
				CASetName:             "test",
				CASetStatus:           "NOT_DELETED",
				CreatedBy:             "jdoe",
				CreatedDate:           test.NewTimeFromString(t, "2025-04-01T15:33:48.464941911Z"),
				DeletedBy:             nil,
				DeletedDate:           nil,
				Description:           "",
				LatestVersion:         nil,
				LatestVersionLink:     nil,
				ProductionVersion:     nil,
				ProductionVersionLink: nil,
				StagingVersion:        nil,
				StagingVersionLink:    nil,
				VersionsLink:          "/mtls-edge-truststore/v2/ca-sets/199/versions/",
			},
			responseHeaders: map[string]string{
				"Location": "/mtls-edge-truststore/v2/ca-sets/199",
			},
		},
		"missing required request param - validation error": {
			request: CreateCASetRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "create ca set failed: struct validation: CASetName: cannot be blank", err.Error())
			},
		},
		"name too short - validation error": {
			request: CreateCASetRequest{
				CASetName: "a",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "create ca set failed: struct validation: CASetName: the length must be between 3 and 64", err.Error())
			},
		},
		"invalid name - validation error": {
			request: CreateCASetRequest{
				CASetName: "###A",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "create ca set failed: struct validation: CASetName: allowed characters are alphanumerics (a-z, A-Z, 0-9), underscore (_), hyphen (-), percent (%) and period (.)", err.Error())
			},
		},
		"invalid name with ... - validation error": {
			request: CreateCASetRequest{
				CASetName: "AAA...A",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "create ca set failed: struct validation: CASetName: CA Set name cannot contain three consecutive periods (...)", err.Error())
			},
		},
		"500 internal server error": {
			request: CreateCASetRequest{
				CASetName:   "test",
				Description: "description",
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
{
    "type": "internal-server-error",
    "title": "Internal Server Error",
    "detail": "Error processing request",
    "instance": "TestInstances",
    "status": 500
}`,
			expectedPath: "/mtls-edge-truststore/v2/ca-sets",
			withError: func(t *testing.T, err error) {
				want := &Error{
					Type:     "internal-server-error",
					Title:    "Internal Server Error",
					Detail:   "Error processing request",
					Instance: "TestInstances",
					Status:   500,
				}
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodPost, r.Method)
				if len(test.responseHeaders) > 0 {
					for header, value := range test.responseHeaders {
						w.Header().Set(header, value)
					}
				}

				w.WriteHeader(test.responseStatus)
				_, err := w.Write([]byte(test.responseBody))
				assert.NoError(t, err)
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.CreateCASet(context.Background(), test.request)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestGetCASet(t *testing.T) {
	tests := map[string]struct {
		params           GetCASetRequest
		expectedPath     string
		responseStatus   int
		responseBody     string
		expectedResponse *GetCASetResponse
		withError        func(*testing.T, error)
	}{
		"200 OK": {
			params: GetCASetRequest{
				CASetID: 199,
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/199",
			responseStatus: http.StatusOK,
			responseBody: `
				{
					"accountId": "A-CCOUNT",
					"caSetId": 199,
					"caSetLink": "/mtls-edge-truststore/v2/ca-sets/199",
					"caSetName": "test",
					"caSetStatus": "NOT_DELETED",
					"createdBy": "jdoe",
					"createdDate": "2025-04-01T15:33:48.464941911Z",
					"deletedBy": null,
					"deletedDate": null,
					"description": "",
					"latestVersion": null,
					"latestVersionLink": null,
					"productionVersion": null,
					"productionVersionLink": null,
					"stagingVersion": null,
					"stagingVersionLink": null,
					"versionsLink": "/mtls-edge-truststore/v2/ca-sets/199/versions/"
				}`,
			expectedResponse: &GetCASetResponse{
				AccountID:             "A-CCOUNT",
				CASetID:               199,
				CASetLink:             "/mtls-edge-truststore/v2/ca-sets/199",
				CASetName:             "test",
				CASetStatus:           "NOT_DELETED",
				CreatedBy:             "jdoe",
				CreatedDate:           test.NewTimeFromString(t, "2025-04-01T15:33:48.464941911Z"),
				DeletedBy:             nil,
				DeletedDate:           nil,
				Description:           "",
				LatestVersion:         nil,
				LatestVersionLink:     nil,
				ProductionVersion:     nil,
				ProductionVersionLink: nil,
				StagingVersion:        nil,
				StagingVersionLink:    nil,
				VersionsLink:          "/mtls-edge-truststore/v2/ca-sets/199/versions/",
			},
		},
		"missing required params - validation error": {
			params: GetCASetRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "get ca set failed: struct validation: CASetID: cannot be blank", err.Error())
			},
		},
		"404 ca set key not found - custom error check": {
			params: GetCASetRequest{
				CASetID: 10,
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/10",
			responseStatus: http.StatusNotFound,
			responseBody: `{
				"contextInfo": {
					"caSetId": 10
				},
				"detail": "Cannot get CA set as the CA set with caSetId 10 is not found.",
				"status": 404,
				"title": "CA set is not found.",
				"type": "/mtls-edge-truststore/v2/error-types/ca-set-not-found"
			}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetNotFound))
			},
		},
		"500 internal server error": {
			params: GetCASetRequest{
				CASetID: 199,
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
{
   "type": "internal-server-error",
   "title": "Internal Server Error",
   "detail": "Error processing request",
   "instance": "TestInstances",
   "status": 500
}`,
			expectedPath: "/mtls-edge-truststore/v2/ca-sets/199",
			withError: func(t *testing.T, err error) {
				want := &Error{
					Type:     "internal-server-error",
					Title:    "Internal Server Error",
					Detail:   "Error processing request",
					Instance: "TestInstances",
					Status:   500,
				}
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
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
			result, err := client.GetCASet(context.Background(), test.params)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestListCASet(t *testing.T) {
	tests := map[string]struct {
		request          ListCASetsRequest
		expectedPath     string
		responseStatus   int
		responseBody     string
		expectedResponse *ListCASetsResponse
		withError        func(*testing.T, error)
	}{
		"200 OK": {
			request:        ListCASetsRequest{},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets",
			responseStatus: http.StatusOK,
			responseBody: `{
				"caSets": [
					{
						"accountId": "A-CCOUNT",
						"caSetId": 199,
						"caSetLink": "/mtls-edge-truststore/v2/ca-sets/199",
						"caSetName": "test",
						"caSetStatus": "NOT_DELETED",
						"createdBy": "jdoe",
						"createdDate": "2025-04-01T15:33:48.464941911Z",
						"deletedBy": null,
						"deletedDate": null,
						"description": "",
						"latestVersion": null,
						"latestVersionLink": null,
						"productionVersion": null,
						"productionVersionLink": null,
						"stagingVersion": null,
						"stagingVersionLink": null,
						"versionsLink": "/mtls-edge-truststore/v2/ca-sets/199/versions/"
					},
					{
						"accountId": "A-CCOUNT",
						"caSetId": 80431,
						"caSetLink": "/mtls-edge-truststore/v2/ca-sets/80431",
						"caSetName": "sktcm2-051623",
						"caSetStatus": "NOT_DELETED",
						"createdBy": "migration_run",
						"createdDate": "2023-10-17T23:04:52Z",
						"deletedBy": null,
						"deletedDate": null,
						"description": "Imported from Techpreview TCM",
						"latestVersion": 2,
						"latestVersionLink": "/mtls-edge-truststore/v2/ca-sets/80431/versions/2",
						"productionVersion": 2,
						"productionVersionLink": "/mtls-edge-truststore/v2/ca-sets/80431/versions/2",
						"stagingVersion": 2,
						"stagingVersionLink": "/mtls-edge-truststore/v2/ca-sets/80431/versions/2",
						"versionsLink": "/mtls-edge-truststore/v2/ca-sets/80431/versions/"
					},
					{
						"accountId": "A-CCOUNT",
						"caSetId": 75201,
						"caSetLink": "/mtls-edge-truststore/v2/ca-sets/75201",
						"caSetName": "CertSet-4-docs",
						"caSetStatus": "NOT_DELETED",
						"createdBy": "migration_run",
						"createdDate": "2023-10-17T23:04:52Z",
						"deletedBy": null,
						"deletedDate": null,
						"description": "Imported from Techpreview TCM",
						"latestVersion": 3,
						"latestVersionLink": "/mtls-edge-truststore/v2/ca-sets/75201/versions/3",
						"productionVersion": null,
						"productionVersionLink": null,
						"stagingVersion": 3,
						"stagingVersionLink": "/mtls-edge-truststore/v2/ca-sets/75201/versions/3",
						"versionsLink": "/mtls-edge-truststore/v2/ca-sets/75201/versions/"
					}
				]
			}`,
			expectedResponse: &ListCASetsResponse{
				CASets: []CASetResponse{
					{
						AccountID:             "A-CCOUNT",
						CASetID:               199,
						CASetLink:             "/mtls-edge-truststore/v2/ca-sets/199",
						CASetName:             "test",
						CASetStatus:           "NOT_DELETED",
						CreatedBy:             "jdoe",
						CreatedDate:           test.NewTimeFromString(t, "2025-04-01T15:33:48.464941911Z"),
						DeletedBy:             nil,
						DeletedDate:           nil,
						Description:           "",
						LatestVersion:         nil,
						LatestVersionLink:     nil,
						ProductionVersion:     nil,
						ProductionVersionLink: nil,
						StagingVersion:        nil,
						StagingVersionLink:    nil,
						VersionsLink:          "/mtls-edge-truststore/v2/ca-sets/199/versions/",
					},
					{
						AccountID:             "A-CCOUNT",
						CASetID:               80431,
						CASetLink:             "/mtls-edge-truststore/v2/ca-sets/80431",
						CASetName:             "sktcm2-051623",
						CASetStatus:           "NOT_DELETED",
						CreatedBy:             "migration_run",
						CreatedDate:           test.NewTimeFromString(t, "2023-10-17T23:04:52Z"),
						DeletedBy:             nil,
						DeletedDate:           nil,
						Description:           "Imported from Techpreview TCM",
						LatestVersion:         ptr.To(int64(2)),
						LatestVersionLink:     ptr.To("/mtls-edge-truststore/v2/ca-sets/80431/versions/2"),
						ProductionVersion:     ptr.To(int64(2)),
						ProductionVersionLink: ptr.To("/mtls-edge-truststore/v2/ca-sets/80431/versions/2"),
						StagingVersion:        ptr.To(int64(2)),
						StagingVersionLink:    ptr.To("/mtls-edge-truststore/v2/ca-sets/80431/versions/2"),
						VersionsLink:          "/mtls-edge-truststore/v2/ca-sets/80431/versions/",
					},
					{
						AccountID:             "A-CCOUNT",
						CASetID:               75201,
						CASetLink:             "/mtls-edge-truststore/v2/ca-sets/75201",
						CASetName:             "CertSet-4-docs",
						CASetStatus:           "NOT_DELETED",
						CreatedBy:             "migration_run",
						CreatedDate:           test.NewTimeFromString(t, "2023-10-17T23:04:52Z"),
						DeletedBy:             nil,
						DeletedDate:           nil,
						Description:           "Imported from Techpreview TCM",
						LatestVersion:         ptr.To(int64(3)),
						LatestVersionLink:     ptr.To("/mtls-edge-truststore/v2/ca-sets/75201/versions/3"),
						ProductionVersion:     nil,
						ProductionVersionLink: nil,
						StagingVersion:        ptr.To(int64(3)),
						StagingVersionLink:    ptr.To("/mtls-edge-truststore/v2/ca-sets/75201/versions/3"),
						VersionsLink:          "/mtls-edge-truststore/v2/ca-sets/75201/versions/",
					},
				},
			},
		},
		"200 OK with filtering and empty response": {
			request: ListCASetsRequest{
				CASetName:   "foo",
				ActivatedOn: "production",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets?activatedOn=production&caSetName=foo",
			responseStatus: http.StatusOK,
			responseBody: `{
				"caSets": []
			}`,
			expectedResponse: &ListCASetsResponse{
				CASets: []CASetResponse{},
			},
		},
		"200 OK with filtering with non lower case value and an empty response": {
			request: ListCASetsRequest{
				CASetName:   "foo",
				ActivatedOn: "PRODUCTION",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets?activatedOn=production&caSetName=foo",
			responseStatus: http.StatusOK,
			responseBody: `{
				"caSets": []
			}`,
			expectedResponse: &ListCASetsResponse{
				CASets: []CASetResponse{},
			},
		},
		"200 OK on production and staging with an empty response": {
			request: ListCASetsRequest{
				ActivatedOn: "STAGING+PRODUCTION",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets?activatedOn=staging%2Bproduction",
			responseStatus: http.StatusOK,
			responseBody: `{
				"caSets": []
			}`,
			expectedResponse: &ListCASetsResponse{
				CASets: []CASetResponse{},
			},
		},
		"invalid network - validation error": {
			request: ListCASetsRequest{
				ActivatedOn: "PROD",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "list ca sets failed: struct validation: ActivatedOn: value 'prod' is invalid. Must be one of: 'staging', 'production' or 'staging+production'", err.Error())
			},
		},
		"name too short - validation error": {
			request: ListCASetsRequest{
				CASetName: "a",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "list ca sets failed: struct validation: CASetName: the length must be between 3 and 64", err.Error())
			},
		},
		"invalid name - validation error": {
			request: ListCASetsRequest{
				CASetName: "###A",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "list ca sets failed: struct validation: CASetName: allowed characters are alphanumerics (a-z, A-Z, 0-9), underscore (_), hyphen (-), percent (%) and period (.)", err.Error())
			},
		},
		"invalid name with ... - validation error": {
			request: ListCASetsRequest{
				CASetName: "AAA...A",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "list ca sets failed: struct validation: CASetName: CA Set name cannot contain three consecutive periods (...)", err.Error())
			},
		},
		"500 internal server error": {
			request:        ListCASetsRequest{},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets",
			responseStatus: http.StatusInternalServerError,
			responseBody: `
{
   "type": "internal-server-error",
   "title": "Internal Server Error",
   "detail": "Error processing request",
   "instance": "TestInstances",
   "status": 500
}`,
			withError: func(t *testing.T, err error) {
				want := &Error{
					Type:     "internal-server-error",
					Title:    "Internal Server Error",
					Detail:   "Error processing request",
					Instance: "TestInstances",
					Status:   500,
				}
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
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
			result, err := client.ListCASets(context.Background(), test.request)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestDeleteCASet(t *testing.T) {
	tests := map[string]struct {
		params         DeleteCASetRequest
		expectedPath   string
		responseStatus int
		responseBody   string
		withError      func(*testing.T, error)
	}{
		"202 Accepted": {
			params: DeleteCASetRequest{
				CASetID: 199,
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/199",
			responseStatus: http.StatusAccepted,
		},
		"missing required params - validation error": {
			params: DeleteCASetRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "delete ca set failed: struct validation: CASetID: cannot be blank", err.Error())
			},
		},
		"500 internal server error": {
			params: DeleteCASetRequest{
				CASetID: 199,
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/199",
			responseStatus: http.StatusInternalServerError,
			responseBody: `
{
   "type": "internal-server-error",
   "title": "Internal Server Error",
   "detail": "Error processing request",
   "instance": "TestInstances",
   "status": 500
}`,
			withError: func(t *testing.T, err error) {
				want := &Error{
					Type:     "internal-server-error",
					Title:    "Internal Server Error",
					Detail:   "Error processing request",
					Instance: "TestInstances",
					Status:   500,
				}
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodDelete, r.Method)
				w.WriteHeader(test.responseStatus)
				_, err := w.Write([]byte(test.responseBody))
				assert.NoError(t, err)
			}))
			client := mockAPIClient(t, mockServer)
			err := client.DeleteCASet(context.Background(), test.params)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
