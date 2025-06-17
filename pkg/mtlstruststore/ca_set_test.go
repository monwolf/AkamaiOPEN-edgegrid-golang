package mtlstruststore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/internal/test"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/ptr"
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
				Description: ptr.To("description"),
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets",
			responseStatus: http.StatusCreated,
			responseBody: `
				{
					"accountId": "A-CCOUNT",
					"caSetId": "199",
					"caSetLink": "/mtls-edge-truststore/v2/ca-sets/199",
					"caSetName": "test",
					"caSetStatus": "NOT_DELETED",
					"createdBy": "jdoe",
					"createdDate": "2025-04-01T15:33:48.464941Z",
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
				CASetID:               "199",
				CASetLink:             "/mtls-edge-truststore/v2/ca-sets/199",
				CASetName:             "test",
				CASetStatus:           "NOT_DELETED",
				CreatedBy:             "jdoe",
				CreatedDate:           test.NewTimeFromString(t, "2025-04-01T15:33:48.464941Z"),
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
				assert.Equal(t, "create ca set failed: struct validation: CASetName: cannot contain three consecutive periods (...)", err.Error())
			},
		},
		"500 internal server error": {
			request: CreateCASetRequest{
				CASetName:   "test",
				Description: ptr.To("description"),
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
				CASetID: "199",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/199",
			responseStatus: http.StatusOK,
			responseBody: `
				{
					"accountId": "A-CCOUNT",
					"caSetId": "199",
					"caSetLink": "/mtls-edge-truststore/v2/ca-sets/199",
					"caSetName": "test",
					"caSetStatus": "NOT_DELETED",
					"createdBy": "jdoe",
					"createdDate": "2025-04-01T15:33:48.464941Z",
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
				CASetID:               "199",
				CASetLink:             "/mtls-edge-truststore/v2/ca-sets/199",
				CASetName:             "test",
				CASetStatus:           "NOT_DELETED",
				CreatedBy:             "jdoe",
				CreatedDate:           test.NewTimeFromString(t, "2025-04-01T15:33:48.464941Z"),
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
				CASetID: "10",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/10",
			responseStatus: http.StatusNotFound,
			responseBody: `{
				"contextInfo": {
					"caSetId": "10"
				},
				"detail": "Cannot get CA set as the CA set with caSetId 10 is not found.",
				"status": 404,
				"title": "CA set is not found.",
				"type": "/mtls-edge-truststore/error-types/ca-set-not-found"
			}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetNotFound))
			},
		},
		"500 internal server error": {
			params: GetCASetRequest{
				CASetID: "199",
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

func TestListCASets(t *testing.T) {
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
						"caSetId": "199",
						"caSetLink": "/mtls-edge-truststore/v2/ca-sets/199",
						"caSetName": "test",
						"caSetStatus": "NOT_DELETED",
						"createdBy": "jdoe",
						"createdDate": "2025-04-01T15:33:48.464941Z",
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
						"caSetId": "80431",
						"caSetLink": "/mtls-edge-truststore/v2/ca-sets/80431",
						"caSetName": "sktcm2-051623",
						"caSetStatus": "NOT_DELETED",
						"createdBy": "migration_run",
						"createdDate": "2023-10-17T23:04:52.491822Z",
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
						"caSetId": "75201",
						"caSetLink": "/mtls-edge-truststore/v2/ca-sets/75201",
						"caSetName": "CertSet-4-docs",
						"caSetStatus": "DELETED",
						"createdBy": "migration_run",
						"createdDate": "2023-10-17T23:04:52.884782Z",
						"deletedBy": "migration_run",
						"deletedDate": "2025-06-04T12:19:33.095023Z",
						"description": "Imported from Techpreview TCM",
						"latestVersion": 3,
						"latestVersionLink": "/mtls-edge-truststore/v2/ca-sets/75201/versions/3",
						"productionVersion": null,
						"productionVersionLink": null,
						"stagingVersion": null,
						"stagingVersionLink": null,
						"versionsLink": "/mtls-edge-truststore/v2/ca-sets/75201/versions/"
					}
				]
			}`,
			expectedResponse: &ListCASetsResponse{
				CASets: []CASetResponse{
					{
						AccountID:             "A-CCOUNT",
						CASetID:               "199",
						CASetLink:             "/mtls-edge-truststore/v2/ca-sets/199",
						CASetName:             "test",
						CASetStatus:           "NOT_DELETED",
						CreatedBy:             "jdoe",
						CreatedDate:           test.NewTimeFromString(t, "2025-04-01T15:33:48.464941Z"),
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
						CASetID:               "80431",
						CASetLink:             "/mtls-edge-truststore/v2/ca-sets/80431",
						CASetName:             "sktcm2-051623",
						CASetStatus:           "NOT_DELETED",
						CreatedBy:             "migration_run",
						CreatedDate:           test.NewTimeFromString(t, "2023-10-17T23:04:52.491822Z"),
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
						CASetID:               "75201",
						CASetLink:             "/mtls-edge-truststore/v2/ca-sets/75201",
						CASetName:             "CertSet-4-docs",
						CASetStatus:           "DELETED",
						CreatedBy:             "migration_run",
						CreatedDate:           test.NewTimeFromString(t, "2023-10-17T23:04:52.884782Z"),
						DeletedBy:             ptr.To("migration_run"),
						DeletedDate:           ptr.To(test.NewTimeFromString(t, "2025-06-04T12:19:33.095023Z")),
						Description:           "Imported from Techpreview TCM",
						LatestVersion:         ptr.To(int64(3)),
						LatestVersionLink:     ptr.To("/mtls-edge-truststore/v2/ca-sets/75201/versions/3"),
						ProductionVersion:     nil,
						ProductionVersionLink: nil,
						StagingVersion:        nil,
						StagingVersionLink:    nil,
						VersionsLink:          "/mtls-edge-truststore/v2/ca-sets/75201/versions/",
					},
				},
			},
		},
		"200 OK with filtering and empty response": {
			request: ListCASetsRequest{
				CASetNamePrefix: "foo",
				ActivatedOn:     "production",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets?activatedOn=production&caSetNamePrefix=foo",
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
				CASetNamePrefix: "foo",
				ActivatedOn:     "PRODUCTION",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets?activatedOn=production&caSetNamePrefix=foo",
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
				assert.Equal(t, "list ca sets failed: struct validation: ActivatedOn: value 'prod' is invalid. Must be one of: 'staging', 'production', 'staging+production' or 'production+staging'.", err.Error())
			},
		},
		"name prefix too long - validation error": {
			request: ListCASetsRequest{
				CASetNamePrefix: strings.Repeat("PrefixTooLong", 5),
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "list ca sets failed: struct validation: CASetNamePrefix: the length must be no more than 64", err.Error())
			},
		},
		"invalid name prefix - validation error": {
			request: ListCASetsRequest{
				CASetNamePrefix: "###A",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "list ca sets failed: struct validation: CASetNamePrefix: allowed characters are alphanumerics (a-z, A-Z, 0-9), underscore (_), hyphen (-), percent (%) and period (.)", err.Error())
			},
		},
		"invalid name prefix with ... - validation error": {
			request: ListCASetsRequest{
				CASetNamePrefix: "AAA...A",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "list ca sets failed: struct validation: CASetNamePrefix: cannot contain three consecutive periods (...)", err.Error())
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
				CASetID: "199",
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
				CASetID: "199",
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

func TestListCASetAssociations(t *testing.T) {
	tests := map[string]struct {
		params           ListCASetAssociationsRequest
		expectedPath     string
		responseStatus   int
		responseBody     string
		expectedResponse *ListCASetAssociationsResponse
		withError        func(*testing.T, error)
	}{
		"200 - No associations": {
			params: ListCASetAssociationsRequest{
				CASetID: "1",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/associations",
			responseStatus: http.StatusOK,
			responseBody: `{
  "associations": {
    "properties": [],
    "enrollments": null
  }
}`,
			expectedResponse: &ListCASetAssociationsResponse{Associations: Associations{Properties: make([]AssociationProperty, 0)}},
		},
		"200 - Navigable property": {
			params: ListCASetAssociationsRequest{
				CASetID: "1",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/associations",
			responseStatus: http.StatusOK,
			responseBody: `{
  "associations": {
    "properties": [
      {
        "propertyId": "123",
        "propertyName": "test-prp-name",
        "assetId": 123456,
        "groupId": 345,
        "hostnames": [
          {
            "hostName": "example.com",
            "network": "STAGING",
            "status": "ATTACHED"
          }
        ]
      }
    ],
    "enrollments": null
  }
}`,
			expectedResponse: &ListCASetAssociationsResponse{Associations: Associations{Properties: []AssociationProperty{
				{
					PropertyID:   "123",
					PropertyName: ptr.To("test-prp-name"),
					AssetID:      ptr.To(int64(123456)),
					GroupID:      ptr.To(int64(345)),
					Hostnames: []AssociationHostname{
						{
							Hostname: "example.com",
							Network:  "STAGING",
							Status:   "ATTACHED",
						},
					},
				},
			}}},
		},
		"200 - Non-navigable property": {
			params: ListCASetAssociationsRequest{
				CASetID: "1",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/associations",
			responseStatus: http.StatusOK,
			responseBody: `{
  "associations": {
    "properties": [
      {
        "propertyId": "123",
        "hostnames": [
          {
            "hostName": "example.com",
            "network": "STAGING",
            "status": "ATTACHED"
          }
        ]
      }
    ],
    "enrollments": null
  }
}`,
			expectedResponse: &ListCASetAssociationsResponse{Associations: Associations{Properties: []AssociationProperty{
				{
					PropertyID: "123",
					Hostnames: []AssociationHostname{
						{
							Hostname: "example.com",
							Network:  "STAGING",
							Status:   "ATTACHED",
						},
					},
				},
			}}},
		},
		"200 - Enrollment": {
			params: ListCASetAssociationsRequest{
				CASetID: "1",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/associations",
			responseStatus: http.StatusOK,
			responseBody: `{
  "associations": {
    "properties": null,
    "enrollments": [
      {
        "enrollmentId": 123456,
        "enrollmentLink": "/cps/v2/enrollments/123456",
        "stagingSlots": [
          78956
        ],
        "productionSlots": [
          78956,
          56478
        ],
        "cn": "example1.com"
      },
      {
        "enrollmentId": 123457,
        "enrollmentLink": "/cps/v2/enrollments/123457",
        "stagingSlots": [
          23456
        ],
        "productionSlots": [
          23456
        ],
        "cn": "example2.com"
      }
    ]
  }
}
`,
			expectedResponse: &ListCASetAssociationsResponse{Associations: Associations{Enrollments: []AssociationEnrollment{
				{
					EnrollmentID:    123456,
					EnrollmentLink:  "/cps/v2/enrollments/123456",
					StagingSlots:    []int64{78956},
					ProductionSlots: []int64{78956, 56478},
					CN:              "example1.com",
				},
				{
					EnrollmentID:    123457,
					EnrollmentLink:  "/cps/v2/enrollments/123457",
					StagingSlots:    []int64{23456},
					ProductionSlots: []int64{23456},
					CN:              "example2.com",
				},
			}}},
		},
		"missing required params - validation error": {
			params: ListCASetAssociationsRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "list ca sets associations failed: struct validation: CASetID: cannot be blank", err.Error())
			},
		},
		"404 ca set not found": {
			params: ListCASetAssociationsRequest{
				CASetID: "2",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/2/associations",
			responseStatus: http.StatusNotFound,
			responseBody: `{
  "contextInfo" : {
    "caSetId" : "2"
  },
  "detail" : "Cannot get CA set associations as the CA set with caSetId 2 is not found.",
  "status" : 404,
  "title" : "CA set is not found.",
  "type" : "/mtls-edge-truststore/error-types/ca-set-not-found"
}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetNotFound), "want: %s; got: %s", ErrGetCASetNotFound, err)
			},
		},
		"issue fetching": {
			params: ListCASetAssociationsRequest{
				CASetID: "1",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/associations",
			responseStatus: http.StatusGatewayTimeout,
			responseBody: `{
  "contextInfo" : {
    "caSetId" : 1,
    "caSetName" : "caSetName-1"
  },
  "detail" : "There are issues fetching the information about associations at this time. The request timed out. Try again later.",
  "status" : 504,
  "title" : "Couldn't fetch associations details. Timeout occurred.",
  "type" : "/mtls-edge-truststore/error-types/cannot-get-ca-set-associations-timeout"
}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrFetchAssociationsTimeout), "want: %s; got: %s", ErrFetchAssociationsTimeout, err)
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
			result, err := client.ListCASetAssociations(context.Background(), test.params)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestCloneCASet(t *testing.T) {
	tests := map[string]struct {
		params              CloneCASetRequest
		expectedPath        string
		expectedRequestBody string
		responseStatus      int
		responseBody        string
		expectedResponse    *CloneCASetResponse
		withError           func(*testing.T, error)
	}{
		"200 - No version provided": {
			params: CloneCASetRequest{
				CloneFromSetID: "1",
				NewCASetName:   "new-set",
				NewDescription: "New CA Set",
			},
			expectedPath: "/mtls-edge-truststore/v2/ca-sets/1/clone",
			expectedRequestBody: `{
  "caSetName":"new-set",
  "description":"New CA Set"
}`,
			responseStatus: http.StatusCreated,
			responseBody: `{
    "accountId": "1-ACC",
    "caSetId": "2",
    "caSetLink": "/mtls-edge-truststore/v2/ca-sets/2",
    "caSetName": "new-set",
    "caSetStatus": "NOT_DELETED",
    "createdBy": "user1",
    "createdDate": "2025-04-10T07:03:32.987904Z",
    "deletedBy": null,
    "deletedDate": null,
    "description": "New CA Set",
    "latestVersion": 1,
    "latestVersionLink": "/mtls-edge-truststore/v2/ca-sets/2/versions/1",
    "productionVersion": null,
    "productionVersionLink": null,
    "stagingVersion": null,
    "stagingVersionLink": null,
    "versionsLink": "/mtls-edge-truststore/v2/ca-sets/2/versions/"
}`,
			expectedResponse: &CloneCASetResponse{
				AccountID:         "1-ACC",
				CASetID:           "2",
				CASetLink:         "/mtls-edge-truststore/v2/ca-sets/2",
				CASetName:         "new-set",
				CASetStatus:       "NOT_DELETED",
				CreatedBy:         "user1",
				CreatedDate:       test.NewTimeFromString(t, "2025-04-10T07:03:32.987904Z"),
				Description:       "New CA Set",
				LatestVersion:     ptr.To(int64(1)),
				LatestVersionLink: ptr.To("/mtls-edge-truststore/v2/ca-sets/2/versions/1"),
				VersionsLink:      "/mtls-edge-truststore/v2/ca-sets/2/versions/",
			},
		},
		"200 - Version provided": {
			params: CloneCASetRequest{
				CloneFromSetID:   "1",
				CloneFromVersion: 2,
				NewCASetName:     "new-set",
				NewDescription:   "New CA Set",
			},
			expectedPath: "/mtls-edge-truststore/v2/ca-sets/1/clone?cloneFromVersion=2",
			expectedRequestBody: `{
  "caSetName":"new-set",
  "description":"New CA Set"
}`,
			responseStatus: http.StatusCreated,
			responseBody: `{
    "accountId": "1-ACC",
    "caSetId": "2",
    "caSetLink": "/mtls-edge-truststore/v2/ca-sets/2",
    "caSetName": "new-set",
    "caSetStatus": "NOT_DELETED",
    "createdBy": "user1",
    "createdDate": "2025-04-10T07:03:32.987904Z",
    "deletedBy": null,
    "deletedDate": null,
    "description": "New CA Set",
    "latestVersion": 1,
    "latestVersionLink": "/mtls-edge-truststore/v2/ca-sets/2/versions/1",
    "productionVersion": null,
    "productionVersionLink": null,
    "stagingVersion": null,
    "stagingVersionLink": null,
    "versionsLink": "/mtls-edge-truststore/v2/ca-sets/2/versions/"
}`,
			expectedResponse: &CloneCASetResponse{
				AccountID:         "1-ACC",
				CASetID:           "2",
				CASetLink:         "/mtls-edge-truststore/v2/ca-sets/2",
				CASetName:         "new-set",
				CASetStatus:       "NOT_DELETED",
				CreatedBy:         "user1",
				CreatedDate:       test.NewTimeFromString(t, "2025-04-10T07:03:32.987904Z"),
				Description:       "New CA Set",
				LatestVersion:     ptr.To(int64(1)),
				LatestVersionLink: ptr.To("/mtls-edge-truststore/v2/ca-sets/2/versions/1"),
				VersionsLink:      "/mtls-edge-truststore/v2/ca-sets/2/versions/",
			},
		},
		"missing required params - validation error": {
			params: CloneCASetRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "clone ca set failed: struct validation: CloneFromSetID: cannot be blank\nNewCASetName: cannot be blank", err.Error())
			},
		},
		"too short required params - validation error": {
			params: CloneCASetRequest{
				CloneFromSetID: "1",
				NewCASetName:   "a",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "clone ca set failed: struct validation: NewCASetName: the length must be between 3 and 64", err.Error())
			},
		},
		"incorrect characters in required parameters - validation error": {
			params: CloneCASetRequest{
				CloneFromSetID: "1",
				NewCASetName:   "#edgegrid",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "clone ca set failed: struct validation: NewCASetName: allowed characters are alphanumerics (a-z, A-Z, 0-9), underscore (_), hyphen (-), percent (%) and period (.)", err.Error())
			},
		},
		"special case in required parameters - validation error": {
			params: CloneCASetRequest{
				CloneFromSetID: "1",
				NewCASetName:   "abc...cba",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "clone ca set failed: struct validation: NewCASetName: cannot contain three consecutive periods (...)", err.Error())
			},
		},
		"400 ca set does not have any version": {
			params: CloneCASetRequest{
				CloneFromSetID: "1",
				NewCASetName:   "new-set",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/clone",
			responseStatus: http.StatusBadRequest,
			responseBody: `{
    "contextInfo": {
        "caSetId": "1",
        "caSetName": "test1"
    },
    "detail": "CA set with caSetId 1 does not contain any versions. At least one version must be present to clone the CA set.",
    "status": 400,
    "title": "CA set does not contain any versions.",
    "type": "/mtls-edge-truststore/error-types/missing-caset-version"
}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrMissingCaCertVersion), "want: %s; got: %s", ErrMissingCaCertVersion, err)
			},
		},
		"404 ca set not found": {
			params: CloneCASetRequest{
				CloneFromSetID: "2",
				NewCASetName:   "new-set",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/2/clone",
			responseStatus: http.StatusNotFound,
			responseBody: `{
		 "contextInfo" : {
		   "caSetId" : 2
		 },
		 "detail" : "Cannot clone CA set as the CA set with caSetId 2 is not found.",
		 "status" : 404,
		 "title" : "CA set is not found.",
		 "type" : "/mtls-edge-truststore/error-types/ca-set-not-found"
		}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetNotFound), "want: %s; got: %s", ErrGetCASetNotFound, err)
			},
		},
		"404 ca set version not found": {
			params: CloneCASetRequest{
				CloneFromSetID:   "1",
				CloneFromVersion: 2,
				NewCASetName:     "new-set",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/clone?cloneFromVersion=2",
			responseStatus: http.StatusNotFound,
			responseBody: `{
  "type": "/mtls-edge-truststore/error-types/ca-set-version-not-found",
  "title": "CA set version not found",
  "status": 404,
  "detail": "Cannot clone CA set as the CA set version with version 2 is not found in the CA set under caSetName test1.",
  "contextInfo": {
    "caSetName": "test1",
    "caSetId": "1",
    "version": 2
  }
}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetVersionNotFound), "want: %s; got: %s", ErrGetCASetVersionNotFound, err)
			},
		},
		"409 duplicate": {
			params: CloneCASetRequest{
				CloneFromSetID: "1",
				NewCASetName:   "new-set",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/clone",
			responseStatus: http.StatusConflict,
			responseBody: `{
  "type": "/mtls-edge-truststore/error-types/ca-set-name-is-not-unique",
  "title": "CA set name already exists",
  "status": 409,
  "detail": "CA set with caSetName new-set cannot be created as another CA set with the same name exists in the account with accountId 1-ACC.",
  "contextInfo": {
    "caSetName": "new-set",
    "accountId": "1-ACC"
  }
}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCaSetNameNotUnique), "want: %s; got: %s", ErrCaSetNameNotUnique, err)
			},
		},
		"422 reached limit": {
			params: CloneCASetRequest{
				CloneFromSetID: "1",
				NewCASetName:   "new-set",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/clone",
			responseStatus: http.StatusUnprocessableEntity,
			responseBody: `{
  "type": "/mtls-edge-truststore/error-types/ca-set-limit-reached",
  "title": "Cannot create a new CA set. Maximum allowed CA set limit has been reached.",
  "status": 422,
  "detail": "Cannot create CA set as you have already reached or exceeded the maximum allowed CA set limit of 2 for your account. Please delete any unused or unwanted CA sets before you attempt to create a new CA set.",
  "contextInfo": {
    "accountId": "1-ACC",
    "currentSetCount": 2,
    "limit": 2
  }
}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCASetLimitReached), "want: %s; got: %s", ErrCASetLimitReached, err)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodPost, r.Method)
				w.WriteHeader(test.responseStatus)
				_, err := w.Write([]byte(test.responseBody))
				assert.NoError(t, err)
				if test.expectedRequestBody != "" {
					body, err := io.ReadAll(r.Body)
					assert.NoError(t, err)
					assert.JSONEq(t, test.expectedRequestBody, string(body))
				}
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.CloneCASet(context.Background(), test.params)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestGetCASetDeletionStatus(t *testing.T) {
	tests := map[string]struct {
		params           GetCASetDeletionStatusRequest
		expectedPath     string
		responseStatus   int
		responseHeaders  map[string]string
		responseBody     string
		expectedResponse *GetCASetDeletionStatusResponse
		withError        func(*testing.T, error)
	}{
		"202 - in progress": {
			params: GetCASetDeletionStatusRequest{
				CASetID: "1",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/status/delete",
			responseStatus: http.StatusAccepted,
			responseHeaders: map[string]string{
				"Retry-After": "2025-04-15T12:15:02Z",
			},
			responseBody: `{
    "caSetId": "1",
    "caSetLink": "/mtls-edge-truststore/v2/ca-sets/1",
    "caSetName": "test1",
    "deletions": [
        {
            "failureReason": null,
            "network": "PRODUCTION",
            "percentComplete": 0,
            "status": "IN_PROGRESS"
        },
        {
            "failureReason": null,
            "network": "STAGING",
            "percentComplete": 0,
            "status": "IN_PROGRESS"
        }
    ],
    "endTime": null,
    "estimatedEndTime": "2025-04-15T12:25:02.183294Z",
    "failureReason": null,
    "resourceMethod": "delete",
    "startTime": "2025-04-15T12:10:02.039140Z",
    "status": "IN_PROGRESS",
    "statusLink": "/mtls-edge-truststore/v2/ca-sets/1/status/delete"
}`,
			expectedResponse: &GetCASetDeletionStatusResponse{
				CASetID:   "1",
				CASetLink: "/mtls-edge-truststore/v2/ca-sets/1",
				CASetName: "test1",
				Deletions: []CASetNetworkDeleteStatus{
					{
						Network:         "PRODUCTION",
						PercentComplete: 0,
						Status:          "IN_PROGRESS",
					},
					{
						Network:         "STAGING",
						PercentComplete: 0,
						Status:          "IN_PROGRESS",
					},
				},
				EstimatedEndTime: ptr.To(test.NewTimeFromString(t, "2025-04-15T12:25:02.183294Z")),
				ResourceMethod:   ptr.To("delete"),
				StartTime:        test.NewTimeFromString(t, "2025-04-15T12:10:02.039140Z"),
				Status:           "IN_PROGRESS",
				StatusLink:       "/mtls-edge-truststore/v2/ca-sets/1/status/delete",
				RetryAfter:       ptr.To(test.NewTimeFromString(t, "2025-04-15T12:15:02Z")),
			},
		},
		"200 - completed": {
			params: GetCASetDeletionStatusRequest{
				CASetID: "1",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/status/delete",
			responseStatus: http.StatusOK,
			responseBody: `{
    "caSetId": "1",
    "caSetLink": "/mtls-edge-truststore/v2/ca-sets/1",
    "caSetName": "test1",
    "deletions": [
        {
            "failureReason": null,
            "network": "PRODUCTION",
            "percentComplete": 100,
            "status": "COMPLETE"
        },
        {
            "failureReason": null,
            "network": "STAGING",
            "percentComplete": 100,
            "status": "COMPLETE"
        }
    ],
    "endTime": "2025-04-15T12:13:30.082193Z",
    "estimatedEndTime": null,
    "failureReason": null,
    "resourceMethod": "delete",
    "startTime": "2025-04-15T12:10:02.039140Z",
    "status": "COMPLETE",
    "statusLink": "/mtls-edge-truststore/v2/ca-sets/1/status/delete"
}`,
			expectedResponse: &GetCASetDeletionStatusResponse{
				CASetID:   "1",
				CASetLink: "/mtls-edge-truststore/v2/ca-sets/1",
				CASetName: "test1",
				Deletions: []CASetNetworkDeleteStatus{
					{
						Network:         "PRODUCTION",
						PercentComplete: 100,
						Status:          "COMPLETE",
					},
					{
						Network:         "STAGING",
						PercentComplete: 100,
						Status:          "COMPLETE",
					},
				},
				EndTime:        ptr.To(test.NewTimeFromString(t, "2025-04-15T12:13:30.082193Z")),
				ResourceMethod: ptr.To("delete"),
				StartTime:      test.NewTimeFromString(t, "2025-04-15T12:10:02.039140Z"),
				Status:         "COMPLETE",
				StatusLink:     "/mtls-edge-truststore/v2/ca-sets/1/status/delete",
			},
		},
		"missing required params - validation error": {
			params: GetCASetDeletionStatusRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "list ca set deletion status failed: struct validation: CASetID: cannot be blank", err.Error())
			},
		},
		"404 ca set not found": {
			params: GetCASetDeletionStatusRequest{
				CASetID: "2",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/2/status/delete",
			responseStatus: http.StatusNotFound,
			responseBody: `{
 "contextInfo" : {
   "caSetId" : "2"
 },
 "detail" : "Cannot get CA set deletions as the CA set with caSetId 2 is not found.",
 "status" : 404,
 "title" : "CA set is not found.",
 "type" : "/mtls-edge-truststore/error-types/ca-set-not-found"
}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetNotFound), "want: %s; got: %s", ErrGetCASetNotFound, err)
			},
		},
		"400 - ca set is not during delete": {
			params: GetCASetDeletionStatusRequest{
				CASetID: "1",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/status/delete",
			responseStatus: http.StatusBadRequest,
			responseBody: `{
    "contextInfo": {
        "caSetId": "1"
    },
    "detail": "No active deletions were found for CA Certificate Set with set ID 1.",
    "status": 400,
    "title": "No active cert deletions found",
    "type": "/mtls-edge-truststore/error-types/no-active-cert-deletions"
}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrNoActiveCertDeletions), "want: %s; got: %s", ErrNoActiveCertDeletions, err)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodGet, r.Method)
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
			result, err := client.GetCASetDeletionStatus(context.Background(), test.params)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestListCASetActivities(t *testing.T) {
	tests := map[string]struct {
		params           ListCASetActivitiesRequest
		expectedPath     string
		responseStatus   int
		responseBody     string
		expectedResponse *ListCASetActivitiesResponse
		withError        func(*testing.T, error)
	}{
		"200 - no query params": {
			params: ListCASetActivitiesRequest{
				CASetID: "1",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/activities",
			responseStatus: http.StatusOK,
			responseBody: `{
    "activities": [
        {
            "activityBy": "user1",
            "activityDate": "2025-04-18T11:30:35.866481Z",
            "network": "PRODUCTION",
            "type": "DELETE_CA_SET",
            "version": null
        },
        {
            "activityBy": "user1",
            "activityDate": "2025-04-18T11:30:35.852930Z",
            "network": "STAGING",
            "type": "DELETE_CA_SET",
            "version": null
        },
        {
            "activityBy": "user1",
            "activityDate": "2025-04-16T13:14:46.183261Z",
            "network": null,
            "type": "CREATE_CA_SET_VERSION",
            "version": 2
        },
        {
            "activityBy": "user1",
            "activityDate": "2025-04-15T13:35:48.292127Z",
            "network": null,
            "type": "CREATE_CA_SET_VERSION",
            "version": 1
        },
        {
            "activityBy": "user1",
            "activityDate": "2025-04-15T13:35:48.257574Z",
            "network": null,
            "type": "CREATE_CA_SET",
            "version": null
        }
    ],
    "caSetId": "1",
    "caSetLink": "/mtls-edge-truststore/v2/ca-sets/1",
    "caSetName": "test1",
    "caSetStatus": "DELETED",
    "createdBy": "user1",
    "createdDate": "2025-04-15T13:35:48.211999Z",
    "deletedBy": "user1",
    "deletedDate": "2025-04-18T11:31:40.225213Z"
}`,
			expectedResponse: &ListCASetActivitiesResponse{
				Activities: []CASetActivity{
					{
						ActivityBy:   "user1",
						ActivityDate: test.NewTimeFromString(t, "2025-04-18T11:30:35.866481Z"),
						Network:      ptr.To("PRODUCTION"),
						Type:         "DELETE_CA_SET",
					},
					{
						ActivityBy:   "user1",
						ActivityDate: test.NewTimeFromString(t, "2025-04-18T11:30:35.852930Z"),
						Network:      ptr.To("STAGING"),
						Type:         "DELETE_CA_SET",
					},
					{
						ActivityBy:   "user1",
						ActivityDate: test.NewTimeFromString(t, "2025-04-16T13:14:46.183261Z"),
						Type:         "CREATE_CA_SET_VERSION",
						Version:      ptr.To(int64(2)),
					},
					{
						ActivityBy:   "user1",
						ActivityDate: test.NewTimeFromString(t, "2025-04-15T13:35:48.292127Z"),
						Type:         "CREATE_CA_SET_VERSION",
						Version:      ptr.To(int64(1)),
					},
					{
						ActivityBy:   "user1",
						ActivityDate: test.NewTimeFromString(t, "2025-04-15T13:35:48.257574Z"),
						Type:         "CREATE_CA_SET",
					},
				},
				CASetID:     "1",
				CASetLink:   "/mtls-edge-truststore/v2/ca-sets/1",
				CASetName:   "test1",
				CASetStatus: "DELETED",
				CreatedBy:   "user1",
				CreatedDate: test.NewTimeFromString(t, "2025-04-15T13:35:48.211999Z"),
				DeletedBy:   ptr.To("user1"),
				DeletedDate: ptr.To(test.NewTimeFromString(t, "2025-04-18T11:31:40.225213Z")),
			},
		},
		"200 - all query params": {
			params: ListCASetActivitiesRequest{
				CASetID: "1",
				Start:   test.NewTimeFromString(t, "2025-04-15T14:00:00Z"),
				End:     test.NewTimeFromString(t, "2025-04-17T14:00:00.00000Z"),
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/activities?end=2025-04-17T14%3A00%3A00Z&start=2025-04-15T14%3A00%3A00Z",
			responseStatus: http.StatusOK,
			responseBody: `{
    "activities": [
        {
            "activityBy": "user1",
            "activityDate": "2025-04-16T13:14:46.183261Z",
            "network": null,
            "type": "CREATE_CA_SET_VERSION",
            "version": 2
        }
    ],
    "caSetId": "1",
    "caSetLink": "/mtls-edge-truststore/v2/ca-sets/1",
    "caSetName": "test1",
    "caSetStatus": "DELETED",
    "createdBy": "user1",
    "createdDate": "2025-04-15T13:35:48.211999Z",
    "deletedBy": "user1",
    "deletedDate": "2025-04-18T11:31:40.225213Z"
}`,
			expectedResponse: &ListCASetActivitiesResponse{
				Activities: []CASetActivity{
					{
						ActivityBy:   "user1",
						ActivityDate: test.NewTimeFromString(t, "2025-04-16T13:14:46.183261Z"),
						Type:         "CREATE_CA_SET_VERSION",
						Version:      ptr.To(int64(2)),
					},
				},
				CASetID:     "1",
				CASetLink:   "/mtls-edge-truststore/v2/ca-sets/1",
				CASetName:   "test1",
				CASetStatus: "DELETED",
				CreatedBy:   "user1",
				CreatedDate: test.NewTimeFromString(t, "2025-04-15T13:35:48.211999Z"),
				DeletedBy:   ptr.To("user1"),
				DeletedDate: ptr.To(test.NewTimeFromString(t, "2025-04-18T11:31:40.225213Z")),
			},
		},
		"missing required params - validation error": {
			params: ListCASetActivitiesRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "get ca set activities failed: struct validation: CASetID: cannot be blank", err.Error())
			},
		},
		"404 ca set not found": {
			params: ListCASetActivitiesRequest{
				CASetID: "2",
			},
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/2/activities",
			responseStatus: http.StatusNotFound,
			responseBody: `{
    "contextInfo": {
        "caSetId": "2"
    },
    "detail": "Cannot get CA set activities as the CA set with caSetId 2 is not found.",
    "status": 404,
    "title": "CA set is not found.",
    "type": "/mtls-edge-truststore/error-types/ca-set-not-found"
}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetNotFound), "want: %s; got: %s", ErrGetCASetNotFound, err)
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
			result, err := client.ListCASetActivities(context.Background(), test.params)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}
