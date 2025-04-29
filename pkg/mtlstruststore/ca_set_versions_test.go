package mtlstruststore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v10/pkg/ptr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateCASetVersion(t *testing.T) {
	tests := map[string]struct {
		request             CreateCASetVersionRequest
		responseStatus      int
		responseBody        string
		expectedRequestBody string
		expectedPath        string
		expectedResponse    *CreateCASetVersionResponse
		withError           func(*testing.T, error)
	}{
		"201- Successful creation": {
			request: CreateCASetVersionRequest{
				CASetID: 123,
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
				  "allowInsecureSha1": false,
				  "description": "Test CA Set Version",
				  "certificates": [
					{
					  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
					  "createdBy": "",
					  "createdDate": "",
					  "endDate": "2025-12-31",
					  "fingerprint": "abc123",
					  "issuer": "Test Issuer",
					  "serialNumber": "123456789",
					  "signatureAlgorithm": "",
					  "startDate": "2025-01-01",
					  "subject": "Test Subject"
					}
				  ]}`,
			responseStatus: http.StatusCreated,
			responseBody: `{
				  "caSetId": 123,
				  "version": 1,
				  "caSetName": "Test CA Set",
				  "versionLink": "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
				  "description": "Test CA Set Version",
				  "allowInsecureSha1": false,
				  "stagingStatus": "PENDING",
				  "productionStatus": "PENDING",
				  "createdDate": "2025-04-10T00:00:00Z",
				  "createdBy": "tester",
				  "modifiedDate": "2025-04-10T00:00:00Z",
				  "modifiedBy": "tester",
				  "certificates": [
					{
					  "subject": "Test Subject",
					  "issuer": "Test Issuer",
					  "endDate": "2025-12-31",
					  "startDate": "2025-01-01",
					  "fingerprint": "abc123",
					  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
					  "serialNumber": "123456789",
					  "signatureAlgorithm": "SHA256WithRSA",
					  "createdDate": "2025-04-10T00:00:00Z",
					  "createdBy": "tester"
					}
				  ]
				}`,
			expectedPath: `/mtls-edge-truststore/v2/ca-sets/123/versions`,
			expectedResponse: &CreateCASetVersionResponse{
				CASetID:           123,
				Version:           1,
				CASetName:         "Test CA Set",
				VersionLink:       "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
				Description:       "Test CA Set Version",
				AllowInsecureSha1: false,
				StagingStatus:     "PENDING",
				ProductionStatus:  "PENDING",
				CreatedDate:       "2025-04-10T00:00:00Z",
				CreatedBy:         "tester",
				ModifiedDate:      "2025-04-10T00:00:00Z",
				ModifiedBy:        "tester",
				Certificates: []Certificate{
					{
						Subject:            "Test Subject",
						Issuer:             "Test Issuer",
						EndDate:            "2025-12-31",
						StartDate:          "2025-01-01",
						Fingerprint:        "abc123",
						CertificatePEM:     "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						SerialNumber:       "123456789",
						SignatureAlgorithm: "SHA256WithRSA",
						CreatedDate:        "2025-04-10T00:00:00Z",
						CreatedBy:          "tester",
					},
				},
			},
		},
		"Validation error - CA Set version description greater than max allowed length": {
			request: CreateCASetVersionRequest{
				CASetID: 123,
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version is a critical step in validating and ensuring the correct version of the Certificate Authority (CA) configuration is applied. It involves thorough checks, validation steps, and the verification of certificates to confirm functionality and compliance.",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "creating a CA set version: struct validation: Description: the length must be no more than 255", err.Error())
			},
		},
		"Validation error - missing CASetID": {
			request: CreateCASetVersionRequest{
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Missing CASetID",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "creating a CA set version: struct validation: CASetID: cannot be blank", err.Error())
			},
		},
		"Validation error - missing Certificates": {
			request: CreateCASetVersionRequest{
				CASetID: 1,
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Missing CASetID",
				},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "creating a CA set version: struct validation: Certificates: cannot be blank", err.Error())
			},
		},
		"Validation error - missing Certificates.CertificatePEM": {
			request: CreateCASetVersionRequest{
				CASetID: 1,
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Missing CASetID",
					Certificates: []Certificate{
						{
							Subject:      "Test Subject",
							Issuer:       "Test Issuer",
							EndDate:      "2025-12-31",
							StartDate:    "2025-01-01",
							Fingerprint:  "abc123",
							SerialNumber: "123456789",
						},
					},
				},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "creating a CA set version: struct validation: Certificates[0]: {\n\tCertificatePEM: cannot be blank\n}", err.Error())
			},
		},
		"Validation error - Certificate's description greater than max allowed length": {
			request: CreateCASetVersionRequest{
				CASetID: 123,
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
							Description:    "Test CA Set Version is a critical step in validating and ensuring the correct version of the Certificate Authority (CA) configuration is applied. It involves thorough checks, validation steps, and the verification of certificates to confirm functionality and compliance.",
						},
					},
				},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "creating a CA set version: struct validation: Certificates[0]: {\n\tDescription: the length must be no more than 255\n}", err.Error())
			},
		},
		"Error Response - CA set is not found": {
			request: CreateCASetVersionRequest{
				CASetID: 123,
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
				  "allowInsecureSha1": false,
				  "description": "Test CA Set Version",
				  "certificates": [
					{
					  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
					  "createdBy": "",
					  "createdDate": "",
					  "endDate": "2025-12-31",
					  "fingerprint": "abc123",
					  "issuer": "Test Issuer",
					  "serialNumber": "123456789",
					  "signatureAlgorithm": "",
					  "startDate": "2025-01-01",
					  "subject": "Test Subject"
					}
				  ]}`,
			responseStatus: http.StatusNotFound,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions",
			responseBody: `
					{
  						"type": "/mtls-edge-truststore/v2/error-types/ca-set-not-found",
  						"title": "CA set is not found.",
  						"status": 404,
  						"detail": "Cannot create a CA set version as the CA set with caSetId 123 is not found.",
  						"contextInfo": {
    						"caSetId": 123
						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetNotFound))
			},
		},
		"Error Response - Number of CA Set versions has reached the limit": {
			request: CreateCASetVersionRequest{
				CASetID: 1,
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
				  "allowInsecureSha1": false,
				  "description": "Test CA Set Version",
				  "certificates": [
					{
					  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
					  "createdBy": "",
					  "createdDate": "",
					  "endDate": "2025-12-31",
					  "fingerprint": "abc123",
					  "issuer": "Test Issuer",
					  "serialNumber": "123456789",
					  "signatureAlgorithm": "",
					  "startDate": "2025-01-01",
					  "subject": "Test Subject"
					}
				  ]}`,
			responseStatus: http.StatusUnprocessableEntity,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/versions",
			responseBody: `
					{
						"type": "/mtls-edge-truststore/v2/error-types/ca-set-version-limit-reached",
						"title": "Maximum allowed CA set version's limit has been reached.",
						"status": 422,
						"detail": "Cannot create CA set version as you have already reached or exceeded the maximum allowed CA set version limit of 10 for the CA set with caSetId 1.",
						"contextInfo": {
							"caSetName": "test",
							"caSetId": 1,
							"maxVersionsPerCaSet": 10
						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCaSetVersionLimitReached))
			},
		},
		"Error Response - Maximum allowed certificates in a version limit reached": {
			request: CreateCASetVersionRequest{
				CASetID: 1,
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
						// Assume repeated to make count 302
					},
				},
			},
			expectedRequestBody: `{
				  "allowInsecureSha1": false,
				  "description": "Test CA Set Version",
				  "certificates": [
					{
					  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
					  "createdBy": "",
					  "createdDate": "",
					  "endDate": "2025-12-31",
					  "fingerprint": "abc123",
					  "issuer": "Test Issuer",
					  "serialNumber": "123456789",
					  "signatureAlgorithm": "",
					  "startDate": "2025-01-01",
					  "subject": "Test Subject"
					}
				  ]}`,
			responseStatus: http.StatusUnprocessableEntity,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/versions",
			responseBody: `
					{
						"type": "/mtls-edge-truststore/v2/error-types/certificate-limit-reached",
						"title": "Submitted certificates exceed the maximum allowed certificates limit.",
						"status": 422,
						"detail": "The maximum number of certificates allowed per CA set version is 300. Number of submitted certificates is 302.",
						"contextInfo": {
							"caSetName": "test",
							"caSetId": 1,
							"maxCertificatesPerVersion": 300,
							"submittedCertificatesCount": 302
						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCertificateLimitReached))
			},
		},
		"Error Response - At least one certificate has failed validation": {
			request: CreateCASetVersionRequest{
				CASetID: 131803,
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "EMAILADDRESS=test@akamai.com, CN=test, OU=DELIVERY, O=AKAMAI, L=BLR, ST=KA, C=IN",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "fingerebc8de3270598ec1fa62c92a20ef86d53bca415978b40733afaa8b09082",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
				  "allowInsecureSha1": false,
				  "description": "Test CA Set Version",
				  "certificates": [
					{
					  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
					  "createdBy": "",
					  "createdDate": "",
					  "endDate": "2025-12-31",
					  "fingerprint": "fingerebc8de3270598ec1fa62c92a20ef86d53bca415978b40733afaa8b09082",
					  "issuer": "Test Issuer",
					  "serialNumber": "123456789",
					  "signatureAlgorithm": "",
					  "startDate": "2025-01-01",
					  "subject": "EMAILADDRESS=test@akamai.com, CN=test, OU=DELIVERY, O=AKAMAI, L=BLR, ST=KA, C=IN"
					}
				  ]}`,
			responseStatus: http.StatusBadRequest,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/131803/versions",
			responseBody: `
		{
			"type": "/mtls-edge-truststore/v2/error-types/certificate-validation-failure-create",
			"title": "Cannot create the ca set version as the certificate(s) has failed validation.",
			"status": 400,
			"contextInfo": {
				"caSetId": 131803,
				"caSetName": "sup-m2-bugjam6"
			},
			"errors": [
				{
					"detail": "The certificate with subject EMAILADDRESS=test@akamai.com, CN=test, OU=DELIVERY, O=AKAMAI, L=BLR, ST=KA, C=IN and fingerprint fingerebc8de3270598ec1fa62c92a20ef86d53bca415978b40733afaa8b09082 uses disallowed signature algorithm SHA1WITHRSA. Allow InsecureSha1 option is not set. This is not allowed.",
					"pointer": "/certificates/0",
					"contextInfo": {
						"description": null,
						"fingerPrint": "fingerebc8de3270598ec1fa62c92a20ef86d53bca415978b40733afaa8b09082",
						"signatureAlgorithm": "SHA1WITHRSA",
						"subject": "EMAILADDRESS=test@akamai.com, CN=test, OU=DELIVERY, O=AKAMAI, L=BLR, ST=KA, C=IN"
					}
				},
				{
					"detail": "The certificate with subject CN=expired-sha1.example.com, OU=Test Unit, O=Test Organization, L=Test City, ST=Test State, C=US and fingerprint finger514689701ac2e3b0a0893fc8500d233d20b7e148f3da68f123bea7dd47c has expired. Expiry date is 2025-01-05T11:19:25Z. The check was performed on 2025-04-10T21:23:48Z.",
					"pointer": "/certificates/0",
					"contextInfo": {
						"description": "expiredSha1Certificate",
						"fingerPrint": "finger514689701ac2e3b0a0893fc8500d233d20b7e148f3da68f123bea7dd47c",
						"expiryDate": "2025-01-05T11:19:25Z",
						"checkDate": "2025-04-10T21:23:48Z",
						"subject": "CN=expired-sha1.example.com, OU=Test Unit, O=Test Organization, L=Test City, ST=Test State, C=US"
					}
				}
			]
		}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCertificateValidationFailedForCreate))
			},
		},
		"Error Response - Deletion in progress for the CA Set on any network": {
			request: CreateCASetVersionRequest{
				CASetID: 1,
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
				  "allowInsecureSha1": false,
				  "description": "Test CA Set Version",
				  "certificates": [
					{
					  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
					  "createdBy": "",
					  "createdDate": "",
					  "endDate": "2025-12-31",
					  "fingerprint": "abc123",
					  "issuer": "Test Issuer",
					  "serialNumber": "123456789",
					  "signatureAlgorithm": "",
					  "startDate": "2025-01-01",
					  "subject": "Test Subject"
					}
				  ]}`,
			responseStatus: http.StatusConflict,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/versions",
			responseBody: `
        {
            "type": "/mtls-edge-truststore/v2/error-types/delete-ca-set-request-in-progress",
            "title": "DELETE request is in progress for the CA set on the network.",
            "status": 409,
            "detail": "Cannot create CA set version as the CA set is being deleted on one or more networks.",
            "contextInfo": {
                "caSetId": 1,
                "caSetName": "caSetName-73f58a4e",
                "deletionLink": "/mtls-edge-truststore/v2/ca-sets/1/status/delete",
                "productionStatus": "IN_PROGRESS",
                "stagingStatus": "IN_PROGRESS",
                "version": 1
            }
        }`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCASetDeleteRequestInProgress))
			},
		},
		"Error Response - Duplicate Version": {
			request: CreateCASetVersionRequest{
				CASetID: 1,
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
				  "allowInsecureSha1": false,
				  "description": "Test CA Set Version",
				  "certificates": [
					{
					  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
					  "createdBy": "",
					  "createdDate": "",
					  "endDate": "2025-12-31",
					  "fingerprint": "abc123",
					  "issuer": "Test Issuer",
					  "serialNumber": "123456789",
					  "signatureAlgorithm": "",
					  "startDate": "2025-01-01",
					  "subject": "Test Subject"
					}
				  ]}`,
			responseStatus: http.StatusUnprocessableEntity,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/versions",
			responseBody: `
        {
            "type": "/mtls-edge-truststore/v2/error-types/duplicate-ca-set-version",
            "title": "A version with same certificates exists in the CA set.",
            "status": 422,
            "detail": "A version with same certificates exists in the CA set.",
            "contextInfo": {
                "caSetName": "tést",
                "caSetId": 1,
                "versionLink": "/tcm-api/ca-sets/1/versions/1"
            }
        }`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCaSetVersionIsDuplicate))
			},
		},
		//"[TODO: Warning in Response] Warning Response - Body contains duplicate certificates (based on fingerPrint)":{},
		"Internal server error": {
			request: CreateCASetVersionRequest{
				CASetID: 123,
				Body: CreateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
				  "allowInsecureSha1": false,
				  "description": "Test CA Set Version",
				  "certificates": [
					{
					  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
					  "createdBy": "",
					  "createdDate": "",
					  "endDate": "2025-12-31",
					  "fingerprint": "abc123",
					  "issuer": "Test Issuer",
					  "serialNumber": "123456789",
					  "signatureAlgorithm": "",
					  "startDate": "2025-01-01",
					  "subject": "Test Subject"
					}
				  ]}`,
			responseStatus: http.StatusInternalServerError,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions",
			responseBody: `
					{
						"type": "internal_error",
						"title": "Internal Server Error",
						"detail": "Error processing request",
						"status": 500
					}`,
			withError: func(t *testing.T, err error) {
				want := &Error{
					Type:        "internal_error",
					Title:       "Internal Server Error",
					Detail:      "Error processing request",
					Status:      http.StatusInternalServerError,
					ContextInfo: nil,
					Errors:      nil,
					Instance:    "",
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
				w.WriteHeader(test.responseStatus)
				_, err := w.Write([]byte(test.responseBody))
				assert.NoError(t, err)

				if len(test.expectedRequestBody) > 0 {
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					assert.JSONEq(t, test.expectedRequestBody, string(body))
				}
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.CreateCASetVersion(context.Background(), test.request)
			if test.withError != nil {
				if test.withError != nil {
					test.withError(t, err)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestCloneCASetVersion(t *testing.T) {
	tests := map[string]struct {
		request          CloneCASetVersionRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *CloneCASetVersionResponse
		withError        func(*testing.T, error)
	}{
		"201- Successful creation": {
			request: CloneCASetVersionRequest{
				CASetID: 123,
				Version: 1,
			},
			responseStatus: http.StatusCreated,
			responseBody: `
					{
					  "caSetId": 123,
					  "version": 1,
					  "caSetName": "Test CA Set",
					  "versionLink": "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
					  "description": "Test CA Set Version",
					  "allowInsecureSha1": false,
					  "stagingStatus": "PENDING",
					  "productionStatus": "PENDING",
					  "createdDate": "2025-04-10T00:00:00Z",
					  "createdBy": "tester",
					  "modifiedDate": "2025-04-10T00:00:00Z",
					  "modifiedBy": "tester",
					  "certificates": [
						{
						  "subject": "Test Subject",
						  "issuer": "Test Issuer",
						  "endDate": "2025-12-31",
						  "startDate": "2025-01-01",
						  "fingerprint": "abc123",
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "SHA256WithRSA",
						  "createdDate": "2025-04-10T00:00:00Z",
						  "createdBy": "tester"
						}
					  ]
					}`,
			expectedPath: `/mtls-edge-truststore/v2/ca-sets/123/versions/1/clone`,
			expectedResponse: &CloneCASetVersionResponse{
				CASetID:           123,
				Version:           1,
				CASetName:         "Test CA Set",
				VersionLink:       "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
				Description:       "Test CA Set Version",
				AllowInsecureSha1: false,
				StagingStatus:     "PENDING",
				ProductionStatus:  "PENDING",
				CreatedDate:       "2025-04-10T00:00:00Z",
				CreatedBy:         "tester",
				ModifiedDate:      "2025-04-10T00:00:00Z",
				ModifiedBy:        "tester",
				Certificates: []Certificate{
					{
						Subject:            "Test Subject",
						Issuer:             "Test Issuer",
						EndDate:            "2025-12-31",
						StartDate:          "2025-01-01",
						Fingerprint:        "abc123",
						CertificatePEM:     "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						SerialNumber:       "123456789",
						SignatureAlgorithm: "SHA256WithRSA",
						CreatedDate:        "2025-04-10T00:00:00Z",
						CreatedBy:          "tester",
					},
				},
			},
		},
		"Validation error - missing CASetID and Version": {
			request: CloneCASetVersionRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "cloning a CA set version: struct validation: CaSetID: cannot be blank; Version: cannot be blank.", err.Error())
			},
		},
		"Error Response - CA set is not found": {
			request: CloneCASetVersionRequest{
				CASetID: 123,
				Version: 1,
			},
			responseStatus: http.StatusNotFound,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/1/clone",
			responseBody: `
					{
  						"type": "/mtls-edge-truststore/v2/error-types/ca-set-not-found",
  						"title": "CA set is not found.",
  						"status": 404,
  						"detail": "Cannot create a CA set version as the CA set with caSetId 123 is not found.",
  						"contextInfo": {
    						"caSetId": 123
						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetNotFound))
			},
		},
		"Error Response - CA set version not found": {
			request: CloneCASetVersionRequest{
				CASetID: 123,
				Version: 12,
			},
			responseStatus: http.StatusNotFound,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/12/clone",
			responseBody: `
					{
				  		"type": "/mtls-edge-truststore/v2/error-types/ca-set-version-not-found",
				  		"title": "CA set version cannot be cloned",
				  		"status": 404,
				  		"detail": "Cannot clone CA set version as the CA set version with version 12 is not found in the CA set with caSetId 123.",
				  		"contextInfo": {
							"caSetName": "test1",
							"caSetId": 123,
							"version": 12
				  		}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetVersionNotFound))
			},
		},
		"Error Response - Deletion in progress for the CA Set on any network": {
			request: CloneCASetVersionRequest{
				CASetID: 1,
				Version: 1,
			},
			responseStatus: http.StatusConflict,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/versions/1/clone",
			responseBody: `
        {
            "type": "/mtls-edge-truststore/v2/error-types/delete-ca-set-request-in-progress",
            "title": "DELETE request is in progress for the CA set on the network.",
            "status": 409,
            "detail": "Cannot clone CA set version as the CA set is being deleted on one or more networks.",
            "contextInfo": {
                "caSetId": 1,
                "caSetName": "caSetName-26250641",
                "deletionLink": "/mtls-edge-truststore/v2/ca-sets/1/status/delete",
                "productionStatus": "IN_PROGRESS",
                "stagingStatus": "IN_PROGRESS",
                "version": 1
            }
        }`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCASetDeleteRequestInProgress))
			},
		},
		//"[TODO: Warning in Response] Error Response - Clone CA set version with expired certs": {},
		"Error Response - Maximum allowed versions in a CA set limit reached": {
			request: CloneCASetVersionRequest{
				CASetID: 1,
				Version: 10,
			},
			responseStatus: http.StatusUnprocessableEntity,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/versions/10/clone",
			responseBody: `
					{
						"type": "/mtls-edge-truststore/v2/error-types/ca-set-version-limit-reached",
						"title": "Maximum allowed CA set version's limit has been reached.",
						"status": 422,
						"detail": "Cannot clone CA set version as you have already reached or exceeded the maximum allowed CA set version limit of 10 for the CA set with caSetName test.",
						"contextInfo": {
							"caSetName": "test",
							"caSetId": 1,
							"maxVersionsPerCaSet": 10
						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCaSetVersionLimitReached))
			},
		},
		"Internal server error": {
			request: CloneCASetVersionRequest{
				CASetID: 123,
				Version: 1,
			},
			responseStatus: http.StatusInternalServerError,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/1/clone",
			responseBody: `
					{
						"type": "internal_error",
						"title": "Internal Server Error",
						"detail": "Error processing request",
						"status": 500
					}`,
			withError: func(t *testing.T, err error) {
				want := &Error{
					Type:        "internal_error",
					Title:       "Internal Server Error",
					Detail:      "Error processing request",
					Status:      http.StatusInternalServerError,
					ContextInfo: nil,
					Errors:      nil,
					Instance:    "",
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
				w.WriteHeader(test.responseStatus)
				_, err := w.Write([]byte(test.responseBody))
				assert.NoError(t, err)
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.CloneCASetVersion(context.Background(), test.request)
			if test.withError != nil {
				if test.withError != nil {
					test.withError(t, err)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestGetCASetVersion(t *testing.T) {
	tests := map[string]struct {
		request          GetCASetVersionRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *GetCASetVersionResponse
		withError        func(*testing.T, error)
	}{
		"200- Successful get version": {
			request: GetCASetVersionRequest{
				CASetID: 123,
				Version: 1,
			},
			responseStatus: http.StatusOK,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
			responseBody: `{
				"caSetId":123,
				"version":1,
				"caSetName":"Test CA Set",
				"versionLink":"/mtls-edge-truststore/v2/ca-sets/123/versions/1",
				"description":"Test CA Set Version",
				"allowInsecureSha1":false,
				"stagingStatus":"PENDING",
				"productionStatus":"PENDING",
				"createdDate":"2025-04-10T00:00:00Z",
				"createdBy":"tester",
				"modifiedDate":"2025-04-10T00:00:00Z",
				"modifiedBy":"tester",
				"certificates":[
					{
						"subject":"Test Subject",
						"issuer":"Test Issuer",
						"endDate":"2025-12-31",
						"startDate":"2025-01-01",
						"fingerprint":"abc123",
						"certificatePem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						"serialNumber":"123456789",
						"signatureAlgorithm":"SHA256WithRSA",
						"createdDate":"2025-04-10T00:00:00Z",
						"createdBy":"tester"
					}
				]
			}`,
			expectedResponse: &GetCASetVersionResponse{
				CASetID:           123,
				Version:           1,
				CASetName:         "Test CA Set",
				VersionLink:       "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
				Description:       "Test CA Set Version",
				AllowInsecureSha1: false,
				StagingStatus:     "PENDING",
				ProductionStatus:  "PENDING",
				CreatedDate:       "2025-04-10T00:00:00Z",
				CreatedBy:         "tester",
				ModifiedDate:      "2025-04-10T00:00:00Z",
				ModifiedBy:        "tester",
				Certificates: []Certificate{
					{
						Subject:            "Test Subject",
						Issuer:             "Test Issuer",
						EndDate:            "2025-12-31",
						StartDate:          "2025-01-01",
						Fingerprint:        "abc123",
						CertificatePEM:     "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						SerialNumber:       "123456789",
						SignatureAlgorithm: "SHA256WithRSA",
						CreatedDate:        "2025-04-10T00:00:00Z",
						CreatedBy:          "tester",
					},
				},
			},
		},
		"Validation error - missing CASetID and Version": {
			request: GetCASetVersionRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "fetching a CA set version: struct validation: CaSetID: cannot be blank; Version: cannot be blank.", err.Error())
			},
		},
		"Error Response - CA set not found": {
			request: GetCASetVersionRequest{
				CASetID: 123,
				Version: 1,
			},
			responseStatus: http.StatusNotFound,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
			responseBody: `
					{
  						"type": "/mtls-edge-truststore/v2/error-types/ca-set-not-found",
  						"title": "CA set not found.",
  						"status": 404,
  						"detail": "Cannot get CA set version as the CA set with caSetId 123 is not found.",
  						"contextInfo": {
							"caSetId": 123
  						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetNotFound))
			},
		},
		"Error Response - CA set version not found": {
			request: GetCASetVersionRequest{
				CASetID: 123,
				Version: 12,
			},
			responseStatus: http.StatusNotFound,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/12",
			responseBody: `
					{
  						"type": "/mtls-edge-truststore/v2/error-types/ca-set-version-not-found",
  						"title": "CA set version not found",
  						"status": 404,
  						"detail": "Cannot get CA set as the CA set version with version 12 is not found in the CA set with caSetId 123",
  						"contextInfo": {
							"caSetName": "test1",
    						"caSetId": 123,
    						"version": 12
  						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetVersionNotFound))
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
			defer mockServer.Close()

			client := mockAPIClient(t, mockServer)
			result, err := client.GetCASetVersion(context.Background(), test.request)

			if test.withError != nil {
				test.withError(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestUpdateCASetVersion(t *testing.T) {
	tests := map[string]struct {
		request             UpdateCASetVersionRequest
		responseStatus      int
		responseBody        string
		expectedPath        string
		expectedRequestBody string
		expectedResponse    *UpdateCASetVersionResponse
		withError           func(*testing.T, error)
	}{
		"200- Successful update": {
			request: UpdateCASetVersionRequest{
				CASetID: 123,
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
					  "allowInsecureSha1": false,
					  "caSetName": "",
					  "certificates": [
						{
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "createdBy": "",
						  "createdDate": "",
						  "endDate": "2025-12-31",
						  "fingerprint": "abc123",
						  "issuer": "Test Issuer",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "",
						  "startDate": "2025-01-01",
						  "subject": "Test Subject"
						}
					  ],
					  "createdBy": "",
					  "createdDate": "",
					  "description": "Test CA Set Version",
					  "modifiedBy": "",
					  "modifiedDate": "",
					  "productionStatus": "",
					  "stagingStatus": "",
					  "version": 1,
					  "versionLink": ""
					}`,
			responseStatus: http.StatusOK,
			responseBody: `
					{
					  "caSetId": 123,
					  "version": 1,
					  "caSetName": "Test CA Set",
					  "versionLink": "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
					  "description": "Test CA Set Version",
					  "allowInsecureSha1": false,
					  "stagingStatus": "PENDING",
					  "productionStatus": "PENDING",
					  "createdDate": "2025-04-10T00:00:00Z",
					  "createdBy": "tester",
					  "modifiedDate": "2025-04-10T00:00:00Z",
					  "modifiedBy": "tester",
					  "certificates": [
						{
						  "subject": "Test Subject",
						  "issuer": "Test Issuer",
						  "endDate": "2025-12-31",
						  "startDate": "2025-01-01",
						  "fingerprint": "abc123",
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "SHA256WithRSA",
						  "createdDate": "2025-04-10T00:00:00Z",
						  "createdBy": "tester"
						}
					  ]
					}`,
			expectedPath: `/mtls-edge-truststore/v2/ca-sets/123/versions/1`,
			expectedResponse: &UpdateCASetVersionResponse{
				CASetID:           123,
				Version:           1,
				CASetName:         "Test CA Set",
				VersionLink:       "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
				Description:       "Test CA Set Version",
				AllowInsecureSha1: false,
				StagingStatus:     "PENDING",
				ProductionStatus:  "PENDING",
				CreatedDate:       "2025-04-10T00:00:00Z",
				CreatedBy:         "tester",
				ModifiedDate:      "2025-04-10T00:00:00Z",
				ModifiedBy:        "tester",
				Certificates: []Certificate{
					{
						Subject:            "Test Subject",
						Issuer:             "Test Issuer",
						EndDate:            "2025-12-31",
						StartDate:          "2025-01-01",
						Fingerprint:        "abc123",
						CertificatePEM:     "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						SerialNumber:       "123456789",
						SignatureAlgorithm: "SHA256WithRSA",
						CreatedDate:        "2025-04-10T00:00:00Z",
						CreatedBy:          "tester",
					},
				},
			},
		},
		"Validation error - CA Set version description greater than max allowed length": {
			request: UpdateCASetVersionRequest{
				CASetID: 123,
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version is a critical step in validating and ensuring the correct version of the Certificate Authority (CA) configuration is applied. It involves thorough checks, validation steps, and the verification of certificates to confirm functionality and compliance.",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "updating a CA set version: struct validation: Description: the length must be no more than 255", err.Error())
			},
		},
		"Validation error - missing CASetID": {
			request: UpdateCASetVersionRequest{
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Missing CASetID",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "updating a CA set version: struct validation: CASetID: cannot be blank", err.Error())
			},
		},
		"Validation error - missing Version": {
			request: UpdateCASetVersionRequest{
				CASetID: 1,
				Body: UpdateCASetVersionRequestBody{
					AllowInsecureSHA1: false,
					Description:       "Missing CASetID",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "updating a CA set version: struct validation: Version: cannot be blank", err.Error())
			},
		},
		"Validation error - missing Certificates": {
			request: UpdateCASetVersionRequest{
				CASetID: 1,
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Missing CASetID",
				},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "updating a CA set version: struct validation: Certificates: cannot be blank", err.Error())
			},
		},
		"Validation error - missing Certificates.CertificatePEM": {
			request: UpdateCASetVersionRequest{
				CASetID: 1,
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Missing CASetID",
					Certificates: []Certificate{
						{
							Subject:      "Test Subject",
							Issuer:       "Test Issuer",
							EndDate:      "2025-12-31",
							StartDate:    "2025-01-01",
							Fingerprint:  "abc123",
							SerialNumber: "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
					  "allowInsecureSha1": false,
					  "caSetName": "",
					  "certificates": [
						{
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "createdBy": "",
						  "createdDate": "",
						  "endDate": "2025-12-31",
						  "fingerprint": "abc123",
						  "issuer": "Test Issuer",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "",
						  "startDate": "2025-01-01",
						  "subject": "Test Subject"
						}
					  ],
					  "createdBy": "",
					  "createdDate": "",
					  "description": "Test CA Set Version",
					  "modifiedBy": "",
					  "modifiedDate": "",
					  "productionStatus": "",
					  "stagingStatus": "",
					  "version": 1,
					  "versionLink": ""
					}`,
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "updating a CA set version: struct validation: Certificates[0]: {\n\tCertificatePEM: cannot be blank\n}", err.Error())
			},
		},
		"Error Response - CA set not found": {
			request: UpdateCASetVersionRequest{
				CASetID: 123,
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
					  "allowInsecureSha1": false,
					  "caSetName": "",
					  "certificates": [
						{
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "createdBy": "",
						  "createdDate": "",
						  "endDate": "2025-12-31",
						  "fingerprint": "abc123",
						  "issuer": "Test Issuer",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "",
						  "startDate": "2025-01-01",
						  "subject": "Test Subject"
						}
					  ],
					  "createdBy": "",
					  "createdDate": "",
					  "description": "Test CA Set Version",
					  "modifiedBy": "",
					  "modifiedDate": "",
					  "productionStatus": "",
					  "stagingStatus": "",
					  "version": 1,
					  "versionLink": ""
					}`,
			responseStatus: http.StatusNotFound,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
			responseBody: `
					{
  						"type": "/mtls-edge-truststore/v2/error-types/ca-set-not-found",
  						"title": "CA set is not found.",
  						"status": 404,
  						"detail": "Cannot create a CA set version as the CA set with caSetId 123 is not found.",
  						"contextInfo": {
    						"caSetId": 123
						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetNotFound))
			},
		},
		"Error Response - CA set version not found": {
			request: UpdateCASetVersionRequest{
				CASetID: 123,
				Body: UpdateCASetVersionRequestBody{
					Version:           12,
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
					  "allowInsecureSha1": false,
					  "caSetName": "",
					  "certificates": [
						{
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "createdBy": "",
						  "createdDate": "",
						  "endDate": "2025-12-31",
						  "fingerprint": "abc123",
						  "issuer": "Test Issuer",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "",
						  "startDate": "2025-01-01",
						  "subject": "Test Subject"
						}
					  ],
					  "createdBy": "",
					  "createdDate": "",
					  "description": "Test CA Set Version",
					  "modifiedBy": "",
					  "modifiedDate": "",
					  "productionStatus": "",
					  "stagingStatus": "",
					  "version": 12,
					  "versionLink": ""
					}`,
			responseStatus: http.StatusNotFound,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/12",
			responseBody: `
					{
  						"type": "/mtls-edge-truststore/v2/error-types/ca-set-version-not-found",
  						"title": "CA set is not found.",
  						"status": 404,
  						"detail": "Cannot create a CA set version as the CA set with caSetId 123 is not found.",
  						"contextInfo": {
    						"caSetName": "test1",
							"caSetId": 2,
							"version": 12
						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetVersionNotFound))
			},
		},
		"Error Response - Deletion in progress for the CA Set on any network": {
			request: UpdateCASetVersionRequest{
				CASetID: 1,
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
					  "allowInsecureSha1": false,
					  "caSetName": "",
					  "certificates": [
						{
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "createdBy": "",
						  "createdDate": "",
						  "endDate": "2025-12-31",
						  "fingerprint": "abc123",
						  "issuer": "Test Issuer",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "",
						  "startDate": "2025-01-01",
						  "subject": "Test Subject"
						}
					  ],
					  "createdBy": "",
					  "createdDate": "",
					  "description": "Test CA Set Version",
					  "modifiedBy": "",
					  "modifiedDate": "",
					  "productionStatus": "",
					  "stagingStatus": "",
					  "version": 1,
					  "versionLink": ""
					}`,
			responseStatus: http.StatusConflict,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/versions/1",
			responseBody: `
					{
						"type": "/mtls-edge-truststore/v2/error-types/delete-ca-set-request-in-progress",
						"title": "DELETE request is in progress for the CA set on the network.",
						"status": 409,
						"detail": "Cannot update CA set version as the CA set is being deleted on one or more networks.",
						"contextInfo": {
							"caSetId": 1,
							"caSetName": "caSetName-123",
							"deletionLink": "/mtls-edge-truststore/v2/ca-sets/1/status/delete",
							"productionStatus": "IN_PROGRESS",
							"stagingStatus": "IN_PROGRESS",
							"version": 1
						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCASetDeleteRequestInProgress))
			},
		},
		"Error Response - Version is being activated or deactivated on either network (STAGING or PRODUCTION)": {
			request: UpdateCASetVersionRequest{
				CASetID: 1,
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
					  "allowInsecureSha1": false,
					  "caSetName": "",
					  "certificates": [
						{
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "createdBy": "",
						  "createdDate": "",
						  "endDate": "2025-12-31",
						  "fingerprint": "abc123",
						  "issuer": "Test Issuer",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "",
						  "startDate": "2025-01-01",
						  "subject": "Test Subject"
						}
					  ],
					  "createdBy": "",
					  "createdDate": "",
					  "description": "Test CA Set Version",
					  "modifiedBy": "",
					  "modifiedDate": "",
					  "productionStatus": "",
					  "stagingStatus": "",
					  "version": 1,
					  "versionLink": ""
					}`,
			responseStatus: http.StatusUnprocessableEntity,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/versions/1",
			responseBody: `
					{
						"type": "/mtls-edge-truststore/v2/error-types/ca-set-version-is-active",
						"title": "CA set version is currently active.",
						"status": 422,
						"detail": "Cannot update the CA set version with version 1 as it is active on production network.",
						"contextInfo": {
							"caSetId": 1,
							"caSetName": "tést",
							"version": 1
						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCASetVersionIsActive))
			},
		},
		"Error Response - CA set version is currently active (Production)": {
			request: UpdateCASetVersionRequest{
				CASetID: 1,
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
					  "allowInsecureSha1": false,
					  "caSetName": "",
					  "certificates": [
						{
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "createdBy": "",
						  "createdDate": "",
						  "endDate": "2025-12-31",
						  "fingerprint": "abc123",
						  "issuer": "Test Issuer",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "",
						  "startDate": "2025-01-01",
						  "subject": "Test Subject"
						}
					  ],
					  "createdBy": "",
					  "createdDate": "",
					  "description": "Test CA Set Version",
					  "modifiedBy": "",
					  "modifiedDate": "",
					  "productionStatus": "",
					  "stagingStatus": "",
					  "version": 1,
					  "versionLink": ""
					}`,
			responseStatus: http.StatusUnprocessableEntity,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/versions/1",
			responseBody: `
		{
			"contextInfo": {
				"caSetId": 1,
				"caSetName": "tést",
				"version": 1
			},
			"detail": "Cannot update the CA set version with version 1 as it is active on production network.",
			"status": 422,
			"title": "CA set version is currently active.",
			"type": "/mtls-edge-truststore/v2/error-types/ca-set-version-is-active"
		}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCASetVersionIsActive))
			},
		},
		"Error Response - CA set version is currently active (Staging)": {
			request: UpdateCASetVersionRequest{
				CASetID: 1,
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
					  "allowInsecureSha1": false,
					  "caSetName": "",
					  "certificates": [
						{
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "createdBy": "",
						  "createdDate": "",
						  "endDate": "2025-12-31",
						  "fingerprint": "abc123",
						  "issuer": "Test Issuer",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "",
						  "startDate": "2025-01-01",
						  "subject": "Test Subject"
						}
					  ],
					  "createdBy": "",
					  "createdDate": "",
					  "description": "Test CA Set Version",
					  "modifiedBy": "",
					  "modifiedDate": "",
					  "productionStatus": "",
					  "stagingStatus": "",
					  "version": 1,
					  "versionLink": ""
					}`,
			responseStatus: http.StatusUnprocessableEntity,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/1/versions/1",
			responseBody: `
		{
			"type": "/mtls-edge-truststore/v2/error-types/ca-set-version-is-active",
			"title": "CA set version is currently active.",
			"status": 422,
			"detail": "Cannot update the CA set version with version 1 as it is  active on staging network/s.",
			"contextInfo": {
				"caSetName": "tést",
				"caSetId": 1,
				"version": 1
			}
		}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCASetVersionIsActive))
			},
		},
		"Error Response - CA set version was previously active": {
			request: UpdateCASetVersionRequest{
				CASetID: 123,
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
					  "allowInsecureSha1": false,
					  "caSetName": "",
					  "certificates": [
						{
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "createdBy": "",
						  "createdDate": "",
						  "endDate": "2025-12-31",
						  "fingerprint": "abc123",
						  "issuer": "Test Issuer",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "",
						  "startDate": "2025-01-01",
						  "subject": "Test Subject"
						}
					  ],
					  "createdBy": "",
					  "createdDate": "",
					  "description": "Test CA Set Version",
					  "modifiedBy": "",
					  "modifiedDate": "",
					  "productionStatus": "",
					  "stagingStatus": "",
					  "version": 1,
					  "versionLink": ""
					}`,
			responseStatus: http.StatusUnprocessableEntity,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
			responseBody: `
		{
			"contextInfo": {
				"caSetId": 123,
				"caSetName": "1.13_bc_testing-COPY",
				"version": 1
			},
			"detail": "Cannot update the CA set version with version 1 as it was previously active on one ore more networks.",
			"status": 422,
			"title": "CA set version was previously active.",
			"type": "/mtls-edge-truststore/v2/error-types/ca-set-version-was-previously-active"
		}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCASetVersionWasPreviouslyActive))
			},
		},
		"Error Response - One or more certificates is invalid": {
			request: UpdateCASetVersionRequest{
				CASetID: 123,
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
					  "allowInsecureSha1": false,
					  "caSetName": "",
					  "certificates": [
						{
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "createdBy": "",
						  "createdDate": "",
						  "endDate": "2025-12-31",
						  "fingerprint": "abc123",
						  "issuer": "Test Issuer",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "",
						  "startDate": "2025-01-01",
						  "subject": "Test Subject"
						}
					  ],
					  "createdBy": "",
					  "createdDate": "",
					  "description": "Test CA Set Version",
					  "modifiedBy": "",
					  "modifiedDate": "",
					  "productionStatus": "",
					  "stagingStatus": "",
					  "version": 1,
					  "versionLink": ""
					}`,
			responseStatus: http.StatusBadRequest,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
			responseBody: `
		{
			"contextInfo": {
				"caSetId": 123,
				"caSetName": "test ca set",
				"version": 1
			},
			"errors": [
				{
					"contextInfo": {
						"description": "new description",
						"fingerPrint": "fingerebc8de3270598ec1fa62c92a20ef86d53bca415978b40733afaa8b09082",
						"signatureAlgorithm": "SHA1WITHRSA",
						"subject": "EMAILADDRESS=test@akamai.com, CN=test, OU=DELIVERY, O=AKAMAI, L=BLR, ST=KA, C=IN"
					},
					"detail": "The certificate with subject EMAILADDRESS=test@akamai.com, CN=test, OU=DELIVERY, O=AKAMAI, L=BLR, ST=KA, C=IN and fingerprint fingerebc8de3270598ec1fa62c92a20ef86d53bca415978b40733afaa8b09082 uses disallowed signature algorithm SHA1WITHRSA. Allow InsecureSha1 option is not set. This is not allowed.",
					"pointer": "/certificates/0"
				}
			],
			"status": 400,
			"title": "Cannot update the ca set version as the certificate(s) has failed validation.",
			"type": "/mtls-edge-truststore/v2/error-types/certificate-validation-failure-update"
		}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCertificateValidationFailedForUpdate))
			},
		},
		"Error Response - Certificate count exceeds allowed limit": {
			request: UpdateCASetVersionRequest{
				CASetID: 123,
				Body: UpdateCASetVersionRequestBody{
					Version:           2,
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
					  "allowInsecureSha1": false,
					  "caSetName": "",
					  "certificates": [
						{
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "createdBy": "",
						  "createdDate": "",
						  "endDate": "2025-12-31",
						  "fingerprint": "abc123",
						  "issuer": "Test Issuer",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "",
						  "startDate": "2025-01-01",
						  "subject": "Test Subject"
						}
					  ],
					  "createdBy": "",
					  "createdDate": "",
					  "description": "Test CA Set Version",
					  "modifiedBy": "",
					  "modifiedDate": "",
					  "productionStatus": "",
					  "stagingStatus": "",
					  "version": 2,
					  "versionLink": ""
					}`,
			responseStatus: http.StatusUnprocessableEntity,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/2",
			responseBody: `
		{
			"contextInfo": {
				"caSetId": 123,
				"caSetName": "sveerava-test-13456111",
				"maxCertificatesPerVersion": 1,
				"submittedCertificatesCount": 2,
				"version": 2
			},
			"detail": "The maximum number of certificates allowed per CA set version is 1. Number of submitted certificates is 2.",
			"status": 422,
			"title": "Submitted certificates exceed the maximum allowed certificates limit.",
			"type": "/mtls-edge-truststore/v2/error-types/certificate-limit-reached"
		}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrCertificateLimitReached))
			},
		},
		"Internal server error": {
			request: UpdateCASetVersionRequest{
				CASetID: 123,
				Body: UpdateCASetVersionRequestBody{
					Version:           1,
					AllowInsecureSHA1: false,
					Description:       "Test CA Set Version",
					Certificates: []Certificate{
						{
							Subject:        "Test Subject",
							Issuer:         "Test Issuer",
							EndDate:        "2025-12-31",
							StartDate:      "2025-01-01",
							Fingerprint:    "abc123",
							CertificatePEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
							SerialNumber:   "123456789",
						},
					},
				},
			},
			expectedRequestBody: `{
					  "allowInsecureSha1": false,
					  "caSetName": "",
					  "certificates": [
						{
						  "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
						  "createdBy": "",
						  "createdDate": "",
						  "endDate": "2025-12-31",
						  "fingerprint": "abc123",
						  "issuer": "Test Issuer",
						  "serialNumber": "123456789",
						  "signatureAlgorithm": "",
						  "startDate": "2025-01-01",
						  "subject": "Test Subject"
						}
					  ],
					  "createdBy": "",
					  "createdDate": "",
					  "description": "Test CA Set Version",
					  "modifiedBy": "",
					  "modifiedDate": "",
					  "productionStatus": "",
					  "stagingStatus": "",
					  "version": 1,
					  "versionLink": ""
					}`,
			responseStatus: http.StatusInternalServerError,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/1",
			responseBody: `
					{
						"type": "internal_error",
						"title": "Internal Server Error",
						"detail": "Error processing request",
						"status": 500
					}`,
			withError: func(t *testing.T, err error) {
				want := &Error{
					Type:        "internal_error",
					Title:       "Internal Server Error",
					Detail:      "Error processing request",
					Status:      http.StatusInternalServerError,
					ContextInfo: nil,
					Errors:      nil,
					Instance:    "",
				}
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodPut, r.Method)
				w.WriteHeader(test.responseStatus)
				_, err := w.Write([]byte(test.responseBody))
				assert.NoError(t, err)

				if len(test.expectedRequestBody) > 0 {
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					assert.JSONEq(t, test.expectedRequestBody, string(body))
				}
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.UpdateCASetVersion(context.Background(), test.request)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestListCASetVersion(t *testing.T) {
	tests := map[string]struct {
		request          ListCASetVersionsRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *ListCASetVersionsResponse
		withError        func(*testing.T, error)
	}{
		"200- Successfully Lists versions": {
			request: ListCASetVersionsRequest{
				CASetID: 123,
			},
			responseStatus: http.StatusOK,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions?",
			responseBody: `{
				   "versions": [
					  {
						 "version": 1,
						 "versionLink": "/mtls-edge-truststore/v2/ca-sets/1000/versions/1",
						 "caSetId" : 1000,
						 "caSetName": "test1",
						 "description": "Optional description for this version.",
						 "allowInsecureSha1": false,
						 "stagingStatus": "ACTIVE",
						 "productionStatus": "INACTIVE",
						 "createdDate": "2023-01-10T11:00:00Z",
						 "createdBy": "jsmith",
						 "modifiedDate": "2023-01-10T12:00:00Z",
						 "modifiedBy": "jsmith",
						 "certificates": [
							{
							   "subject": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
							   "issuer": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=tcm-13-example.com",
							   "endDate": "2020-04-07T17:33:39Z",
							   "startDate": "2019-04-08T17:33:39Z",
							   "fingerprint": "1E:DD:AD:32:C3:54:3F:C3:6F:7F:94:51:8D:5E:F7:ED:7C:DB:5D:A5",
							   "certificatePem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
							   "serialNumber": "11612024106234270900",
							   "signatureAlgorithm": "SHA256WITHRSA",
							   "createdDate": "2020-04-07T17:33:39Z",
							   "createdBy": "jsmith2",
							   "description": "Optional description for the certificate"
							},
							{
							   "subject": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate1.tcm-11-example.com",
							   "issuer": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
							   "endDate": "2020-04-07T17:43:58Z",
							   "startDate": "2019-04-08T17:43:58Z",
							   "fingerprint": "1F:DD:AD:32:C3:54:3F:C3:6F:7F:04:51:8D:5E:F7:ED:7C:DB:5D:A5",
							   "certificatePem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
							   "serialNumber": "11612024106234270901",
							   "signatureAlgorithm": "SHA256WITHRSA",
							   "createdDate": "2020-04-07T17:33:39Z",
							   "createdBy": "jsmith2",
							   "description": "Optional description for the certificate"
							}
						 ]
					  },
					  {
						 "caSetId" : 1000,
						 "caSetName": "test1", 
						 "version": 2,
						 "versionLink": "/mtls-edge-truststore/v2/ca-sets/1000/versions/2",
						 "description": null,
						 "allowInsecureSha1": true,
						 "stagingStatus": "ACTIVE",
						 "productionStatus": "INACTIVE",
						 "createdDate": "2023-01-10T11:00:00Z",
						 "createdBy": "jsmith",
						 "modifiedDate": "2023-01-10T12:00:00Z",
						 "modifiedBy": "jsmith",
						 "certificates": [
							{
							   "subject": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
							   "issuer": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=tcm-13-example.com",
							   "endDate": "2020-04-07T17:33:39Z",
							   "startDate": "2019-04-08T17:33:39Z",
							   "fingerprint": "1E:DD:AD:32:C3:54:3F:C3:6F:7F:94:51:8D:5E:F7:ED:7C:DB:5D:A5",
							   "certificatePem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
							   "serialNumber": "11612024106234270900",
							   "signatureAlgorithm": "SHA256WITHRSA",
							   "createdDate": "2020-04-07T17:33:39Z",
							   "createdBy": "jsmith2",
							   "description": "Optional description for the certificate"
							},
							{
							   "subject": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate1.tcm-11-example.com",
							   "issuer": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
							   "endDate": "2020-04-07T17:43:58Z",
							   "startDate": "2019-04-08T17:43:58Z",
							   "fingerprint": "1F:DD:AD:32:C3:54:3F:C3:6F:7F:04:51:8D:5E:F7:ED:7C:DB:5D:A6",
							   "certificatePem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
							   "serialNumber": "11612024106234270901",
							   "signatureAlgorithm": "SHA256WITHRSA",
							   "createdDate": "2020-04-07T17:33:39Z",
							   "createdBy": "jsmith2",
							   "description": "Optional description for the certificate"
							}
						 ]
					  }
				   ]
				}`,
			expectedResponse: &ListCASetVersionsResponse{
				Versions: []CASetVersion{
					{
						CASetID:           1000,
						Version:           1,
						CASetName:         "test1",
						VersionLink:       "/mtls-edge-truststore/v2/ca-sets/1000/versions/1",
						Description:       "Optional description for this version.",
						AllowInsecureSha1: false,
						StagingStatus:     "ACTIVE",
						ProductionStatus:  "INACTIVE",
						CreatedDate:       "2023-01-10T11:00:00Z",
						CreatedBy:         "jsmith",
						ModifiedDate:      "2023-01-10T12:00:00Z",
						ModifiedBy:        "jsmith",
						Certificates: []Certificate{
							{
								Subject:            "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
								Issuer:             "C=US,ST=MA,L=Cambridge,O=Akamai,CN=tcm-13-example.com",
								EndDate:            "2020-04-07T17:33:39Z",
								StartDate:          "2019-04-08T17:33:39Z",
								Fingerprint:        "1E:DD:AD:32:C3:54:3F:C3:6F:7F:94:51:8D:5E:F7:ED:7C:DB:5D:A5",
								CertificatePEM:     "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
								SerialNumber:       "11612024106234270900",
								SignatureAlgorithm: "SHA256WITHRSA",
								CreatedDate:        "2020-04-07T17:33:39Z",
								CreatedBy:          "jsmith2",
								Description:        "Optional description for the certificate",
							},
							{
								Subject:            "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate1.tcm-11-example.com",
								Issuer:             "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
								EndDate:            "2020-04-07T17:43:58Z",
								StartDate:          "2019-04-08T17:43:58Z",
								Fingerprint:        "1F:DD:AD:32:C3:54:3F:C3:6F:7F:04:51:8D:5E:F7:ED:7C:DB:5D:A5",
								CertificatePEM:     "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
								SerialNumber:       "11612024106234270901",
								SignatureAlgorithm: "SHA256WITHRSA",
								CreatedDate:        "2020-04-07T17:33:39Z",
								CreatedBy:          "jsmith2",
								Description:        "Optional description for the certificate",
							},
						},
					},
					{
						CASetID: 1000,
						Version: 2,

						CASetName:         "test1",
						VersionLink:       "/mtls-edge-truststore/v2/ca-sets/1000/versions/2",
						Description:       "", // null in JSON maps to empty string in Go
						AllowInsecureSha1: true,
						StagingStatus:     "ACTIVE",
						ProductionStatus:  "INACTIVE",
						CreatedDate:       "2023-01-10T11:00:00Z",
						CreatedBy:         "jsmith",
						ModifiedDate:      "2023-01-10T12:00:00Z",
						ModifiedBy:        "jsmith",
						Certificates: []Certificate{
							{
								Subject:            "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
								Issuer:             "C=US,ST=MA,L=Cambridge,O=Akamai,CN=tcm-13-example.com",
								EndDate:            "2020-04-07T17:33:39Z",
								StartDate:          "2019-04-08T17:33:39Z",
								Fingerprint:        "1E:DD:AD:32:C3:54:3F:C3:6F:7F:94:51:8D:5E:F7:ED:7C:DB:5D:A5",
								CertificatePEM:     "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
								SerialNumber:       "11612024106234270900",
								SignatureAlgorithm: "SHA256WITHRSA",
								CreatedDate:        "2020-04-07T17:33:39Z",
								CreatedBy:          "jsmith2",
								Description:        "Optional description for the certificate",
							},
							{
								Subject:            "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate1.tcm-11-example.com",
								Issuer:             "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
								EndDate:            "2020-04-07T17:43:58Z",
								StartDate:          "2019-04-08T17:43:58Z",
								Fingerprint:        "1F:DD:AD:32:C3:54:3F:C3:6F:7F:04:51:8D:5E:F7:ED:7C:DB:5D:A6",
								CertificatePEM:     "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
								SerialNumber:       "11612024106234270901",
								SignatureAlgorithm: "SHA256WITHRSA",
								CreatedDate:        "2020-04-07T17:33:39Z",
								CreatedBy:          "jsmith2",
								Description:        "Optional description for the certificate",
							},
						},
					},
				},
			},
		},
		"200- Successfully Lists versions with optional params": {
			request: ListCASetVersionsRequest{
				CASetID:             123,
				IncludeCertificates: ptr.To(true),
				ActiveVersionsOnly:  ptr.To(true),
			},
			responseStatus: http.StatusOK,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions?activeVersionsOnly=true&includeCertificates=true",
			responseBody: `{
				   "versions": [
					  {
						 "version": 1,
						 "versionLink": "/mtls-edge-truststore/v2/ca-sets/1000/versions/1",
						 "caSetId" : 1000,
						 "caSetName": "test1",
						 "description": "Optional description for this version.",
						 "allowInsecureSha1": false,
						 "stagingStatus": "ACTIVE",
						 "productionStatus": "ACTIVE",
						 "createdDate": "2023-01-10T11:00:00Z",
						 "createdBy": "jsmith",
						 "modifiedDate": "2023-01-10T12:00:00Z",
						 "modifiedBy": "jsmith",
						 "certificates": [
							{
							   "subject": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
							   "issuer": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=tcm-13-example.com",
							   "endDate": "2020-04-07T17:33:39Z",
							   "startDate": "2019-04-08T17:33:39Z",
							   "fingerprint": "1E:DD:AD:32:C3:54:3F:C3:6F:7F:94:51:8D:5E:F7:ED:7C:DB:5D:A5",
							   "certificatePem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
							   "serialNumber": "11612024106234270900",
							   "signatureAlgorithm": "SHA256WITHRSA",
							   "createdDate": "2020-04-07T17:33:39Z",
							   "createdBy": "jsmith2",
							   "description": "Optional description for the certificate"
							},
							{
							   "subject": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate1.tcm-11-example.com",
							   "issuer": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
							   "endDate": "2020-04-07T17:43:58Z",
							   "startDate": "2019-04-08T17:43:58Z",
							   "fingerprint": "1F:DD:AD:32:C3:54:3F:C3:6F:7F:04:51:8D:5E:F7:ED:7C:DB:5D:A5",
							   "certificatePem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
							   "serialNumber": "11612024106234270901",
							   "signatureAlgorithm": "SHA256WITHRSA",
							   "createdDate": "2020-04-07T17:33:39Z",
							   "createdBy": "jsmith2",
							   "description": "Optional description for the certificate"
							}
						 ]
					  },
					  {
						 "caSetId" : 1000,
						 "caSetName": "test1", 
						 "version": 2,
						 "versionLink": "/mtls-edge-truststore/v2/ca-sets/1000/versions/2",
						 "description": null,
						 "allowInsecureSha1": true,
						 "stagingStatus": "ACTIVE",
						 "productionStatus": "ACTIVE",
						 "createdDate": "2023-01-10T11:00:00Z",
						 "createdBy": "jsmith",
						 "modifiedDate": "2023-01-10T12:00:00Z",
						 "modifiedBy": "jsmith",
						 "certificates": [
							{
							   "subject": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
							   "issuer": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=tcm-13-example.com",
							   "endDate": "2020-04-07T17:33:39Z",
							   "startDate": "2019-04-08T17:33:39Z",
							   "fingerprint": "1E:DD:AD:32:C3:54:3F:C3:6F:7F:94:51:8D:5E:F7:ED:7C:DB:5D:A5",
							   "certificatePem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
							   "serialNumber": "11612024106234270900",
							   "signatureAlgorithm": "SHA256WITHRSA",
							   "createdDate": "2020-04-07T17:33:39Z",
							   "createdBy": "jsmith2",
							   "description": "Optional description for the certificate"
							},
							{
							   "subject": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate1.tcm-11-example.com",
							   "issuer": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
							   "endDate": "2020-04-07T17:43:58Z",
							   "startDate": "2019-04-08T17:43:58Z",
							   "fingerprint": "1F:DD:AD:32:C3:54:3F:C3:6F:7F:04:51:8D:5E:F7:ED:7C:DB:5D:A6",
							   "certificatePem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
							   "serialNumber": "11612024106234270901",
							   "signatureAlgorithm": "SHA256WITHRSA",
							   "createdDate": "2020-04-07T17:33:39Z",
							   "createdBy": "jsmith2",
							   "description": "Optional description for the certificate"
							}
						 ]
					  }
				   ]
				}`,
			expectedResponse: &ListCASetVersionsResponse{
				Versions: []CASetVersion{
					{
						CASetID:           1000,
						Version:           1,
						CASetName:         "test1",
						VersionLink:       "/mtls-edge-truststore/v2/ca-sets/1000/versions/1",
						Description:       "Optional description for this version.",
						AllowInsecureSha1: false,
						StagingStatus:     "ACTIVE",
						ProductionStatus:  "ACTIVE",
						CreatedDate:       "2023-01-10T11:00:00Z",
						CreatedBy:         "jsmith",
						ModifiedDate:      "2023-01-10T12:00:00Z",
						ModifiedBy:        "jsmith",
						Certificates: []Certificate{
							{
								Subject:            "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
								Issuer:             "C=US,ST=MA,L=Cambridge,O=Akamai,CN=tcm-13-example.com",
								EndDate:            "2020-04-07T17:33:39Z",
								StartDate:          "2019-04-08T17:33:39Z",
								Fingerprint:        "1E:DD:AD:32:C3:54:3F:C3:6F:7F:94:51:8D:5E:F7:ED:7C:DB:5D:A5",
								CertificatePEM:     "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
								SerialNumber:       "11612024106234270900",
								SignatureAlgorithm: "SHA256WITHRSA",
								CreatedDate:        "2020-04-07T17:33:39Z",
								CreatedBy:          "jsmith2",
								Description:        "Optional description for the certificate",
							},
							{
								Subject:            "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate1.tcm-11-example.com",
								Issuer:             "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
								EndDate:            "2020-04-07T17:43:58Z",
								StartDate:          "2019-04-08T17:43:58Z",
								Fingerprint:        "1F:DD:AD:32:C3:54:3F:C3:6F:7F:04:51:8D:5E:F7:ED:7C:DB:5D:A5",
								CertificatePEM:     "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
								SerialNumber:       "11612024106234270901",
								SignatureAlgorithm: "SHA256WITHRSA",
								CreatedDate:        "2020-04-07T17:33:39Z",
								CreatedBy:          "jsmith2",
								Description:        "Optional description for the certificate",
							},
						},
					},
					{
						CASetID:           1000,
						Version:           2,
						CASetName:         "test1",
						VersionLink:       "/mtls-edge-truststore/v2/ca-sets/1000/versions/2",
						Description:       "", // null in JSON maps to empty string in Go
						AllowInsecureSha1: true,
						StagingStatus:     "ACTIVE",
						ProductionStatus:  "ACTIVE",
						CreatedDate:       "2023-01-10T11:00:00Z",
						CreatedBy:         "jsmith",
						ModifiedDate:      "2023-01-10T12:00:00Z",
						ModifiedBy:        "jsmith",
						Certificates: []Certificate{
							{
								Subject:            "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
								Issuer:             "C=US,ST=MA,L=Cambridge,O=Akamai,CN=tcm-13-example.com",
								EndDate:            "2020-04-07T17:33:39Z",
								StartDate:          "2019-04-08T17:33:39Z",
								Fingerprint:        "1E:DD:AD:32:C3:54:3F:C3:6F:7F:94:51:8D:5E:F7:ED:7C:DB:5D:A5",
								CertificatePEM:     "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
								SerialNumber:       "11612024106234270900",
								SignatureAlgorithm: "SHA256WITHRSA",
								CreatedDate:        "2020-04-07T17:33:39Z",
								CreatedBy:          "jsmith2",
								Description:        "Optional description for the certificate",
							},
							{
								Subject:            "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate1.tcm-11-example.com",
								Issuer:             "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
								EndDate:            "2020-04-07T17:43:58Z",
								StartDate:          "2019-04-08T17:43:58Z",
								Fingerprint:        "1F:DD:AD:32:C3:54:3F:C3:6F:7F:04:51:8D:5E:F7:ED:7C:DB:5D:A6",
								CertificatePEM:     "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
								SerialNumber:       "11612024106234270901",
								SignatureAlgorithm: "SHA256WITHRSA",
								CreatedDate:        "2020-04-07T17:33:39Z",
								CreatedBy:          "jsmith2",
								Description:        "Optional description for the certificate",
							},
						},
					},
				},
			},
		},
		"200- Successfully Lists versions with optional params 2": {
			request: ListCASetVersionsRequest{
				CASetID:             123,
				IncludeCertificates: ptr.To(false),
				ActiveVersionsOnly:  ptr.To(true),
			},
			responseStatus: http.StatusOK,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions?activeVersionsOnly=true&includeCertificates=false",
			responseBody: `{
				   "versions": [
					  {
						 "version": 1,
						 "versionLink": "/mtls-edge-truststore/v2/ca-sets/1000/versions/1",
						 "caSetId" : 1000,
						 "caSetName": "test1",
						 "description": "Optional description for this version.",
						 "allowInsecureSha1": false,
						 "stagingStatus": "ACTIVE",
						 "productionStatus": "ACTIVE",
						 "createdDate": "2023-01-10T11:00:00Z",
						 "createdBy": "jsmith",
						 "modifiedDate": "2023-01-10T12:00:00Z",
						 "modifiedBy": "jsmith"
					  },
					  {
						 "caSetId" : 1000,
						 "caSetName": "test1", 
						 "version": 2,
						 "versionLink": "/mtls-edge-truststore/v2/ca-sets/1000/versions/2",
						 "description": null,
						 "allowInsecureSha1": true,
						 "stagingStatus": "ACTIVE",
						 "productionStatus": "ACTIVE",
						 "createdDate": "2023-01-10T11:00:00Z",
						 "createdBy": "jsmith",
						 "modifiedDate": "2023-01-10T12:00:00Z",
						 "modifiedBy": "jsmith"
					  }
				   ]
				}`,
			expectedResponse: &ListCASetVersionsResponse{
				Versions: []CASetVersion{
					{
						CASetID:           1000,
						Version:           1,
						CASetName:         "test1",
						VersionLink:       "/mtls-edge-truststore/v2/ca-sets/1000/versions/1",
						Description:       "Optional description for this version.",
						AllowInsecureSha1: false,
						StagingStatus:     "ACTIVE",
						ProductionStatus:  "ACTIVE",
						CreatedDate:       "2023-01-10T11:00:00Z",
						CreatedBy:         "jsmith",
						ModifiedDate:      "2023-01-10T12:00:00Z",
						ModifiedBy:        "jsmith",
					},
					{
						CASetID: 1000,
						Version: 2,

						CASetName:         "test1",
						VersionLink:       "/mtls-edge-truststore/v2/ca-sets/1000/versions/2",
						Description:       "", // null in JSON maps to empty string in Go
						AllowInsecureSha1: true,
						StagingStatus:     "ACTIVE",
						ProductionStatus:  "ACTIVE",
						CreatedDate:       "2023-01-10T11:00:00Z",
						CreatedBy:         "jsmith",
						ModifiedDate:      "2023-01-10T12:00:00Z",
						ModifiedBy:        "jsmith",
					},
				},
			},
		},
		"Validation error - missing CASetID": {
			request: ListCASetVersionsRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "fetching CA set versions: struct validation: CASetID: cannot be blank.", err.Error())
			},
		},
		"Error Response - CA set is not found": {
			request: ListCASetVersionsRequest{
				CASetID: 123,
			},
			responseStatus: http.StatusNotFound,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions?",
			responseBody: `
					{
  						"type": "/mtls-edge-truststore/v2/error-types/ca-set-not-found",
  						"title": "CA set not found.",
  						"status": 404,
  						"detail": "Cannot get CA set version as the CA set with caSetId 123 is not found.",
  						"contextInfo": {
							"caSetId": 123
  						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetNotFound))
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
			defer mockServer.Close()

			client := mockAPIClient(t, mockServer)
			result, err := client.ListCASetVersions(context.Background(), test.request)

			if test.withError != nil {
				test.withError(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestGetCASetVersionCertificates(t *testing.T) {
	tests := map[string]struct {
		request          GetCASetVersionCertificatesRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *GetCASetVersionCertificatesResponse
		withError        func(*testing.T, error)
	}{
		"200- Successful get certificates of a version": {
			request: GetCASetVersionCertificatesRequest{
				CASetID: 123,
				Version: 1,
			},
			responseStatus: http.StatusOK,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/1/certificates?",
			responseBody: `{
				  "caSetId" : 1,
				  "caSetName": "test1",
				  "version": 1,
				  "certificates": [
					{
					  "subject": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
					  "issuer": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=tcm-13-example.com",
					  "endDate": "2020-04-07T17:33:39Z",
					  "startDate": "2019-04-08T17:33:39Z",
					  "fingerprint": "1E:DD:AD:32:C3:54:3F:C3:6F:7F:94:51:8D:5E:F7:ED:7C:DB:5D:A5",
					  "certificatePem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
					  "serialNumber": "11612024106234272000",
					  "signatureAlgorithm": "SHA256WITHRSA",
					  "createdDate": "2020-04-07T17:33:39Z",
					  "description": "Optional description for the certificate",
					  "createdBy": "jsmith2"
					},
					{
					  "subject": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate1.tcm-11-example.com",
					  "issuer": "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
					  "endDate": "2020-04-07T17:43:58Z",
					  "startDate": "2019-04-08T17:43:58Z",
					  "fingerprint": "1F:DD:AD:32:C3:54:3F:C3:6F:7F:04:51:8D:5E:F7:ED:7C:DB:5D:A5",
					  "certificatePem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
					  "serialNumber": "11612024106234272000",
					  "signatureAlgorithm": "SHA256WITHRSA",
					  "createdDate": "2020-04-07T17:33:39Z",
					  "description": "Optional description for the certificate",
					  "createdBy": "jsmith2"
					}
				]
			}`,
			expectedResponse: &GetCASetVersionCertificatesResponse{
				CASetID:   1,
				Version:   1,
				CASetName: "test1",
				Certificates: []Certificate{
					{
						Subject:            "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
						Issuer:             "C=US,ST=MA,L=Cambridge,O=Akamai,CN=tcm-13-example.com",
						EndDate:            "2020-04-07T17:33:39Z",
						StartDate:          "2019-04-08T17:33:39Z",
						Fingerprint:        "1E:DD:AD:32:C3:54:3F:C3:6F:7F:94:51:8D:5E:F7:ED:7C:DB:5D:A5",
						CertificatePEM:     "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
						SerialNumber:       "11612024106234272000",
						SignatureAlgorithm: "SHA256WITHRSA",
						CreatedDate:        "2020-04-07T17:33:39Z",
						Description:        "Optional description for the certificate",
						CreatedBy:          "jsmith2",
					},
					{
						Subject:            "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate1.tcm-11-example.com",
						Issuer:             "C=US,ST=MA,L=Cambridge,O=Akamai,CN=intermediate.tcm-11-example.com",
						EndDate:            "2020-04-07T17:43:58Z",
						StartDate:          "2019-04-08T17:43:58Z",
						Fingerprint:        "1F:DD:AD:32:C3:54:3F:C3:6F:7F:04:51:8D:5E:F7:ED:7C:DB:5D:A5",
						CertificatePEM:     "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
						SerialNumber:       "11612024106234272000",
						SignatureAlgorithm: "SHA256WITHRSA",
						CreatedDate:        "2020-04-07T17:33:39Z",
						Description:        "Optional description for the certificate",
						CreatedBy:          "jsmith2",
					},
				},
			},
		},
		"Validation error - missing CASetID and Version": {
			request: GetCASetVersionCertificatesRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "fetching certificates for a CA set version: struct validation: CaSetID: cannot be blank; Version: cannot be blank.", err.Error())
			},
		},
		"Validation error - invalid certificateStatus value": {
			request: GetCASetVersionCertificatesRequest{
				CASetID:               123,
				Version:               1,
				ExpiryThresholdInDays: ptr.To(10),
				CertificateStatus:     ptr.To(CertificateStatus("EXPIRY")),
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, `fetching certificates for a CA set version: struct validation: CertificateStatus: value must be one of: 'EXPIRING', 'EXPIRED', or 'EXPIRING,EXPIRED'.`, err.Error())
			},
		},
		"Validation error - missing certificateStatus when expiryThresholdInDays is set": {
			request: GetCASetVersionCertificatesRequest{
				CASetID:               123,
				Version:               1,
				ExpiryThresholdInDays: ptr.To(10),
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "certificateStatus must be provided when expiryThresholdInDays is set", err.Error())
			},
		},
		"Error Response - CA set is not found": {
			request: GetCASetVersionCertificatesRequest{
				CASetID: 123,
				Version: 1,
			},
			responseStatus: http.StatusNotFound,
			expectedPath:   "/mtls-edge-truststore/v2/ca-sets/123/versions/1/certificates?",
			responseBody: `
					{
  						"type": "/mtls-edge-truststore/v2/error-types/ca-set-not-found",
  						"title": "CA set not found.",
  						"status": 404,
  						"detail": "Cannot get CA set version as the CA set with caSetId 123 is not found.",
  						"contextInfo": {
							"caSetId": 123
  						}
					}`,
			withError: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, ErrGetCASetNotFound))
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
			defer mockServer.Close()

			client := mockAPIClient(t, mockServer)
			result, err := client.GetCASetVersionCertificates(context.Background(), test.request)

			if test.withError != nil {
				test.withError(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}
