package papi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/ptr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPapiGetPropertyVersionHostnames(t *testing.T) {
	tests := map[string]struct {
		params           GetPropertyVersionHostnamesRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *GetPropertyVersionHostnamesResponse
		withError        func(*testing.T, error)
	}{
		"200 OK": {
			params: GetPropertyVersionHostnamesRequest{
				PropertyID:        "prp_175780",
				PropertyVersion:   3,
				GroupID:           "grp_15225",
				ContractID:        "ctr_1-1TJZH5",
				IncludeCertStatus: false,
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "accountId": "act_1-1TJZFB",
    "contractId": "ctr_1-1TJZH5",
    "groupId": "grp_15225",
    "propertyId": "prp_175780",
    "propertyVersion": 3,
    "etag": "6aed418629b4e5c0",
    "hostnames": {
        "items": [
            {
                "cnameType": "EDGE_HOSTNAME",
                "edgeHostnameId": "ehn_895822",
                "cnameFrom": "example.com",
                "cnameTo": "example.com.edgesuite.net"
            },
            {
                "cnameType": "EDGE_HOSTNAME",
                "edgeHostnameId": "ehn_895833",
                "cnameFrom": "m.example.com",
                "cnameTo": "m.example.com.edgesuite.net"
            }
        ]
    }
}

`,
			expectedPath: "/papi/v1/properties/prp_175780/versions/3/hostnames?contractId=ctr_1-1TJZH5&groupId=grp_15225&includeCertStatus=false&validateHostnames=false",
			expectedResponse: &GetPropertyVersionHostnamesResponse{
				AccountID:       "act_1-1TJZFB",
				ContractID:      "ctr_1-1TJZH5",
				GroupID:         "grp_15225",
				PropertyID:      "prp_175780",
				PropertyVersion: 3,
				Etag:            "6aed418629b4e5c0",
				Hostnames: HostnameResponseItems{
					Items: []Hostname{
						{
							CnameType:      "EDGE_HOSTNAME",
							EdgeHostnameID: "ehn_895822",
							CnameFrom:      "example.com",
							CnameTo:        "example.com.edgesuite.net",
						},
						{
							CnameType:      "EDGE_HOSTNAME",
							EdgeHostnameID: "ehn_895833",
							CnameFrom:      "m.example.com",
							CnameTo:        "m.example.com.edgesuite.net",
						},
					},
				},
			},
		},
		"302 - missed contractId and groupId": {
			params: GetPropertyVersionHostnamesRequest{
				PropertyID:        "prp_175780",
				PropertyVersion:   3,
				IncludeCertStatus: false,
			},
			responseStatus: http.StatusFound,
			responseBody: `
{
    "redirectLink": "/papi/v1/properties/prp_175780/versions/1/hostnames?groupId=12345&contractId=G-12RS3N4"
}`,
			expectedPath: "/papi/v1/properties/prp_175780/versions/3/hostnames?includeCertStatus=false&validateHostnames=false",
			withError: func(t *testing.T, err error) {
				want := &Error{
					RedirectLink: ptr.To("/papi/v1/properties/prp_175780/versions/1/hostnames?groupId=12345&contractId=G-12RS3N4"),
					StatusCode:   http.StatusFound,
				}
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
			},
		},
		"validation error PropertyID missing": {
			params: GetPropertyVersionHostnamesRequest{
				PropertyVersion: 3,
			},
			withError: func(t *testing.T, err error) {
				want := ErrStructValidation
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
				assert.Contains(t, err.Error(), "PropertyID")
			},
		},
		"validation error PropertyVersion missing": {
			params: GetPropertyVersionHostnamesRequest{
				PropertyID: "prp_175780",
			},
			withError: func(t *testing.T, err error) {
				want := ErrStructValidation
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
				assert.Contains(t, err.Error(), "PropertyVersion")
			},
		},
		"500 internal server status error": {
			params: GetPropertyVersionHostnamesRequest{
				PropertyID:      "prp_175780",
				PropertyVersion: 3,
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
{
	"type": "internal_error",
    "title": "Internal Server Error",
    "detail": "Error fetching hostnames",
    "status": 500
}`,
			expectedPath: "/papi/v1/properties/prp_175780/versions/3/hostnames?includeCertStatus=false&validateHostnames=false",
			withError: func(t *testing.T, err error) {
				want := &Error{
					Type:       "internal_error",
					Title:      "Internal Server Error",
					Detail:     "Error fetching hostnames",
					StatusCode: http.StatusInternalServerError,
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
			result, err := client.GetPropertyVersionHostnames(context.Background(), test.params)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestPapiUpdatePropertyVersionHostnames(t *testing.T) {
	tests := map[string]struct {
		params           UpdatePropertyVersionHostnamesRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *UpdatePropertyVersionHostnamesResponse
		withError        func(*testing.T, error)
	}{
		"200 OK": {
			params: UpdatePropertyVersionHostnamesRequest{
				PropertyID:        "prp_175780",
				PropertyVersion:   3,
				GroupID:           "grp_15225",
				ContractID:        "ctr_1-1TJZH5",
				IncludeCertStatus: true,
				Hostnames: []Hostname{
					{
						CnameType:            "EDGE_HOSTNAME",
						CnameFrom:            "m.example.com",
						CnameTo:              "example.com.edgekey.net",
						CertProvisioningType: "DEFAULT",
					},
					{
						CnameType:            "EDGE_HOSTNAME",
						EdgeHostnameID:       "ehn_895824",
						CnameFrom:            "example3.com",
						CertProvisioningType: "CPS_MANAGED",
					},
				},
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "accountId": "act_1-1TJZFB",
    "contractId": "ctr_1-1TJZH5",
    "groupId": "grp_15225",
    "propertyId": "prp_175780",
    "propertyVersion": 3,
    "etag": "6aed418629b4e5c0",
    "hostnames": {
        "items": [
            {
                "cnameType": "EDGE_HOSTNAME",
                "edgeHostnameId": "ehn_895822",
                "cnameFrom": "m.example.com",
                "cnameTo": "example.com.edgekey.net",
                "certProvisioningType": "DEFAULT",
                "certStatus": {
                    "validationCname": {
                        "hostname": "_acme-challenge.www.example.com",
                        "target": "{token}.www.example.com.akamai-domain.com"
                    },
                    "staging": [
                        {
                            "status": "NEEDS_VALIDATION"
                        }
                    ],
                    "production": [
                        {
                            "status": "NEEDS_VALIDATION"
                        }
                    ]
                }
            },
            {
                "cnameType": "EDGE_HOSTNAME",
                "edgeHostnameId": "ehn_895833",
                "cnameFrom": "example3.com",
                "cnameTo": "m.example.com.edgesuite.net",
 				"certProvisioningType": "CPS_MANAGED"
            }
        ]
    }
}
`,
			expectedPath: "/papi/v1/properties/prp_175780/versions/3/hostnames?contractId=ctr_1-1TJZH5&groupId=grp_15225&includeCertStatus=true&validateHostnames=false",
			expectedResponse: &UpdatePropertyVersionHostnamesResponse{
				AccountID:       "act_1-1TJZFB",
				ContractID:      "ctr_1-1TJZH5",
				GroupID:         "grp_15225",
				PropertyID:      "prp_175780",
				PropertyVersion: 3,
				Etag:            "6aed418629b4e5c0",
				Hostnames: HostnameResponseItems{
					Items: []Hostname{
						{
							CnameType:            "EDGE_HOSTNAME",
							EdgeHostnameID:       "ehn_895822",
							CnameFrom:            "m.example.com",
							CnameTo:              "example.com.edgekey.net",
							CertProvisioningType: "DEFAULT",
							CertStatus: CertStatusItem{
								ValidationCname: ValidationCname{
									Hostname: "_acme-challenge.www.example.com",
									Target:   "{token}.www.example.com.akamai-domain.com",
								},
								Staging:    []StatusItem{{Status: "NEEDS_VALIDATION"}},
								Production: []StatusItem{{Status: "NEEDS_VALIDATION"}},
							},
						},
						{
							CnameType:            "EDGE_HOSTNAME",
							EdgeHostnameID:       "ehn_895833",
							CnameFrom:            "example3.com",
							CnameTo:              "m.example.com.edgesuite.net",
							CertProvisioningType: "CPS_MANAGED",
						},
					},
				},
			},
		},
		"200 empty hostnames": {
			params: UpdatePropertyVersionHostnamesRequest{
				PropertyID:        "prp_175780",
				PropertyVersion:   3,
				GroupID:           "grp_15225",
				ContractID:        "ctr_1-1TJZH5",
				IncludeCertStatus: true,
				Hostnames:         []Hostname{{}},
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "accountId": "act_1-1TJZFB",
    "contractId": "ctr_1-1TJZH5",
    "groupId": "grp_15225",
    "propertyId": "prp_175780",
    "propertyVersion": 3,
    "etag": "6aed418629b4e5c0",
    "hostnames": {
        "items": []
    }
}

`,
			expectedPath: "/papi/v1/properties/prp_175780/versions/3/hostnames?contractId=ctr_1-1TJZH5&groupId=grp_15225&includeCertStatus=true&validateHostnames=false",
			expectedResponse: &UpdatePropertyVersionHostnamesResponse{
				AccountID:       "act_1-1TJZFB",
				ContractID:      "ctr_1-1TJZH5",
				GroupID:         "grp_15225",
				PropertyID:      "prp_175780",
				PropertyVersion: 3,
				Etag:            "6aed418629b4e5c0",
				Hostnames: HostnameResponseItems{
					Items: []Hostname{},
				},
			},
		},
		"200 VerifyHostnames true empty hostnames": {
			params: UpdatePropertyVersionHostnamesRequest{
				PropertyID:        "prp_175780",
				PropertyVersion:   3,
				GroupID:           "grp_15225",
				ContractID:        "ctr_1-1TJZH5",
				ValidateHostnames: true,
				IncludeCertStatus: true,
				Hostnames:         []Hostname{{}},
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "accountId": "act_1-1TJZFB",
    "contractId": "ctr_1-1TJZH5",
    "groupId": "grp_15225",
    "propertyId": "prp_175780",
    "propertyVersion": 3,
    "etag": "6aed418629b4e5c0",
	"validateHostnames": true,
    "hostnames": {
        "items": []
    }
}
`,
			expectedPath: "/papi/v1/properties/prp_175780/versions/3/hostnames?contractId=ctr_1-1TJZH5&groupId=grp_15225&includeCertStatus=true&validateHostnames=true",
			expectedResponse: &UpdatePropertyVersionHostnamesResponse{
				AccountID:       "act_1-1TJZFB",
				ContractID:      "ctr_1-1TJZH5",
				GroupID:         "grp_15225",
				PropertyID:      "prp_175780",
				PropertyVersion: 3,
				Etag:            "6aed418629b4e5c0",
				Hostnames: HostnameResponseItems{
					Items: []Hostname{},
				},
			},
		},
		"302 - missed contractId and groupId": {
			params: UpdatePropertyVersionHostnamesRequest{
				PropertyID:        "prp_175780",
				PropertyVersion:   3,
				IncludeCertStatus: true,
				Hostnames: []Hostname{
					{
						CnameType:            "EDGE_HOSTNAME",
						CnameFrom:            "m.example.com",
						CnameTo:              "example.com.edgekey.net",
						CertProvisioningType: "DEFAULT",
					},
					{
						CnameType:            "EDGE_HOSTNAME",
						EdgeHostnameID:       "ehn_895824",
						CnameFrom:            "example3.com",
						CertProvisioningType: "CPS_MANAGED",
					},
				},
			},
			responseStatus: http.StatusFound,
			responseBody: `
{
    "redirectLink": "/papi/v1/properties/prp_175780/versions/3/hostnames?groupId=12345&contractId=G-12RS3N4"
}`,
			expectedPath: "/papi/v1/properties/prp_175780/versions/3/hostnames?includeCertStatus=true&validateHostnames=false",
			withError: func(t *testing.T, err error) {
				want := &Error{
					RedirectLink: ptr.To("/papi/v1/properties/prp_175780/versions/3/hostnames?groupId=12345&contractId=G-12RS3N4"),
					StatusCode:   http.StatusFound,
				}
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
			},
		},
		"validation error PropertyID missing": {
			params: UpdatePropertyVersionHostnamesRequest{
				PropertyVersion: 3,
				Hostnames:       []Hostname{{}},
			},
			withError: func(t *testing.T, err error) {
				want := ErrStructValidation
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
				assert.Contains(t, err.Error(), "PropertyID")
			},
		},
		"validation error PropertyVersion missing": {
			params: UpdatePropertyVersionHostnamesRequest{
				PropertyID: "prp_175780",
				Hostnames:  []Hostname{{}},
			},
			withError: func(t *testing.T, err error) {
				want := ErrStructValidation
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
				assert.Contains(t, err.Error(), "PropertyVersion")
			},
		},
		"200 Hostnames missing": {
			params: UpdatePropertyVersionHostnamesRequest{
				PropertyID:        "prp_175780",
				PropertyVersion:   3,
				GroupID:           "grp_15225",
				ContractID:        "ctr_1-1TJZH5",
				IncludeCertStatus: true,
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
	"accountId": "act_1-1TJZFB",
	"contractId": "ctr_1-1TJZH5",
	"groupId": "grp_15225",
	"propertyId": "prp_175780",
	"propertyVersion": 3,
	"etag": "6aed418629b4e5c0",
	"validateHostnames": false,
	"hostnames": {
		"items": []
	}
}`,
			expectedPath: "/papi/v1/properties/prp_175780/versions/3/hostnames?contractId=ctr_1-1TJZH5&groupId=grp_15225&includeCertStatus=true&validateHostnames=false",
			expectedResponse: &UpdatePropertyVersionHostnamesResponse{
				AccountID:       "act_1-1TJZFB",
				ContractID:      "ctr_1-1TJZH5",
				GroupID:         "grp_15225",
				PropertyID:      "prp_175780",
				PropertyVersion: 3,
				Etag:            "6aed418629b4e5c0",
				Hostnames: HostnameResponseItems{
					Items: []Hostname{},
				},
			},
		},
		"200 Hostnames items missing": {
			params: UpdatePropertyVersionHostnamesRequest{
				PropertyID:        "prp_175780",
				PropertyVersion:   3,
				GroupID:           "grp_15225",
				ContractID:        "ctr_1-1TJZH5",
				Hostnames:         nil,
				IncludeCertStatus: true,
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
	"accountId": "act_1-1TJZFB",
	"contractId": "ctr_1-1TJZH5",
	"groupId": "grp_15225",
	"propertyId": "prp_175780",
	"propertyVersion": 3,
	"etag": "6aed418629b4e5c0",
	"validateHostnames": false,
	"hostnames": {
		"items": []
	}
}`,
			expectedPath: "/papi/v1/properties/prp_175780/versions/3/hostnames?contractId=ctr_1-1TJZH5&groupId=grp_15225&includeCertStatus=true&validateHostnames=false",
			expectedResponse: &UpdatePropertyVersionHostnamesResponse{
				AccountID:       "act_1-1TJZFB",
				ContractID:      "ctr_1-1TJZH5",
				GroupID:         "grp_15225",
				PropertyID:      "prp_175780",
				PropertyVersion: 3,
				Etag:            "6aed418629b4e5c0",
				Hostnames: HostnameResponseItems{
					Items: []Hostname{},
				},
			},
		},
		"200 Hostnames items empty": {
			params: UpdatePropertyVersionHostnamesRequest{
				PropertyID:        "prp_175780",
				PropertyVersion:   3,
				GroupID:           "grp_15225",
				ContractID:        "ctr_1-1TJZH5",
				IncludeCertStatus: true,
				Hostnames:         []Hostname{},
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
	"accountId": "act_1-1TJZFB",
	"contractId": "ctr_1-1TJZH5",
	"groupId": "grp_15225",
	"propertyId": "prp_175780",
	"propertyVersion": 3,
	"etag": "6aed418629b4e5c0",
	"validateHostnames": false,
	"hostnames": {
		"items": []
	}
}`,
			expectedPath: "/papi/v1/properties/prp_175780/versions/3/hostnames?contractId=ctr_1-1TJZH5&groupId=grp_15225&includeCertStatus=true&validateHostnames=false",
			expectedResponse: &UpdatePropertyVersionHostnamesResponse{
				AccountID:       "act_1-1TJZFB",
				ContractID:      "ctr_1-1TJZH5",
				GroupID:         "grp_15225",
				PropertyID:      "prp_175780",
				PropertyVersion: 3,
				Etag:            "6aed418629b4e5c0",
				Hostnames: HostnameResponseItems{
					Items: []Hostname{},
				},
			},
		},
		"400 Hostnames cert type is invalid": {
			params: UpdatePropertyVersionHostnamesRequest{
				PropertyID:        "prp_175780",
				PropertyVersion:   3,
				GroupID:           "grp_15225",
				ContractID:        "ctr_1-1TJZH5",
				IncludeCertStatus: true,
				Hostnames: []Hostname{
					{
						CnameType:            "EDGE_HOSTNAME",
						CnameFrom:            "m.example.com",
						CnameTo:              "example.com.edgesuite.net",
						CertProvisioningType: "INVALID_TYPE",
					},
				},
			},
			responseStatus: http.StatusBadRequest,
			responseBody: `
{
    "type": "https://problems.luna.akamaiapis.net/papi/v0/json-mapping-error",
    "title": "Unable to interpret JSON",
    "detail": "Your input could not be interpreted as the expected JSON format. Cannot deserialize value of type com.akamai.platformtk.entities.HostnameRelation$CertProvisioningType from String INVALID_TYPE: not one of the values accepted for Enum class: [DEFAULT, CPS_MANAGED]\n at [Source: (org.apache.catalina.connector.CoyoteInputStream); line: 6, column: 41] (through reference chain: java.util.ArrayList[0]->com.akamai.luna.papi.model.HostnameItem[certProvisioningType]).",
    "status": 400
}`,
			expectedPath: "/papi/v1/properties/prp_175780/versions/3/hostnames?contractId=ctr_1-1TJZH5&groupId=grp_15225&includeCertStatus=true&validateHostnames=false",
			withError: func(t *testing.T, err error) {
				want := &Error{
					Type:       "https://problems.luna.akamaiapis.net/papi/v0/json-mapping-error",
					Title:      "Unable to interpret JSON",
					Detail:     "Your input could not be interpreted as the expected JSON format. Cannot deserialize value of type com.akamai.platformtk.entities.HostnameRelation$CertProvisioningType from String INVALID_TYPE: not one of the values accepted for Enum class: [DEFAULT, CPS_MANAGED]\n at [Source: (org.apache.catalina.connector.CoyoteInputStream); line: 6, column: 41] (through reference chain: java.util.ArrayList[0]->com.akamai.luna.papi.model.HostnameItem[certProvisioningType]).",
					StatusCode: http.StatusBadRequest,
				}
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
			},
		},
		"500 internal server status error": {
			params: UpdatePropertyVersionHostnamesRequest{
				PropertyID:        "prp_175780",
				PropertyVersion:   3,
				Hostnames:         []Hostname{{}},
				IncludeCertStatus: true,
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
{
	"type": "internal_error",
    "title": "Internal Server Error",
    "detail": "Error updating hostnames",
    "status": 500
}`,
			expectedPath: "/papi/v1/properties/prp_175780/versions/3/hostnames?includeCertStatus=true&validateHostnames=false",
			withError: func(t *testing.T, err error) {
				want := &Error{
					Type:       "internal_error",
					Title:      "Internal Server Error",
					Detail:     "Error updating hostnames",
					StatusCode: http.StatusInternalServerError,
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
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.UpdatePropertyVersionHostnames(context.Background(), test.params)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestPapiPatchPropertyVersionHostnames(t *testing.T) {
	tests := map[string]struct {
		params              PatchPropertyVersionHostnamesRequest
		responseStatus      int
		responseBody        string
		expectedPath        string
		expectedRequestBody string
		expectedResponse    *PatchPropertyVersionHostnamesResponse
		withError           func(*testing.T, error)
	}{
		"200 OK - only add": {
			params: PatchPropertyVersionHostnamesRequest{
				PropertyID:      "prp_123",
				PropertyVersion: 1,
				Body: PatchPropertyVersionHostnamesRequestBody{
					Add: []HostnameAdd{
						{
							CnameType: HostnameCnameTypeEdgeHostname,
							CnameFrom: "m.example.com",
							CnameTo:   "example.com.edgekey.net",
						},
						{
							CnameType:            HostnameCnameTypeEdgeHostname,
							EdgeHostnameID:       "ehn_666",
							CnameFrom:            "example3.com",
							CertProvisioningType: CertTypeDefault,
						},
					},
				},
			},
			responseStatus: http.StatusOK,
			responseBody: `
			{
				"accountId": "act_789",
				"contractId": "ctr_456",
				"groupId": "grp_321",
				"propertyId": "prp_123",
				"propertyName": "test-property",
				"propertyVersion": 1,
				"etag": "123abc456def7890",
				"hostnames": {
					"items": [
						{
							"cnameType": "EDGE_HOSTNAME",
							"edgeHostnameId": "ehn_555",
							"cnameFrom": "m.example.com",
							"cnameTo": "example.com.edgekey.net",
							"certProvisioningType": "CPS_MANAGED"
						},
						{
							"cnameType": "EDGE_HOSTNAME",
							"edgeHostnameId": "ehn_666",
							"cnameFrom": "example3.com",
							"cnameTo": "m.example.com.edgesuite.net",
							"certProvisioningType": "DEFAULT"
						}
					]
				}
			}`,
			expectedPath:        "/papi/v1/properties/prp_123/versions/1/hostnames",
			expectedRequestBody: `{"add":[{"cnameFrom":"m.example.com","cnameType":"EDGE_HOSTNAME","cnameTo":"example.com.edgekey.net"},{"cnameFrom":"example3.com","cnameType":"EDGE_HOSTNAME","certProvisioningType":"DEFAULT","edgeHostnameId":"ehn_666"}]}`,
			expectedResponse: &PatchPropertyVersionHostnamesResponse{
				AccountID:       "act_789",
				ContractID:      "ctr_456",
				GroupID:         "grp_321",
				PropertyID:      "prp_123",
				PropertyVersion: 1,
				PropertyName:    "test-property",
				Etag:            "123abc456def7890",
				Hostnames: HostnameResponseItems{
					Items: []Hostname{
						{
							CnameType:            HostnameCnameTypeEdgeHostname,
							CnameFrom:            "m.example.com",
							CnameTo:              "example.com.edgekey.net",
							EdgeHostnameID:       "ehn_555",
							CertProvisioningType: "CPS_MANAGED",
						},
						{
							CnameType:            HostnameCnameTypeEdgeHostname,
							EdgeHostnameID:       "ehn_666",
							CnameFrom:            "example3.com",
							CertProvisioningType: "DEFAULT",
							CnameTo:              "m.example.com.edgesuite.net",
						},
					},
				},
			},
		},
		"200 OK - only remove": {
			params: PatchPropertyVersionHostnamesRequest{
				PropertyID:      "prp_123",
				PropertyVersion: 1,
				Body: PatchPropertyVersionHostnamesRequestBody{
					Remove: []string{
						"ehn_555",
						"ehn_666",
					},
				},
			},
			responseStatus: http.StatusOK,
			responseBody: `
			{
				"accountId": "act_789",
				"contractId": "ctr_456",
				"groupId": "grp_321",
				"propertyId": "prp_123",
				"propertyName": "test-property",
				"propertyVersion": 1,
				"etag": "123abc456def7890",
				"hostnames": {
					"items": []
				}
			}`,
			expectedPath:        "/papi/v1/properties/prp_123/versions/1/hostnames",
			expectedRequestBody: `{"remove":["ehn_555","ehn_666"]}`,
			expectedResponse: &PatchPropertyVersionHostnamesResponse{
				AccountID:       "act_789",
				ContractID:      "ctr_456",
				GroupID:         "grp_321",
				PropertyID:      "prp_123",
				PropertyVersion: 1,
				PropertyName:    "test-property",
				Etag:            "123abc456def7890",
				Hostnames: HostnameResponseItems{
					Items: []Hostname{},
				},
			},
		},
		"200 OK - add and remove": {
			params: PatchPropertyVersionHostnamesRequest{
				PropertyID:      "prp_123",
				PropertyVersion: 1,
				Body: PatchPropertyVersionHostnamesRequestBody{
					Remove: []string{
						"ehn_555",
						"ehn_666",
					},
					Add: []HostnameAdd{
						{
							CnameType: HostnameCnameTypeEdgeHostname,
							CnameFrom: "m.example.com",
							CnameTo:   "example.com.edgekey.net",
						},
						{
							CnameType:            HostnameCnameTypeEdgeHostname,
							EdgeHostnameID:       "ehn_888",
							CnameFrom:            "example3.com",
							CertProvisioningType: CertTypeDefault,
						},
					},
				},
			},
			responseStatus: http.StatusOK,
			responseBody: `
			{
				"accountId": "act_789",
				"contractId": "ctr_456",
				"groupId": "grp_321",
				"propertyId": "prp_123",
				"propertyName": "test-property",
				"propertyVersion": 1,
				"etag": "123abc456def7890",
				"hostnames": {
					"items": [
						{
							"cnameType": "EDGE_HOSTNAME",
							"edgeHostnameId": "ehn_777",
							"cnameFrom": "m.example.com",
							"cnameTo": "example.com.edgekey.net",
							"certProvisioningType": "CPS_MANAGED"
						},
						{
							"cnameType": "EDGE_HOSTNAME",
							"edgeHostnameId": "ehn_888",
							"cnameFrom": "example3.com",
							"cnameTo": "m.example.com.edgesuite.net",
							"certProvisioningType": "DEFAULT"
						}
					]
				}
			}`,
			expectedPath:        "/papi/v1/properties/prp_123/versions/1/hostnames",
			expectedRequestBody: `{"add":[{"cnameFrom":"m.example.com","cnameType":"EDGE_HOSTNAME","cnameTo":"example.com.edgekey.net"},{"cnameFrom":"example3.com","cnameType":"EDGE_HOSTNAME","certProvisioningType":"DEFAULT","edgeHostnameId":"ehn_888"}],"remove":["ehn_555","ehn_666"]}`,
			expectedResponse: &PatchPropertyVersionHostnamesResponse{
				AccountID:       "act_789",
				ContractID:      "ctr_456",
				GroupID:         "grp_321",
				PropertyID:      "prp_123",
				PropertyVersion: 1,
				PropertyName:    "test-property",
				Etag:            "123abc456def7890",
				Hostnames: HostnameResponseItems{
					Items: []Hostname{
						{
							CnameType:            HostnameCnameTypeEdgeHostname,
							CnameFrom:            "m.example.com",
							CnameTo:              "example.com.edgekey.net",
							EdgeHostnameID:       "ehn_777",
							CertProvisioningType: "CPS_MANAGED",
						},
						{
							CnameType:            HostnameCnameTypeEdgeHostname,
							EdgeHostnameID:       "ehn_888",
							CnameFrom:            "example3.com",
							CertProvisioningType: "DEFAULT",
							CnameTo:              "m.example.com.edgesuite.net",
						},
					},
				},
			},
		},
		"200 OK - with optional fields": {
			params: PatchPropertyVersionHostnamesRequest{
				PropertyID:        "prp_123",
				PropertyVersion:   1,
				ContractID:        "ctr_456",
				GroupID:           "grp_321",
				IncludeCertStatus: true,
				ValidateHostnames: true,
				Body: PatchPropertyVersionHostnamesRequestBody{
					Add: []HostnameAdd{
						{
							CnameType: HostnameCnameTypeEdgeHostname,
							CnameFrom: "m.example.com",
							CnameTo:   "example.com.edgekey.net",
						},
						{
							CnameType:            HostnameCnameTypeEdgeHostname,
							EdgeHostnameID:       "ehn_666",
							CnameFrom:            "example3.com",
							CertProvisioningType: CertTypeDefault,
						},
					},
				},
			},
			responseStatus: http.StatusOK,
			responseBody: `
			{
				"accountId": "act_789",
				"contractId": "ctr_456",
				"groupId": "grp_321",
				"propertyId": "prp_123",
				"propertyName": "test-property",
				"propertyVersion": 1,
				"etag": "123abc456def7890",
				"hostnames": {
					"items": [
						{
							"cnameType": "EDGE_HOSTNAME",
							"edgeHostnameId": "ehn_555",
							"cnameFrom": "m.example.com",
							"cnameTo": "example.com.edgekey.net",
							"certProvisioningType": "CPS_MANAGED"
						},
						{
							"cnameType": "EDGE_HOSTNAME",
							"edgeHostnameId": "ehn_666",
							"cnameFrom": "example3.com",
							"cnameTo": "m.example.com.edgesuite.net",
							"certProvisioningType": "DEFAULT",
							"certStatus": {
								"production": [
									{
										"status": "PENDING"
									}
								],
								"staging": [
									{
										"status": "PENDING"
									}
								],
								"validationCname": {
									"hostname": "_acme-challenge.example3.com",
									"target": "ac.ee03f141752f0e52808f6669ad50ad43.example3.com.validate-akdv.net"
								}
							}
						}
					]
				}
			}`,
			expectedPath:        "/papi/v1/properties/prp_123/versions/1/hostnames?contractId=ctr_456&groupId=grp_321&includeCertStatus=true&validateHostnames=true",
			expectedRequestBody: `{"add":[{"cnameFrom":"m.example.com","cnameType":"EDGE_HOSTNAME","cnameTo":"example.com.edgekey.net"},{"cnameFrom":"example3.com","cnameType":"EDGE_HOSTNAME","certProvisioningType":"DEFAULT","edgeHostnameId":"ehn_666"}]}`,
			expectedResponse: &PatchPropertyVersionHostnamesResponse{
				AccountID:       "act_789",
				ContractID:      "ctr_456",
				GroupID:         "grp_321",
				PropertyID:      "prp_123",
				PropertyVersion: 1,
				PropertyName:    "test-property",
				Etag:            "123abc456def7890",
				Hostnames: HostnameResponseItems{
					Items: []Hostname{
						{
							CnameType:            HostnameCnameTypeEdgeHostname,
							CnameFrom:            "m.example.com",
							CnameTo:              "example.com.edgekey.net",
							EdgeHostnameID:       "ehn_555",
							CertProvisioningType: "CPS_MANAGED",
						},
						{
							CnameType:            HostnameCnameTypeEdgeHostname,
							EdgeHostnameID:       "ehn_666",
							CnameFrom:            "example3.com",
							CertProvisioningType: "DEFAULT",
							CnameTo:              "m.example.com.edgesuite.net",
							CertStatus: CertStatusItem{
								Production: []StatusItem{
									{
										Status: "PENDING",
									},
								},
								Staging: []StatusItem{
									{
										Status: "PENDING",
									},
								},
								ValidationCname: ValidationCname{
									Hostname: "_acme-challenge.example3.com",
									Target:   "ac.ee03f141752f0e52808f6669ad50ad43.example3.com.validate-akdv.net",
								},
							},
						},
					},
				},
			},
		},
		"validation errors missing required fields": {
			params: PatchPropertyVersionHostnamesRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "patching hostnames: struct validation: PropertyID: cannot be blank\nPropertyVersion: cannot be blank", err.Error())
				assert.ErrorIs(t, err, ErrStructValidation)
				assert.ErrorIs(t, err, ErrPatchPropertyVersionHostnames)
			},
		},
		"validation errors missing required fields in body": {
			params: PatchPropertyVersionHostnamesRequest{
				PropertyID:      "prp_123",
				PropertyVersion: 1,
				Body: PatchPropertyVersionHostnamesRequestBody{
					Add: []HostnameAdd{{}},
				},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "patching hostnames: struct validation: Body: {\n\tAdd[0]: {\n\t\tCnameFrom: cannot be blank\n\t\trequired parameters: either CnameTo or EdgeHostnameID must be provided\n\t}\n}", err.Error())
				assert.ErrorIs(t, err, ErrStructValidation)
				assert.ErrorIs(t, err, ErrPatchPropertyVersionHostnames)
			},
		},
		"validation errors- invalid CertProvisioningType and CnameType": {
			params: PatchPropertyVersionHostnamesRequest{
				PropertyID:      "prp_123",
				PropertyVersion: 1,
				Body: PatchPropertyVersionHostnamesRequestBody{
					Add: []HostnameAdd{
						{
							CnameType:            HostnameCnameType("WRONG"),
							CnameFrom:            "m.example.com",
							CnameTo:              "example.com.edgekey.net",
							CertProvisioningType: CertType("WRONG"),
						},
					},
				},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "patching hostnames: struct validation: Body: {\n\tAdd[0]: {\n\t\tCertProvisioningType: value 'WRONG' is invalid. Must be one of: 'CPS_MANAGED' or 'DEFAULT'\n\t\tCnameType: value 'WRONG' is invalid. There is only one supported value of: EDGE_HOSTNAME\n\t}\n}",
					err.Error())
				assert.ErrorIs(t, err, ErrStructValidation)
				assert.ErrorIs(t, err, ErrPatchPropertyVersionHostnames)
			},
		},
		"500 internal server status error": {
			params: PatchPropertyVersionHostnamesRequest{
				PropertyID:      "prp_123",
				PropertyVersion: 1,
				Body: PatchPropertyVersionHostnamesRequestBody{
					Add: []HostnameAdd{
						{
							CnameType: HostnameCnameTypeEdgeHostname,
							CnameFrom: "m.example.com",
							CnameTo:   "example.com.edgekey.net",
						},
						{
							CnameType:            HostnameCnameTypeEdgeHostname,
							EdgeHostnameID:       "ehn_666",
							CnameFrom:            "example3.com",
							CertProvisioningType: CertTypeDefault,
						},
					},
				},
			},
			responseStatus: http.StatusInternalServerError,
			expectedPath:   "/papi/v1/properties/prp_123/versions/1/hostnames",
			responseBody: `
			{
				"type": "internal_error",
				"title": "Internal Server Error",
				"detail": "Error updating hostnames",
				"status": 500
			}`,
			withError: func(t *testing.T, err error) {
				want := &Error{
					Type:       "internal_error",
					Title:      "Internal Server Error",
					Detail:     "Error updating hostnames",
					StatusCode: http.StatusInternalServerError,
				}
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
				assert.ErrorIs(t, err, ErrPatchPropertyVersionHostnames)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodPatch, r.Method)
				w.WriteHeader(test.responseStatus)
				_, err := w.Write([]byte(test.responseBody))
				assert.NoError(t, err)

				if len(test.expectedRequestBody) > 0 {
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					assert.Equal(t, test.expectedRequestBody, string(body))
				}
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.PatchPropertyVersionHostnames(context.Background(), test.params)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}
