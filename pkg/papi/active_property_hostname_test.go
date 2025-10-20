package papi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/ptr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPapiListActivePropertyHostnames(t *testing.T) {
	tests := map[string]struct {
		params           ListActivePropertyHostnamesRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *ListActivePropertyHostnamesResponse
		withError        func(*testing.T, error)
	}{
		"200 OK - required params": {
			params: ListActivePropertyHostnamesRequest{
				PropertyID: "prp_175780",
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "accountId": "act_123",
    "contractId": "ctr_123",
    "groupId": "grp_15225",
    "propertyId": "prp_175780",
	"defaultSort": "hostname:a",
    "currentSort": "hostname:d", 
    "hostnames": {
		"currentItemCount": 2,
        "items": [
            {
                "cnameFrom": "example.com",
        		"cnameType": "EDGE_HOSTNAME",
        		"productionCertType": "DEFAULT",
        		"productionCnameTo": "example.com.edgekey.net",
        		"productionEdgeHostnameID": "ehn_895822"
            },
            {
                "cnameFrom": "m-example.com",
        		"cnameType": "EDGE_HOSTNAME",
        		"stagingCertType": "DEFAULT",
        		"stagingEdgeHostnameID": "ehn_293412",
				"stagingCnameTo": "m-example.com.edgekey.net"
            }
        ]
    }
}
`,
			expectedPath: "/papi/v1/properties/prp_175780/hostnames",
			expectedResponse: &ListActivePropertyHostnamesResponse{
				AccountID:   "act_123",
				ContractID:  "ctr_123",
				GroupID:     "grp_15225",
				PropertyID:  "prp_175780",
				DefaultSort: SortAscending,
				CurrentSort: SortDescending,
				Hostnames: HostnamesResponseItems{
					CurrentItemCount: 2,
					Items: []HostnameItem{
						{
							CnameFrom:                "example.com",
							CnameType:                HostnameCnameTypeEdgeHostname,
							ProductionCertType:       CertTypeDefault,
							ProductionCnameTo:        "example.com.edgekey.net",
							ProductionEdgeHostnameID: "ehn_895822",
						},
						{
							CnameFrom:             "m-example.com",
							CnameType:             HostnameCnameTypeEdgeHostname,
							StagingCertType:       CertTypeDefault,
							StagingEdgeHostnameID: "ehn_293412",
							StagingCnameTo:        "m-example.com.edgekey.net",
						},
					},
				},
			},
		},
		"200 OK - all params": {
			params: ListActivePropertyHostnamesRequest{
				PropertyID:        "prp_175780",
				GroupID:           "grp_15225",
				ContractID:        "ctr_123",
				IncludeCertStatus: false,
				Offset:            0,
				Limit:             1,
				Sort:              "hostname:a",
				Hostname:          "example.com",
				CnameTo:           "example.com",
				Network:           ActivationNetworkProduction,
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "accountId": "act_123",
    "contractId": "ctr_123",
    "groupId": "grp_15225",
    "propertyId": "prp_175780",
	"defaultSort": "hostname:a",
    "currentSort": "hostname:d", 
    "hostnames": {
		"currentItemCount": 2,
        "items": [
            {
                "cnameFrom": "example.com",
        		"cnameType": "EDGE_HOSTNAME",
        		"productionCertType": "DEFAULT",
        		"productionCnameTo": "example.com.edgekey.net",
        		"productionEdgeHostnameID": "ehn_895822"
            },
            {
                "cnameFrom": "m-example.com",
        		"cnameType": "EDGE_HOSTNAME",
        		"stagingCertType": "DEFAULT",
        		"stagingEdgeHostnameID": "ehn_293412",
				"stagingCnameTo": "m-example.com.edgekey.net"
            }
        ],
		"previousLink": "previous link",
		"nextLink": "next link"
    }
}
`,
			expectedPath: "/papi/v1/properties/prp_175780/hostnames?cnameTo=example.com&contractId=ctr_123&groupId=grp_15225&hostname=example.com&limit=1&network=PRODUCTION&sort=hostname%3Aa",
			expectedResponse: &ListActivePropertyHostnamesResponse{
				AccountID:   "act_123",
				ContractID:  "ctr_123",
				GroupID:     "grp_15225",
				PropertyID:  "prp_175780",
				DefaultSort: SortAscending,
				CurrentSort: SortDescending,
				Hostnames: HostnamesResponseItems{
					CurrentItemCount: 2,
					Items: []HostnameItem{
						{
							CnameFrom:                "example.com",
							CnameType:                HostnameCnameTypeEdgeHostname,
							ProductionCertType:       CertTypeDefault,
							ProductionCnameTo:        "example.com.edgekey.net",
							ProductionEdgeHostnameID: "ehn_895822",
						},
						{
							CnameFrom:             "m-example.com",
							CnameType:             HostnameCnameTypeEdgeHostname,
							StagingCertType:       CertTypeDefault,
							StagingEdgeHostnameID: "ehn_293412",
							StagingCnameTo:        "m-example.com.edgekey.net",
						},
					},
					PreviousLink: ptr.To("previous link"),
					NextLink:     ptr.To("next link"),
				},
			},
		},
		"200 OK - all types": {
			params: ListActivePropertyHostnamesRequest{
				PropertyID:        "prp_175780",
				IncludeCertStatus: true,
			},
			responseStatus: http.StatusOK,
			responseBody: `
				{
				  "accountId": "act_123",
				  "availableSort": [
					"hostname:a",
					"hostname:d"
				  ],
				  "contractId": "ctr_123",
				  "currentSort": "hostname:a",
				  "defaultSort": "hostname:a",
				  "groupId": "grp_15225",
				  "hostnames": {
					"currentItemCount": 5,
					"items": [
					  {
						"cnameFrom": "example.com",
						"cnameType": "EDGE_HOSTNAME",
						"productionCertType": "DEFAULT",
						"productionCnameTo": "example.com.edgekey.net",
						"productionEdgeHostnameId": "ehn_895822"
					  },
					  {
						"cnameFrom": "m-example.com",
						"cnameType": "EDGE_HOSTNAME",
						"stagingCertType": "DEFAULT",
						"stagingCnameTo": "m-example.com.edgekey.net",
						"stagingEdgeHostnameId": "ehn_293412"
					  },
					  {
						"certStatus": {
						  "authorization": {
							"dns01": {
							  "result": {
								"message": "dns01 cps dry run cname/TXT incomplete",
								"src": "CPS",
								"timestamp": "2024-07-25T16:17:37Z"
							  },
							  "value": "dummy-unique-value-for-DNS-TXT-record"
							},
							"http01": {
							  "body": "unique http body content",
							  "result": {
								"message": "http01 cps dry run fail reason",
								"src": "CPS",
								"timestamp": "2024-07-25T16:17:37Z"
							  },
							  "url": "/.well-known/acme-challenge/"
							},
							"status": "ATTEMPTING_VALIDATION",
							"validUntil": "2024-07-25T16:17:37Z"
						  },
						  "certExpirationDate": "2024-07-25T16:17:37Z",
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
							"hostname": "_acme-challenge.www.example.com",
							"target": "{token}.www.example.com.akamai-domain.com"
						  }
						},
						"cnameFrom": "example2.com",
						"cnameType": "EDGE_HOSTNAME",
						"stagingCertType": "DEFAULT",
						"stagingCnameTo": "example2.com.edgekey.net",
						"stagingEdgeHostnameId": "ehn_895822"
					  },
					  {
						"ccmCertStatus": {
						  "ecdsaStagingStatus": "DEPLOYED",
						  "rsaStagingStatus": "DEPLOYED"
						},
						"ccmCertificates": {
						  "ecdsaCertId": "98765",
						  "ecdsaCertLink": "/ccm/v1/certificates/98765",
						  "rsaCertId": "12345",
						  "rsaCertLink": "/ccm/v1/certificates/12345"
						},
						"cnameFrom": "www.example-ccm.com",
						"cnameType": "EDGE_HOSTNAME",
						"mtls": {
						  "caSetId": "524125",
						  "caSetLink": "/mtls-edge-truststore/v2/ca-sets/524125",
						  "checkClientOcsp": false,
						  "sendCaSetClient": false
						},
						"stagingCertType": "CCM",
						"stagingEdgeHostnameId": "ehn_7123",
						"tlsConfiguration": {
						  "cipherProfile": "ak-akamai-2020q1",
						  "disallowedTlsVersions": [
							"TLSv1_1",
							"TLSv1"
						  ],
						  "fipsMode": false,
						  "stapleServerOcspResponse": true
						}
					  },
					  {
						"ccmCertStatus": {
						  "ecdsaProductionStatus": "DEPLOYED",
						  "rsaProductionStatus": "DEPLOYED"
						},
						"ccmCertificates": {
						  "ecdsaCertId": "98765",
						  "ecdsaCertLink": "/ccm/v1/certificates/98765",
						  "rsaCertId": "12345",
						  "rsaCertLink": "/ccm/v1/certificates/12345"
						},
						"cnameFrom": "www.example-ccm.com",
						"cnameType": "EDGE_HOSTNAME",
						"mtls": {
						  "caSetId": "524125",
						  "caSetLink": "/mtls-edge-truststore/v2/ca-sets/524125",
						  "checkClientOcsp": false,
						  "sendCaSetClient": false
						},
						"productionCertType": "CCM",
						"productionEdgeHostnameId": "ehn_7123",
						"tlsConfiguration": {
						  "cipherProfile": "ak-akamai-2020q1",
						  "disallowedTlsVersions": [
							"TLSv1_1",
							"TLSv1"
						  ],
						  "fipsMode": false,
						  "stapleServerOcspResponse": true
						}
					  }
					],
					"nextLink": "/papi/v1/properties/prp_175780/hostnames?offset=1&groupId=grp_15225&contractId=ctr_K-0N7RAK71&limit=3",
					"totalItems": 5
				  },
				  "propertyId": "prp_175780",
				  "propertyName": "mytestproperty.com"
				}`,
			expectedPath: "/papi/v1/properties/prp_175780/hostnames?includeCertStatus=true",
			expectedResponse: &ListActivePropertyHostnamesResponse{
				AccountID:    "act_123",
				ContractID:   "ctr_123",
				GroupID:      "grp_15225",
				PropertyID:   "prp_175780",
				PropertyName: "mytestproperty.com",
				DefaultSort:  SortAscending,
				CurrentSort:  SortAscending,
				AvailableSort: []SortOrder{
					SortAscending,
					SortDescending,
				},
				Hostnames: HostnamesResponseItems{
					CurrentItemCount: 5,
					TotalItems:       5,
					Items: []HostnameItem{
						{
							CnameFrom:                "example.com",
							CnameType:                HostnameCnameTypeEdgeHostname,
							ProductionCertType:       CertTypeDefault,
							ProductionCnameTo:        "example.com.edgekey.net",
							ProductionEdgeHostnameID: "ehn_895822",
						},
						{
							CnameFrom:             "m-example.com",
							CnameType:             HostnameCnameTypeEdgeHostname,
							StagingCertType:       CertTypeDefault,
							StagingEdgeHostnameID: "ehn_293412",
							StagingCnameTo:        "m-example.com.edgekey.net",
						},
						{
							CnameFrom:             "example2.com",
							CnameType:             HostnameCnameTypeEdgeHostname,
							StagingCertType:       CertTypeDefault,
							StagingEdgeHostnameID: "ehn_895822",
							StagingCnameTo:        "example2.com.edgekey.net",
							CertStatus: &CertStatusItem{
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
									Hostname: "_acme-challenge.www.example.com",
									Target:   "{token}.www.example.com.akamai-domain.com",
								},
							},
						},
						{
							CnameFrom:             "www.example-ccm.com",
							CnameType:             HostnameCnameTypeEdgeHostname,
							StagingCertType:       CertTypeCCM,
							StagingEdgeHostnameID: "ehn_7123",
							MTLS: &MTLS{
								CASetID:         "524125",
								CASetLink:       "/mtls-edge-truststore/v2/ca-sets/524125",
								CheckClientOCSP: false,
								SendCASetClient: false,
							},
							TLSConfiguration: &TLSConfiguration{
								CipherProfile:            "ak-akamai-2020q1",
								DisallowedTLSVersions:    []string{"TLSv1_1", "TLSv1"},
								FIPSMode:                 false,
								StapleServerOcspResponse: true, //TODO OCSP
							},
							CCMCertificates: &CCMCertificates{
								ECDSACertID:   "98765",
								ECDSACertLink: "/ccm/v1/certificates/98765",
								RSACertID:     "12345",
								RSACertLink:   "/ccm/v1/certificates/12345",
							},
							CCMCertStatus: &CCMCertStatus{
								ECDSAStagingStatus: "DEPLOYED",
								RSAStagingStatus:   "DEPLOYED",
							},
						},
						{
							CnameFrom:                "www.example-ccm.com",
							CnameType:                HostnameCnameTypeEdgeHostname,
							ProductionCertType:       CertTypeCCM,
							ProductionEdgeHostnameID: "ehn_7123",
							MTLS: &MTLS{
								CASetID:         "524125",
								CASetLink:       "/mtls-edge-truststore/v2/ca-sets/524125",
								CheckClientOCSP: false,
								SendCASetClient: false,
							},
							TLSConfiguration: &TLSConfiguration{
								CipherProfile:            "ak-akamai-2020q1",
								DisallowedTLSVersions:    []string{"TLSv1_1", "TLSv1"},
								FIPSMode:                 false,
								StapleServerOcspResponse: true,
							},
							CCMCertificates: &CCMCertificates{
								ECDSACertID:   "98765",
								ECDSACertLink: "/ccm/v1/certificates/98765",
								RSACertID:     "12345",
								RSACertLink:   "/ccm/v1/certificates/12345",
							},
							CCMCertStatus: &CCMCertStatus{
								ECDSAProductionStatus: "DEPLOYED",
								RSAProductionStatus:   "DEPLOYED",
							},
						},
					},
					NextLink: ptr.To("/papi/v1/properties/prp_175780/hostnames?offset=1&groupId=grp_15225&contractId=ctr_K-0N7RAK71&limit=3"),
				},
			},
		},
		"validation error PropertyID missing": {
			params: ListActivePropertyHostnamesRequest{
				Offset: 3,
			},
			withError: func(t *testing.T, err error) {
				want := ErrStructValidation
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
				assert.Contains(t, err.Error(), "PropertyID")
			},
		},
		"validation error Offset negative": {
			params: ListActivePropertyHostnamesRequest{
				PropertyID: "prp_175780",
				Offset:     -1,
			},
			withError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Offset")
			},
		},
		"validation error Limit negative": {
			params: ListActivePropertyHostnamesRequest{
				PropertyID: "prp_175780",
				Limit:      -1,
			},
			withError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Limit")
			},
		},
		"validation error Network invalid": {
			params: ListActivePropertyHostnamesRequest{
				PropertyID: "prp_175780",
				Network:    "invalid_network",
			},
			withError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Network")
			},
		},
		"validation error network missing": {
			params: ListActivePropertyHostnamesRequest{
				Offset: 3,
			},
			withError: func(t *testing.T, err error) {
				want := ErrStructValidation
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
				assert.Contains(t, err.Error(), "PropertyID")
			},
		},
		"validation error Sort method invalid": {
			params: ListActivePropertyHostnamesRequest{
				PropertyID: "prp_175780",
				Sort:       "asc",
			},
			withError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Sort")
			},
		},
		"500 internal server status error": {
			params: ListActivePropertyHostnamesRequest{
				PropertyID: "prp_175780",
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
{
	"type": "internal_error",
    "title": "Internal Server Error",
    "detail": "Error fetching hostnames",
    "status": 500
}`,
			expectedPath: "/papi/v1/properties/prp_175780/hostnames",
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
			result, err := client.ListActivePropertyHostnames(context.Background(), test.params)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}

func TestPapiGetActivePropertyHostnamesDiff(t *testing.T) {
	tests := map[string]struct {
		params           GetActivePropertyHostnamesDiffRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *GetActivePropertyHostnamesDiffResponse
		withError        func(*testing.T, error)
	}{
		"200 OK - required params": {
			params: GetActivePropertyHostnamesDiffRequest{
				PropertyID: "prp_175780",
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "accountId": "act_123",
    "contractId": "ctr_123",
    "groupId": "grp_15225",
    "propertyId": "prp_175780",
    "hostnames": {
		"currentItemCount": 2,
        "items": [
            {
                "cnameFrom": "example.com",
        	    "ProductionCnameType": "EDGE_HOSTNAME",
        		"productionCnameTo": "example.com.edgekey.net",
        		"productionEdgeHostnameID": "ehn_895822",
				"productionCertProvisioningType": "CPS_MANAGED"
            },
            {
                "cnameFrom": "m-example.com",
        		"stagingCnameType":	"EDGE_HOSTNAME",
				"stagingCnameTo": "m-example.com.edgekey.net",
        		"stagingEdgeHostnameID": "ehn_293412",
				"stagingCertProvisioningType": "CPS_MANAGED"
            }
        ]
    }
}
`,
			expectedPath: "/papi/v1/properties/prp_175780/hostnames/diff",
			expectedResponse: &GetActivePropertyHostnamesDiffResponse{
				AccountID:  "act_123",
				ContractID: "ctr_123",
				GroupID:    "grp_15225",
				PropertyID: "prp_175780",
				Hostnames: HostnamesDiffResponseItems{
					CurrentItemCount: 2,
					Items: []HostnameDiffItem{
						{
							CnameFrom:                      "example.com",
							ProductionCnameTo:              "example.com.edgekey.net",
							ProductionCnameType:            HostnameCnameTypeEdgeHostname,
							ProductionEdgeHostnameID:       "ehn_895822",
							ProductionCertProvisioningType: CertTypeCPSManaged,
						},
						{
							CnameFrom:                   "m-example.com",
							StagingCnameTo:              "m-example.com.edgekey.net",
							StagingCnameType:            HostnameCnameTypeEdgeHostname,
							StagingEdgeHostnameID:       "ehn_293412",
							StagingCertProvisioningType: CertTypeCPSManaged,
						},
					},
				},
			},
		},
		"200 OK - all params": {
			params: GetActivePropertyHostnamesDiffRequest{
				PropertyID: "prp_175780",
				GroupID:    "grp_15225",
				ContractID: "ctr_123",
				Offset:     1,
				Limit:      1,
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "accountId": "act_123",
    "contractId": "ctr_123",
    "groupId": "grp_15225",
    "propertyId": "prp_175780",
    "hostnames": {
		"currentItemCount": 2,
        "items": [
            {
                "cnameFrom": "example.com",
        	    "ProductionCnameType": "EDGE_HOSTNAME",
        		"productionCnameTo": "example.com.edgekey.net",
        		"productionEdgeHostnameID": "ehn_895822",
				"productionCertProvisioningType": "CPS_MANAGED"
            },
            {
                "cnameFrom": "m-example.com",
        		"stagingCnameType":	"EDGE_HOSTNAME",
				"stagingCnameTo": "m-example.com.edgekey.net",
        		"stagingEdgeHostnameID": "ehn_293412",
				"stagingCertProvisioningType": "CPS_MANAGED"
            }
        ],
		"previousLink": "previous link",
		"nextLink": "next link"
    }
}
`,
			expectedPath: "/papi/v1/properties/prp_175780/hostnames/diff?contractId=ctr_123&groupId=grp_15225&limit=1&offset=1",
			expectedResponse: &GetActivePropertyHostnamesDiffResponse{
				AccountID:  "act_123",
				ContractID: "ctr_123",
				GroupID:    "grp_15225",
				PropertyID: "prp_175780",
				Hostnames: HostnamesDiffResponseItems{
					CurrentItemCount: 2,
					Items: []HostnameDiffItem{
						{
							CnameFrom:                      "example.com",
							ProductionCnameTo:              "example.com.edgekey.net",
							ProductionCnameType:            HostnameCnameTypeEdgeHostname,
							ProductionEdgeHostnameID:       "ehn_895822",
							ProductionCertProvisioningType: CertTypeCPSManaged,
						},
						{
							CnameFrom:                   "m-example.com",
							StagingCnameTo:              "m-example.com.edgekey.net",
							StagingCnameType:            HostnameCnameTypeEdgeHostname,
							StagingEdgeHostnameID:       "ehn_293412",
							StagingCertProvisioningType: CertTypeCPSManaged,
						},
					},
					PreviousLink: ptr.To("previous link"),
					NextLink:     ptr.To("next link"),
				},
			},
		},
		"validation error PropertyID missing": {
			params: GetActivePropertyHostnamesDiffRequest{
				Offset: 3,
			},
			withError: func(t *testing.T, err error) {
				want := ErrStructValidation
				assert.True(t, errors.Is(err, want), "want: %s; got: %s", want, err)
				assert.Contains(t, err.Error(), "PropertyID")
			},
		},
		"validation error Offset negative": {
			params: GetActivePropertyHostnamesDiffRequest{
				PropertyID: "prp_175780",
				Offset:     -1,
			},
			withError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Offset")
			},
		},
		"validation error Limit negative": {
			params: GetActivePropertyHostnamesDiffRequest{
				PropertyID: "prp_175780",
				Limit:      -1,
			},
			withError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Limit")
			},
		},
		"500 internal server status error": {
			params: GetActivePropertyHostnamesDiffRequest{
				PropertyID: "prp_175780",
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
{
	"type": "internal_error",
    "title": "Internal Server Error",
    "detail": "Error fetching hostnames",
    "status": 500
}`,
			expectedPath: "/papi/v1/properties/prp_175780/hostnames/diff",
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
			result, err := client.GetActivePropertyHostnamesDiff(context.Background(), test.params)
			if test.withError != nil {
				test.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedResponse, result)
		})
	}
}
