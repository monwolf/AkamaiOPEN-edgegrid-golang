package ccm

import (
	"context"
	"fmt"
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

func TestPatchCertificate(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		params              PatchCertificateRequest
		responseStatus      int
		responseBody        string
		expectedResponse    *PatchCertificateResponse
		expectedRequestBody string
		expectedPath        string
		expectedHeaders     map[string]string
		withError           func(*testing.T, error)
	}{
		"200 OK - only rename with all allowed characters": {
			params: PatchCertificateRequest{
				CertificateID:   "123",
				CertificateName: ptr.To("test 0123456789.-_"),
			},
			expectedResponse: &PatchCertificateResponse{
				AccountID:               "acc_123",
				CertificateID:           "123",
				CertificateName:         "test 0123456789.-_",
				CertificateStatus:       "CSR_READY",
				CertificateType:         "THIRD_PARTY",
				ContractID:              "ctr_123",
				CreatedBy:               "user",
				CreatedDate:             test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
				CSRExpirationDate:       test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
				CSRPEM:                  "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
				KeySize:                 "2048",
				KeyType:                 "RSA",
				ModifiedBy:              "user",
				ModifiedDate:            test.NewTimeFromString(t, "2025-08-22T09:01:32.607358Z"),
				SANs:                    []string{"example.com", "www.example.com"},
				SecureNetwork:           "ENHANCED_TLS",
				SignedCertificateIssuer: ptr.To("EMPTY"),
				Subject: &Subject{
					Country:      ptr.To("US"),
					Organization: ptr.To(""),
					State:        ptr.To("Massachusetts"),
					Locality:     ptr.To("Cambridge"),
					CommonName:   ptr.To("example.com"),
				},
			},
			expectedRequestBody: "[{\"op\":\"replace\",\"path\":\"/certificateName\",\"value\":\"test 0123456789.-_\"}]",
			responseStatus:      200,
			responseBody: `
			{
				"accountId": "acc_123",
				"certificateId": "123",
				"certificateName": "test 0123456789.-_",
				"certificateStatus": "CSR_READY",
				"certificateType": "THIRD_PARTY",
				"contractId": "ctr_123",
				"createdBy": "user",
				"createdDate": "2025-08-22T09:01:32.607357Z",
				"csrExpirationDate": "2026-10-24T09:01:34Z",
				"csrPem": "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
				"keySize": "2048",
				"keyType": "RSA",
				"modifiedBy": "user",
				"modifiedDate": "2025-08-22T09:01:32.607358Z",
				"sans": [
					"example.com",
					"www.example.com"
				],
				"secureNetwork": "ENHANCED_TLS",
				"signedCertificateIssuer": "EMPTY",
				"signedCertificateNotValidAfterDate": null,
				"signedCertificateNotValidBeforeDate": null,
				"signedCertificatePem": null,
				"signedCertificateSHA256Fingerprint": null,
				"signedCertificateSerialNumber": null,
				"subject": {
					"commonName": "example.com",
					"country": "US",
					"locality": "Cambridge",
					"organization": "",
					"state": "Massachusetts"
				},
				"trustChainPem": null
			}`,
			expectedPath: "/ccm/v1/certificates/123",
			expectedHeaders: map[string]string{
				"Content-Type": "application/json-patch+json",
			},
		},
		"200 OK - reset name by providing empty value": {
			params: PatchCertificateRequest{
				CertificateID:   "123",
				CertificateName: ptr.To(""),
			},
			expectedResponse: &PatchCertificateResponse{
				AccountID:               "acc_123",
				CertificateID:           "123",
				CertificateName:         "example.com20250822092651008941",
				CertificateStatus:       "CSR_READY",
				CertificateType:         "THIRD_PARTY",
				ContractID:              "ctr_123",
				CreatedBy:               "user",
				CreatedDate:             test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
				CSRExpirationDate:       test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
				CSRPEM:                  "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
				KeySize:                 "2048",
				KeyType:                 "RSA",
				ModifiedBy:              "user",
				ModifiedDate:            test.NewTimeFromString(t, "2025-08-22T09:01:32.607358Z"),
				SANs:                    []string{"example.com", "www.example.com"},
				SecureNetwork:           "ENHANCED_TLS",
				SignedCertificateIssuer: ptr.To("EMPTY"),
				Subject: &Subject{
					Country:      ptr.To("US"),
					Organization: ptr.To(""),
					State:        ptr.To("Massachusetts"),
					Locality:     ptr.To("Cambridge"),
					CommonName:   ptr.To("example.com"),
				},
			},
			expectedRequestBody: "[{\"op\":\"replace\",\"path\":\"/certificateName\",\"value\":\"\"}]",
			responseStatus:      200,
			responseBody: `
			{
				"accountId": "acc_123",
				"certificateId": "123",
				"certificateName": "example.com20250822092651008941",
				"certificateStatus": "CSR_READY",
				"certificateType": "THIRD_PARTY",
				"contractId": "ctr_123",
				"createdBy": "user",
				"createdDate": "2025-08-22T09:01:32.607357Z",
				"csrExpirationDate": "2026-10-24T09:01:34Z",
				"csrPem": "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
				"keySize": "2048",
				"keyType": "RSA",
				"modifiedBy": "user",
				"modifiedDate": "2025-08-22T09:01:32.607358Z",
				"sans": [
					"example.com",
					"www.example.com"
				],
				"secureNetwork": "ENHANCED_TLS",
				"signedCertificateIssuer": "EMPTY",
				"signedCertificateNotValidAfterDate": null,
				"signedCertificateNotValidBeforeDate": null,
				"signedCertificatePem": null,
				"signedCertificateSHA256Fingerprint": null,
				"signedCertificateSerialNumber": null,
				"subject": {
					"commonName": "example.com",
					"country": "US",
					"locality": "Cambridge",
					"organization": "",
					"state": "Massachusetts"
				},
				"trustChainPem": null
			}`,
			expectedPath: "/ccm/v1/certificates/123",
			expectedHeaders: map[string]string{
				"Content-Type": "application/json-patch+json",
			},
		},
		"200 OK - upload signed certificate PEM only": {
			params: PatchCertificateRequest{
				CertificateID:        "123",
				SignedCertificatePEM: "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
			},
			expectedResponse: &PatchCertificateResponse{
				AccountID:                           "acc_123",
				CertificateID:                       "123",
				CertificateName:                     "Certificate-name-rename",
				CertificateStatus:                   "CSR_READY",
				CertificateType:                     "THIRD_PARTY",
				ContractID:                          "ctr_123",
				CreatedBy:                           "user",
				CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
				CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
				CSRPEM:                              "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
				KeySize:                             "2048",
				KeyType:                             "RSA",
				ModifiedBy:                          "user",
				ModifiedDate:                        test.NewTimeFromString(t, "2025-08-22T09:01:32.607358Z"),
				SANs:                                []string{"example.com", "www.example.com"},
				SecureNetwork:                       "ENHANCED_TLS",
				SignedCertificateIssuer:             ptr.To("CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA"),
				SignedCertificateNotValidAfterDate:  ptr.To(test.NewTimeFromString(t, "2027-11-22T12:11:31Z")),
				SignedCertificateNotValidBeforeDate: ptr.To(test.NewTimeFromString(t, "2025-08-22T11:11:31Z")),
				SignedCertificatePEM:                ptr.To("-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n"),
				SignedCertificateSHA256Fingerprint:  ptr.To("4E:69:28:A1:CE:F1:E4:97:CE:39:FE:12:98"),
				SignedCertificateSerialNumber:       ptr.To("a2:84:7d:dc:97:f1"),
				Subject: &Subject{
					CommonName:   ptr.To("example.com"),
					Country:      ptr.To("US"),
					Locality:     ptr.To("Cambridge"),
					Organization: ptr.To(""),
					State:        ptr.To("Massachusetts"),
				},
				TrustChainPEM: nil,
			},
			expectedRequestBody: `[{"op":"add","path":"/signedCertificatePem","value":"-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n"}]`,
			responseStatus:      200,
			responseBody: `
			{
				"accountId": "acc_123",
				"certificateId": "123",
				"certificateName": "Certificate-name-rename",
				"certificateStatus": "CSR_READY",
				"certificateType": "THIRD_PARTY",
				"contractId": "ctr_123",
				"createdBy": "user",
				"createdDate": "2025-08-22T09:01:32.607357Z",
				"csrExpirationDate": "2026-10-24T09:01:34Z",
				"csrPem": "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
				"keySize": "2048",
				"keyType": "RSA",
				"modifiedBy": "user",
				"modifiedDate": "2025-08-22T09:01:32.607358Z",
				"sans": [
					"example.com",
					"www.example.com"
				],
				"secureNetwork": "ENHANCED_TLS",
				"signedCertificateIssuer": "CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA",
				"signedCertificateNotValidAfterDate": "2027-11-22T12:11:31Z",
				"signedCertificateNotValidBeforeDate": "2025-08-22T11:11:31Z",
				"signedCertificatePem": "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
				"signedCertificateSHA256Fingerprint": "4E:69:28:A1:CE:F1:E4:97:CE:39:FE:12:98",
				"signedCertificateSerialNumber": "a2:84:7d:dc:97:f1",
				"subject": {
					"commonName": "example.com",
					"country": "US",
					"locality": "Cambridge",
					"organization": "",
					"state": "Massachusetts"
				},
				"trustChainPem": null
			}`,
			expectedPath: "/ccm/v1/certificates/123",
			expectedHeaders: map[string]string{
				"Content-Type": "application/json-patch+json",
			},
		},
		"200 OK - upload signed certificate PEM with trust chain": {
			params: PatchCertificateRequest{
				CertificateID:        "123",
				SignedCertificatePEM: "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
				TrustChainPEM:        "-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n",
			},
			expectedResponse: &PatchCertificateResponse{
				AccountID:                           "acc_123",
				CertificateID:                       "123",
				CertificateName:                     "Certificate-name-rename",
				CertificateStatus:                   "CSR_READY",
				CertificateType:                     "THIRD_PARTY",
				ContractID:                          "ctr_123",
				CreatedBy:                           "user",
				CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
				CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
				CSRPEM:                              "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
				KeySize:                             "2048",
				KeyType:                             "RSA",
				ModifiedBy:                          "user",
				ModifiedDate:                        test.NewTimeFromString(t, "2025-08-22T09:01:32.607358Z"),
				SANs:                                []string{"example.com", "www.example.com"},
				SecureNetwork:                       "ENHANCED_TLS",
				SignedCertificateIssuer:             ptr.To("CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA"),
				SignedCertificateNotValidAfterDate:  ptr.To(test.NewTimeFromString(t, "2027-11-22T12:11:31Z")),
				SignedCertificateNotValidBeforeDate: ptr.To(test.NewTimeFromString(t, "2025-08-22T11:11:31Z")),
				SignedCertificatePEM:                ptr.To("-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n"),
				SignedCertificateSHA256Fingerprint:  ptr.To("4E:69:28:A1:CE:F1:E4:97:CE:39:FE:12:98"),
				SignedCertificateSerialNumber:       ptr.To("a2:84:7d:dc:97:f1"),
				Subject: &Subject{
					CommonName:   ptr.To("example.com"),
					Country:      ptr.To("US"),
					Locality:     ptr.To("Cambridge"),
					Organization: ptr.To(""),
					State:        ptr.To("Massachusetts"),
				},
				TrustChainPEM: ptr.To("-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"),
			},
			expectedRequestBody: `[{"op":"add","path":"/signedCertificatePem","value":"-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n"},{"op":"add","path":"/trustChainPem","value":"-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"}]`,
			responseStatus:      200,
			responseBody: `
			{
				"accountId": "acc_123",
				"certificateId": "123",
				"certificateName": "Certificate-name-rename",
				"certificateStatus": "CSR_READY",
				"certificateType": "THIRD_PARTY",
				"contractId": "ctr_123",
				"createdBy": "user",
				"createdDate": "2025-08-22T09:01:32.607357Z",
				"csrExpirationDate": "2026-10-24T09:01:34Z",
				"csrPem": "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
				"keySize": "2048",
				"keyType": "RSA",
				"modifiedBy": "user",
				"modifiedDate": "2025-08-22T09:01:32.607358Z",
				"sans": [
					"example.com",
					"www.example.com"
				],
				"secureNetwork": "ENHANCED_TLS",
				"signedCertificateIssuer": "CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA",
				"signedCertificateNotValidAfterDate": "2027-11-22T12:11:31Z",
				"signedCertificateNotValidBeforeDate": "2025-08-22T11:11:31Z",
				"signedCertificatePem": "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
				"signedCertificateSHA256Fingerprint": "4E:69:28:A1:CE:F1:E4:97:CE:39:FE:12:98",
				"signedCertificateSerialNumber": "a2:84:7d:dc:97:f1",
				"subject": {
					"commonName": "example.com",
					"country": "US",
					"locality": "Cambridge",
					"organization": "",
					"state": "Massachusetts"
				},
				"trustChainPem": "-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"
			}`,
			expectedPath: "/ccm/v1/certificates/123",
			expectedHeaders: map[string]string{
				"Content-Type": "application/json-patch+json",
			},
		},
		"200 OK - upload signed certificate with AcknowledgeWarnings query param": {
			params: PatchCertificateRequest{
				CertificateID:        "123",
				SignedCertificatePEM: "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
				AcknowledgeWarnings:  true,
			},
			expectedResponse: &PatchCertificateResponse{
				AccountID:                           "acc_123",
				CertificateID:                       "123",
				CertificateName:                     "Certificate-name-rename",
				CertificateStatus:                   "CSR_READY",
				CertificateType:                     "THIRD_PARTY",
				ContractID:                          "ctr_123",
				CreatedBy:                           "user",
				CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
				CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
				CSRPEM:                              "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
				KeySize:                             "2048",
				KeyType:                             "RSA",
				ModifiedBy:                          "user",
				ModifiedDate:                        test.NewTimeFromString(t, "2025-08-22T09:01:32.607358Z"),
				SANs:                                []string{"example.com", "www.example.com"},
				SecureNetwork:                       "ENHANCED_TLS",
				SignedCertificateIssuer:             ptr.To("CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA"),
				SignedCertificateNotValidAfterDate:  ptr.To(test.NewTimeFromString(t, "2027-11-22T12:11:31Z")),
				SignedCertificateNotValidBeforeDate: ptr.To(test.NewTimeFromString(t, "2025-08-22T11:11:31Z")),
				SignedCertificatePEM:                ptr.To("-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n"),
				SignedCertificateSHA256Fingerprint:  ptr.To("4E:69:28:A1:CE:F1:E4:97:CE:39:FE:12:98"),
				SignedCertificateSerialNumber:       ptr.To("a2:84:7d:dc:97:f1"),
				Subject: &Subject{
					CommonName:   ptr.To("example.com"),
					Country:      ptr.To("US"),
					Locality:     ptr.To("Cambridge"),
					Organization: ptr.To(""),
					State:        ptr.To("Massachusetts"),
				},
				TrustChainPEM: nil,
			},
			expectedRequestBody: `[{"op":"add","path":"/signedCertificatePem","value":"-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n"}]`,
			responseStatus:      200,
			responseBody: `
			{
				"accountId": "acc_123",
				"certificateId": "123",
				"certificateName": "Certificate-name-rename",
				"certificateStatus": "CSR_READY",
				"certificateType": "THIRD_PARTY",
				"contractId": "ctr_123",
				"createdBy": "user",
				"createdDate": "2025-08-22T09:01:32.607357Z",
				"csrExpirationDate": "2026-10-24T09:01:34Z",
				"csrPem": "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
				"keySize": "2048",
				"keyType": "RSA",
				"modifiedBy": "user",
				"modifiedDate": "2025-08-22T09:01:32.607358Z",
				"sans": [
					"example.com",
					"www.example.com"
				],
				"secureNetwork": "ENHANCED_TLS",
				"signedCertificateIssuer": "CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA",
				"signedCertificateNotValidAfterDate": "2027-11-22T12:11:31Z",
				"signedCertificateNotValidBeforeDate": "2025-08-22T11:11:31Z",
				"signedCertificatePem": "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
				"signedCertificateSHA256Fingerprint": "4E:69:28:A1:CE:F1:E4:97:CE:39:FE:12:98",
				"signedCertificateSerialNumber": "a2:84:7d:dc:97:f1",
				"subject": {
					"commonName": "example.com",
					"country": "US",
					"locality": "Cambridge",
					"organization": "",
					"state": "Massachusetts"
				},
				"trustChainPem": null
			}`,
			expectedPath: "/ccm/v1/certificates/123?acknowledgeWarnings=true",
			expectedHeaders: map[string]string{
				"Content-Type": "application/json-patch+json",
			},
		},
		"200 OK - upload signed certificate and trust chain PEM with AcknowledgeWarnings query param and rename certificate": {
			params: PatchCertificateRequest{
				CertificateID:        "123",
				SignedCertificatePEM: "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
				TrustChainPEM:        "-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n",
				CertificateName:      ptr.To("Certificate-name-rename"),
				AcknowledgeWarnings:  true,
			},
			expectedResponse: &PatchCertificateResponse{
				AccountID:                           "acc_123",
				CertificateID:                       "123",
				CertificateName:                     "Certificate-name-rename",
				CertificateStatus:                   "CSR_READY",
				CertificateType:                     "THIRD_PARTY",
				ContractID:                          "ctr_123",
				CreatedBy:                           "user",
				CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
				CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
				CSRPEM:                              "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
				KeySize:                             "2048",
				KeyType:                             "RSA",
				ModifiedBy:                          "user",
				ModifiedDate:                        test.NewTimeFromString(t, "2025-08-22T09:01:32.607358Z"),
				SANs:                                []string{"example.com", "www.example.com"},
				SecureNetwork:                       "ENHANCED_TLS",
				SignedCertificateIssuer:             ptr.To("CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA"),
				SignedCertificateNotValidAfterDate:  ptr.To(test.NewTimeFromString(t, "2027-11-22T12:11:31Z")),
				SignedCertificateNotValidBeforeDate: ptr.To(test.NewTimeFromString(t, "2025-08-22T11:11:31Z")),
				SignedCertificatePEM:                ptr.To("-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n"),
				SignedCertificateSHA256Fingerprint:  ptr.To("4E:69:28:A1:CE:F1:E4:97:CE:39:FE:12:98"),
				SignedCertificateSerialNumber:       ptr.To("a2:84:7d:dc:97:f1"),
				Subject: &Subject{
					CommonName:   ptr.To("example.com"),
					Country:      ptr.To("US"),
					Locality:     ptr.To("Cambridge"),
					Organization: ptr.To(""),
					State:        ptr.To("Massachusetts"),
				},
				TrustChainPEM: ptr.To("-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"),
			},
			expectedRequestBody: `[{"op":"add","path":"/signedCertificatePem","value":"-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n"},{"op":"add","path":"/trustChainPem","value":"-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"},{"op":"replace","path":"/certificateName","value":"Certificate-name-rename"}]`,
			responseStatus:      200,
			responseBody: `
			{
				"accountId": "acc_123",
				"certificateId": "123",
				"certificateName": "Certificate-name-rename",
				"certificateStatus": "CSR_READY",
				"certificateType": "THIRD_PARTY",
				"contractId": "ctr_123",
				"createdBy": "user",
				"createdDate": "2025-08-22T09:01:32.607357Z",
				"csrExpirationDate": "2026-10-24T09:01:34Z",
				"csrPem": "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
				"keySize": "2048",
				"keyType": "RSA",
				"modifiedBy": "user",
				"modifiedDate": "2025-08-22T09:01:32.607358Z",
				"sans": [
					"example.com",
					"www.example.com"
				],
				"secureNetwork": "ENHANCED_TLS",
				"signedCertificateIssuer": "CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA",
				"signedCertificateNotValidAfterDate": "2027-11-22T12:11:31Z",
				"signedCertificateNotValidBeforeDate": "2025-08-22T11:11:31Z",
				"signedCertificatePem": "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
				"signedCertificateSHA256Fingerprint": "4E:69:28:A1:CE:F1:E4:97:CE:39:FE:12:98",
				"signedCertificateSerialNumber": "a2:84:7d:dc:97:f1",
				"subject": {
					"commonName": "example.com",
					"country": "US",
					"locality": "Cambridge",
					"organization": "",
					"state": "Massachusetts"
				},
				"trustChainPem": "-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"
			}`,
			expectedPath: "/ccm/v1/certificates/123?acknowledgeWarnings=true",
			expectedHeaders: map[string]string{
				"Content-Type": "application/json-patch+json",
			},
		},
		"409 OK - warnings in the response for certificate pem": {
			params: PatchCertificateRequest{
				CertificateID:        "123",
				SignedCertificatePEM: "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
			},
			expectedRequestBody: `[{"op":"add","path":"/signedCertificatePem","value":"-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n"}]`,
			responseStatus:      409,
			responseBody: `
			{
				"data": {
					"signedCertificatePem": "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
					"signedCertificates": [
						{
							"certificatePem": "-----BEGIN CERTIFICATE-----\nexample-PEM\n-----END CERTIFICATE-----",
							"createdBy": null,
							"createdDate": null,
							"displayName": null,
							"endDate": "2027-11-22T12:45:19Z",
							"fingerprint": null,
							"issuer": "CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA",
							"sans": [
								"example.com",
								"www.example.com"
							],
							"serialNumber": "1234567890",
							"signatureAlgorithm": "SHA256WITHRSA",
							"startDate": "2025-08-22T11:45:19Z",
							"subject": {
								"commonName": "example.com",
								"country": "US",
								"locality": "Cambridge",
								"organization": null,
								"state": "Massachusetts"
							},
							"validation": {
								"errors": [],
								"notices": [],
								"warnings": [
									{
										"detail": "Message: Certificate validity period is above the maximum 398 days.. Name: LEAF_CERTIFICATE",
										"instance": "/error-types/certificate-validation-warning?traceId=123456789",
										"message": "Certificate validity period is above the maximum 398 days.",
										"name": "LEAF_CERTIFICATE",
										"title": "Certificate validation warning.",
										"type": "/error-types/certificate-validation-warning"
									}
								]
							}
						}
					],
					"trustChain": [],
					"trustChainPem": null,
					"validation": {
						"errors": [],
						"notices": [],
						"warnings": [
							{
								"detail": "Message: Name: MaxMinExpirationDateValidator Message: RSA certificate expiration is longer than allowed. Must expire within 398 days. Name: UNKNOWN",
								"instance": "/error-types/certificate-validation-warning?traceId=123456789",
								"message": "Name: MaxMinExpirationDateValidator Message: RSA certificate expiration is longer than allowed. Must expire within 398 days",
								"name": "UNKNOWN",
								"status": 400,
								"title": "Certificate validation warning.",
								"type": "/error-types/certificate-validation-warning"
							},
							{
								"detail": "Message: Name: TrustChainRequiredValidator Message: RSA certificate does not come with a trust chain and this is a non-standard practice. Name: UNKNOWN",
								"instance": "/error-types/certificate-validation-warning?traceId=123456789",
								"message": "Name: TrustChainRequiredValidator Message: RSA certificate does not come with a trust chain and this is a non-standard practice",
								"name": "UNKNOWN",
								"status": 400,
								"title": "Certificate validation warning.",
								"type": "/error-types/certificate-validation-warning"
							}
						]
					}
				},
				"detail": "Warnings detected in one or more of the uploaded certificates.",
				"instance": "/error-types/upload-certificate-validation-warnings?traceId=123456789",
				"status": 409,
				"title": "Validation warnings for uploaded signed certificate(s) and trust chain(s) for one or more key types.",
				"type": "/error-types/upload-certificate-validation-warnings"
			}`,
			expectedPath: "/ccm/v1/certificates/123",
			expectedHeaders: map[string]string{
				"Content-Type": "application/json-patch+json",
			},
			withError: func(t *testing.T, err error) {
				want := fmt.Errorf("%w: %w", ErrPatchCertificate, &Error{
					Type:     "/error-types/upload-certificate-validation-warnings",
					Title:    "Validation warnings for uploaded signed certificate(s) and trust chain(s) for one or more key types.",
					Detail:   "Warnings detected in one or more of the uploaded certificates.",
					Instance: "/error-types/upload-certificate-validation-warnings?traceId=123456789",
					Status:   409,
					Data: &ValidationData{
						SignedCertificatePEM: "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
						SignedCertificates: []PEMValidation{
							{
								CertificatePEM:     "-----BEGIN CERTIFICATE-----\nexample-PEM\n-----END CERTIFICATE-----",
								CreatedBy:          nil,
								CreatedDate:        nil,
								DisplayName:        nil,
								EndDate:            ptr.To("2027-11-22T12:45:19Z"),
								Fingerprint:        nil,
								Issuer:             ptr.To("CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA"),
								SerialNumber:       ptr.To("1234567890"),
								SignatureAlgorithm: ptr.To("SHA256WITHRSA"),
								StartDate:          ptr.To("2025-08-22T11:45:19Z"),
								Subject: &Subject{
									CommonName:   ptr.To("example.com"),
									Country:      ptr.To("US"),
									Locality:     ptr.To("Cambridge"),
									Organization: nil,
									State:        ptr.To("Massachusetts"),
								},
								Validation: &ValidationResult{
									Errors:  []ValidationDetail{},
									Notices: []ValidationDetail{},
									Warnings: []ValidationDetail{
										{
											Detail:   "Message: Certificate validity period is above the maximum 398 days.. Name: LEAF_CERTIFICATE",
											Instance: "/error-types/certificate-validation-warning?traceId=123456789",
											Message:  "Certificate validity period is above the maximum 398 days.",
											Name:     "LEAF_CERTIFICATE",
											Title:    "Certificate validation warning.",
											Type:     "/error-types/certificate-validation-warning",
										},
									},
								},
							},
						},
						TrustChain:    []PEMValidation{},
						TrustChainPEM: nil,
						Validation: &ValidationResult{
							Errors:  []ValidationDetail{},
							Notices: []ValidationDetail{},
							Warnings: []ValidationDetail{
								{
									Detail:   "Message: Name: MaxMinExpirationDateValidator Message: RSA certificate expiration is longer than allowed. Must expire within 398 days. Name: UNKNOWN",
									Instance: "/error-types/certificate-validation-warning?traceId=123456789",
									Message:  "Name: MaxMinExpirationDateValidator Message: RSA certificate expiration is longer than allowed. Must expire within 398 days",
									Name:     "UNKNOWN",
									Status:   ptr.To(400),
									Title:    "Certificate validation warning.",
									Type:     "/error-types/certificate-validation-warning",
								},
								{
									Detail:   "Message: Name: TrustChainRequiredValidator Message: RSA certificate does not come with a trust chain and this is a non-standard practice. Name: UNKNOWN",
									Instance: "/error-types/certificate-validation-warning?traceId=123456789",
									Message:  "Name: TrustChainRequiredValidator Message: RSA certificate does not come with a trust chain and this is a non-standard practice",
									Name:     "UNKNOWN",
									Status:   ptr.To(400),
									Title:    "Certificate validation warning.",
									Type:     "/error-types/certificate-validation-warning",
								},
							},
						},
					},
				})
				assert.EqualError(t, err, want.Error(), "want: %s; got: %s", want, err)
			},
		},
		"409 OK - warnings in the response for certificate pem and trust chain": {
			params: PatchCertificateRequest{
				CertificateID:        "123",
				SignedCertificatePEM: "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
			},
			expectedRequestBody: `[{"op":"add","path":"/signedCertificatePem","value":"-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n"}]`,
			responseStatus:      409,
			responseBody: `
			{
				"data": {
					"signedCertificatePem": "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
					"signedCertificates": [
						{
							"certificatePem": "-----BEGIN CERTIFICATE-----\nexample-PEM\n-----END CERTIFICATE-----",
							"createdBy": null,
							"createdDate": null,
							"displayName": null,
							"endDate": "2027-11-22T12:45:19Z",
							"fingerprint": null,
							"issuer": "CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA",
							"sans": [
								"example.com",
								"www.example.com"
							],
							"serialNumber": "1234567890",
							"signatureAlgorithm": "SHA256WITHRSA",
							"startDate": "2025-08-22T11:45:19Z",
							"subject": {
								"commonName": "example.com",
								"country": "US",
								"locality": "Cambridge",
								"organization": null,
								"state": "Massachusetts"
							},
							"validation": {
								"errors": [],
								"notices": [],
								"warnings": [
									{
										"detail": "Message: Certificate validity period is above the maximum 398 days.. Name: LEAF_CERTIFICATE",
										"instance": "/error-types/certificate-validation-warning?traceId=123456789",
										"message": "Certificate validity period is above the maximum 398 days.",
										"name": "LEAF_CERTIFICATE",
										"title": "Certificate validation warning.",
										"type": "/error-types/certificate-validation-warning"
									}
								]
							}
						}
					],
					"trustChain": [
						{
							"certificatePem": "-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----",
							"createdBy": null,
							"createdDate": null,
							"displayName": null,
							"endDate": "2027-11-22T12:45:19Z",
							"fingerprint": null,
							"issuer": "CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA",
							"sans": null,
							"serialNumber": "1234567890",
							"signatureAlgorithm": "SHA256WITHRSA",
							"startDate": "2025-08-22T11:45:19Z",
							"subject": null,
							"validation": {
								"errors": [
									{
										"detail": "Message: Certificate is not an intermediate trust chain certificate. Name: TRUST_CHAIN_CERTIFICATE",
										"instance": "/error-types/certificate-validation-failed?traceId=123456789",
										"message": "Certificate is not an intermediate trust chain certificate.",
										"name": "TRUST_CHAIN_CERTIFICATE",
										"title": "Certificate validation error.",
										"type": "/error-types/certificate-validation-failed"
									}
								],
								"notices": [],
								"warnings": []
							}
						}
					],
					"trustChainPem": "-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n",
					"validation": {
						"errors": [],
						"notices": [],
						"warnings": []
					}
				},
				"detail": "Errors detected in one or more of the uploaded certificates.",
				"instance": "/error-types/upload-certificate-validation-failed?traceId=123456789",
				"status": 400,
				"title": "Validation failed for uploaded signed certificate(s) and trust chain(s) for one or more key types.",
				"type": "/error-types/upload-certificate-validation-failed"
			}`,
			expectedPath: "/ccm/v1/certificates/123",
			expectedHeaders: map[string]string{
				"Content-Type": "application/json-patch+json",
			},
			withError: func(t *testing.T, err error) {
				want := fmt.Errorf("%w: %w", ErrPatchCertificate, &Error{
					Type:     "/error-types/upload-certificate-validation-failed",
					Title:    "Validation failed for uploaded signed certificate(s) and trust chain(s) for one or more key types.",
					Detail:   "Errors detected in one or more of the uploaded certificates.",
					Instance: "/error-types/upload-certificate-validation-failed?traceId=123456789",
					Status:   409,
					Data: &ValidationData{
						SignedCertificatePEM: "-----BEGIN CERTIFICATE-----\nexample-signed-PEM\n-----END CERTIFICATE-----\n",
						SignedCertificates: []PEMValidation{
							{
								CertificatePEM:     "-----BEGIN CERTIFICATE-----\nexample-PEM\n-----END CERTIFICATE-----",
								CreatedBy:          nil,
								CreatedDate:        nil,
								DisplayName:        nil,
								EndDate:            ptr.To("2027-11-22T12:45:19Z"),
								Fingerprint:        nil,
								Issuer:             ptr.To("CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA"),
								SerialNumber:       ptr.To("1234567890"),
								SignatureAlgorithm: ptr.To("SHA256WITHRSA"),
								StartDate:          ptr.To("2025-08-22T11:45:19Z"),
								Subject: &Subject{
									CommonName:   ptr.To("example.com"),
									Country:      ptr.To("US"),
									Locality:     ptr.To("Cambridge"),
									Organization: nil,
									State:        ptr.To("Massachusetts"),
								},
								Validation: &ValidationResult{
									Errors:  []ValidationDetail{},
									Notices: []ValidationDetail{},
									Warnings: []ValidationDetail{
										{
											Detail:   "Message: Certificate validity period is above the maximum 398 days.. Name: LEAF_CERTIFICATE",
											Instance: "/error-types/certificate-validation-warning?traceId=123456789",
											Message:  "Certificate validity period is above the maximum 398 days.",
											Name:     "LEAF_CERTIFICATE",
											Title:    "Certificate validation warning.",
											Type:     "/error-types/certificate-validation-warning",
										},
									},
								},
							},
						},
						TrustChain: []PEMValidation{
							{
								CertificatePEM:     "-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----",
								CreatedBy:          nil,
								CreatedDate:        nil,
								DisplayName:        nil,
								EndDate:            ptr.To("2027-11-22T12:45:19Z"),
								Fingerprint:        nil,
								Issuer:             ptr.To("CN=mkcert user (name surname),OU=organization (name surname),O=mkcert development CA"),
								SerialNumber:       ptr.To("1234567890"),
								SignatureAlgorithm: ptr.To("SHA256WITHRSA"),
								StartDate:          ptr.To("2025-08-22T11:45:19Z"),
								Subject:            nil,
								Validation: &ValidationResult{
									Errors: []ValidationDetail{
										{
											Detail:   "Message: Certificate is not an intermediate trust chain certificate. Name: TRUST_CHAIN_CERTIFICATE",
											Instance: "/error-types/certificate-validation-failed?traceId=123456789",
											Message:  "Certificate is not an intermediate trust chain certificate.",
											Name:     "TRUST_CHAIN_CERTIFICATE",
											Title:    "Certificate validation error.",
											Type:     "/error-types/certificate-validation-failed",
										},
									},
									Notices:  []ValidationDetail{},
									Warnings: []ValidationDetail{},
								},
							},
						},
						TrustChainPEM: ptr.To("-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"),
						Validation: &ValidationResult{
							Errors:   []ValidationDetail{},
							Notices:  []ValidationDetail{},
							Warnings: []ValidationDetail{},
						},
					},
				})
				assert.EqualError(t, err, want.Error(), "want: %s; got: %s", want, err)
			},
		},
		"409 Conflict - name already in use": {
			params: PatchCertificateRequest{
				CertificateID:   "123",
				CertificateName: ptr.To("duplicate-name"),
			},
			expectedRequestBody: "[{\"op\":\"replace\",\"path\":\"/certificateName\",\"value\":\"duplicate-name\"}]",
			responseStatus:      409,
			responseBody: `
			{
				"certificateIdentifier": "certificateName",
				"certificateIdentifierValue": "duplicate-name.com20250821015427758880",
				"detail": "Certificate with {certificateName}: {duplicate-name.com20250821015427758880} already exists with the current account Id!",
				"instance": "/error-types/certificate-name-already-in-use?traceId=-123",
				"status": 409,
				"title": "Certificate name already in use.",
				"type": "/error-types/certificate-name-already-in-use"
			}`,
			expectedPath: "/ccm/v1/certificates/123",
			expectedHeaders: map[string]string{
				"Content-Type": "application/json-patch+json",
			},
			withError: func(t *testing.T, err error) {
				want := fmt.Errorf("%w: %w", ErrPatchCertificate, &Error{
					Type:                       "/error-types/certificate-name-already-in-use",
					Title:                      "Certificate name already in use.",
					Detail:                     "Certificate with {certificateName}: {duplicate-name.com20250821015427758880} already exists with the current account Id!",
					Status:                     http.StatusConflict,
					Instance:                   "/error-types/certificate-name-already-in-use?traceId=-123",
					CertificateIdentifier:      "certificateName",
					CertificateIdentifierValue: "duplicate-name.com20250821015427758880",
				})
				assert.EqualError(t, err, want.Error(), "want: %s; got: %s", want, err)
				assert.ErrorIs(t, err, ErrCertificateNameInUse)
			},
		},
		"validation error - name too long - assert that error is ErrPatchCertificate and ErrStructValidation": {
			params: PatchCertificateRequest{
				CertificateID:   "123",
				CertificateName: ptr.To(strings.Repeat("A", 271)),
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "patching certificate: struct validation: CertificateName: the length must be no more than 270",
					err.Error())
				assert.ErrorIs(t, err, ErrPatchCertificate)
				assert.ErrorIs(t, err, ErrStructValidation)
			},
		},
		"validation error - name contains invalid characters": {
			params: PatchCertificateRequest{
				CertificateID:   "123",
				CertificateName: ptr.To("Invalid@Name"),
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "patching certificate: struct validation: CertificateName: the input can only contain digits (1-9), letters (a-z, A-Z), spaces, hyphens, periods, and underscores.",
					err.Error())
				assert.ErrorIs(t, err, ErrPatchCertificate)
				assert.ErrorIs(t, err, ErrStructValidation)
			},
		},
		"validation error - missing required parameters": {
			params: PatchCertificateRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "patching certificate: struct validation: CertificateID: cannot be blank\nrequired parameters: at least one of SignedCertificatePEM or CertificateName must be provided",
					err.Error())
				assert.ErrorIs(t, err, ErrPatchCertificate)
				assert.ErrorIs(t, err, ErrStructValidation)
			},
		},
		"URL parsing error - assert that error is ErrPatchCertificate when parsing URL": {
			params: PatchCertificateRequest{
				CertificateID: "123 wrong url",
			},
			withError: func(t *testing.T, err error) {
				assert.EqualError(t, err, "patching certificate: struct validation: required parameters: at least one of SignedCertificatePEM or CertificateName must be provided")
				assert.ErrorIs(t, err, ErrPatchCertificate, "want: %s; got: %s", ErrPatchCertificate, err)
				assert.ErrorIs(t, err, ErrStructValidation, "want: %s; got: %s", ErrStructValidation, err)
			},
		},
		"500 internal server error - assert that error is ErrPatchCertificate": {
			params: PatchCertificateRequest{
				CertificateID:   "123",
				CertificateName: ptr.To("New-Certificate-Name"),
			},
			expectedRequestBody: "[{\"op\":\"replace\",\"path\":\"/certificateName\",\"value\":\"New-Certificate-Name\"}]",
			responseStatus:      500,
			responseBody: `
			{
				"type": "internal_error",
				"title": "Internal Server Error",
				"detail": "Error removing property hostname",
				"status": 500
			}`,
			expectedPath: "/ccm/v1/certificates/123",
			withError: func(t *testing.T, err error) {
				want := fmt.Errorf("%w: %w", ErrPatchCertificate, &Error{
					Type:   "internal_error",
					Title:  "Internal Server Error",
					Detail: "Error removing property hostname",
					Status: http.StatusInternalServerError,
				})
				assert.EqualError(t, err, want.Error(), "want: %s; got: %s", want, err)
				assert.ErrorIs(t, err, ErrPatchCertificate)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tc.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodPatch, r.Method)
				for k, v := range tc.expectedHeaders {
					assert.Equal(t, v, r.Header.Get(k))
				}
				requestBody, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedRequestBody, string(requestBody))
				w.WriteHeader(tc.responseStatus)
				_, err = w.Write([]byte(tc.responseBody))
				assert.NoError(t, err)
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.PatchCertificate(context.Background(), tc.params)

			if tc.withError != nil {
				tc.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedResponse, result)
		})
	}
}
