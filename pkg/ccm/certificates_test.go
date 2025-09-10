package ccm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/internal/test"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/ptr"
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
				ContractID:              "A-123",
				CreatedBy:               "user",
				CreatedDate:             test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
				CSRExpirationDate:       test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
				CSRPEM:                  ptr.To("-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n"),
				KeySize:                 "2048",
				KeyType:                 "RSA",
				ModifiedBy:              "user",
				ModifiedDate:            test.NewTimeFromString(t, "2025-08-22T09:01:32.607358Z"),
				SANs:                    []string{"example.com", "www.example.com"},
				SecureNetwork:           "ENHANCED_TLS",
				SignedCertificateIssuer: nil,
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
				"contractId": "A-123",
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
				"signedCertificateIssuer": null,
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
				ContractID:              "A-123",
				CreatedBy:               "user",
				CreatedDate:             test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
				CSRExpirationDate:       test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
				CSRPEM:                  ptr.To("-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n"),
				KeySize:                 "2048",
				KeyType:                 "RSA",
				ModifiedBy:              "user",
				ModifiedDate:            test.NewTimeFromString(t, "2025-08-22T09:01:32.607358Z"),
				SANs:                    []string{"example.com", "www.example.com"},
				SecureNetwork:           "ENHANCED_TLS",
				SignedCertificateIssuer: nil,
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
				"contractId": "A-123",
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
				"signedCertificateIssuer": null,
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
				ContractID:                          "A-123",
				CreatedBy:                           "user",
				CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
				CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
				CSRPEM:                              ptr.To("-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n"),
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
				"contractId": "A-123",
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
				ContractID:                          "A-123",
				CreatedBy:                           "user",
				CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
				CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
				CSRPEM:                              ptr.To("-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n"),
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
				"contractId": "A-123",
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
				ContractID:                          "A-123",
				CreatedBy:                           "user",
				CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
				CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
				CSRPEM:                              ptr.To("-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n"),
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
				"contractId": "A-123",
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
				ContractID:                          "A-123",
				CreatedBy:                           "user",
				CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
				CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
				CSRPEM:                              ptr.To("-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n"),
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
				"contractId": "A-123",
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

func TestListCertificates(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		params           ListCertificatesRequest
		expectedResponse *ListCertificatesResponse
		responseStatus   int
		responseBody     string
		expectedPath     string
		withError        func(t *testing.T, err error)
	}{
		"200 OK - list certificates with no params": {
			params: ListCertificatesRequest{},
			expectedResponse: &ListCertificatesResponse{
				Certificates: []Certificate{
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert1_1234",
						CertificateName:                     "Test Certificate1",
						CertificateStatus:                   "ACTIVE",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
						CSRPEM:                              nil,
						KeySize:                             "2048",
						KeyType:                             "RSA",
						SANs:                                []string{"test-example.com", "www.test-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             nil,
						SignedCertificateNotValidAfterDate:  ptr.To(test.NewTimeFromString(t, "2027-11-22T12:11:31Z")),
						SignedCertificateNotValidBeforeDate: ptr.To(test.NewTimeFromString(t, "2025-08-22T11:11:31Z")),
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName: ptr.To("test-example.com"),
							Country:    ptr.To("US"),
							Locality:   ptr.To("Cambridge"),
							State:      ptr.To("Massachusetts"),
						},
						TrustChainPEM: nil,
					},
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert2_1234",
						CertificateName:                     "Test Certificate2",
						CertificateStatus:                   "CSR_READY",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2025-09-15T10:20:30.123456Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
						CSRPEM:                              nil,
						KeySize:                             "P-256",
						KeyType:                             "ECDSA",
						SANs:                                []string{"test2-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             ptr.To("O=test organization NY,L=New York,ST=NY,C=US"),
						SignedCertificateNotValidAfterDate:  ptr.To(test.NewTimeFromString(t, "2027-11-22T12:11:31Z")),
						SignedCertificateNotValidBeforeDate: ptr.To(test.NewTimeFromString(t, "2025-08-22T11:11:31Z")),
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName:   ptr.To("test2-example.com"),
							Country:      ptr.To("US"),
							Locality:     ptr.To("New York"),
							Organization: ptr.To("test organization NY"),
							State:        ptr.To("New York"),
						},
						TrustChainPEM: ptr.To("-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"),
					},
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert3_1234",
						CertificateName:                     "Test Certificate3",
						CertificateStatus:                   "READY_FOR_USE",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2025-10-05T11:30:45.654321Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
						CSRPEM:                              nil,
						KeySize:                             "2048",
						KeyType:                             "RSA",
						SANs:                                []string{"test3-example.com", "www.test3-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             nil,
						SignedCertificateNotValidAfterDate:  nil,
						SignedCertificateNotValidBeforeDate: nil,
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName: ptr.To("test3-example.com"),
							Country:    ptr.To("US"),
							Locality:   ptr.To("San Francisco"),
							State:      ptr.To("California"),
						},
						TrustChainPEM: nil,
					},
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert4_1234",
						CertificateName:                     "Test Certificate4",
						CertificateStatus:                   "READY_FOR_USE",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2023-10-05T11:30:45.654321Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2024-10-24T09:01:34Z"),
						CSRPEM:                              nil,
						KeySize:                             "P-256",
						KeyType:                             "ECDSA",
						SANs:                                []string{"test4-example.com", "www.test4-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             ptr.To("O=test organization LA,L=Los Angeles,ST=California,C=US"),
						SignedCertificateNotValidAfterDate:  nil,
						SignedCertificateNotValidBeforeDate: nil,
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName:   ptr.To("test4-example.com"),
							Country:      ptr.To("US"),
							Locality:     ptr.To("Los Angeles"),
							Organization: ptr.To("test organization LA"),
							State:        ptr.To("California"),
						},
						TrustChainPEM: nil,
					},
				},
				Links: Links{
					Self:     "/ccm/v1/certificates?page=1&pageSize=10",
					Next:     nil,
					Previous: nil,
				},
				Metadata: ListMetadata{
					TotalItems: 4,
					TotalPages: 1,
				},
			},
			responseStatus: 200,
			responseBody: `
			{
				"certificates": [
					{
						"accountId": "test-account-id",
						"certificateId": "cert1_1234",
						"certificateName": "Test Certificate1",
						"certificateStatus": "ACTIVE",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2025-08-22T09:01:32.607357Z",
						"csrExpirationDate": "2026-10-24T09:01:34Z",
						"csrPem": null,
						"keySize": "2048",
						"keyType": "RSA",
						"sans": [
							"test-example.com",
							"www.test-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": null,
						"signedCertificateNotValidAfterDate": "2027-11-22T12:11:31Z",
						"signedCertificateNotValidBeforeDate": "2025-08-22T11:11:31Z",
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test-example.com",
							"country": "US",
							"locality": "Cambridge",
							"state": "Massachusetts"
						},
						"trustChainPem": null
					},
					{
						"accountId": "test-account-id",
						"certificateId": "cert2_1234",
						"certificateName": "Test Certificate2",
						"certificateStatus": "CSR_READY",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2025-09-15T10:20:30.123456Z",
						"csrExpirationDate": "2026-10-24T09:01:34Z",
						"csrPem": null,
						"keySize": "P-256",
						"keyType": "ECDSA",
						"sans": [
							"test2-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": "O=test organization NY,L=New York,ST=NY,C=US",
						"signedCertificateNotValidAfterDate": "2027-11-22T12:11:31Z",
						"signedCertificateNotValidBeforeDate": "2025-08-22T11:11:31Z",
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test2-example.com",
							"country": "US",
							"locality": "New York",
							"organization": "test organization NY",
							"state": "New York"
						},
						"trustChainPem": "-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"
					},
					{
						"accountId": "test-account-id",
						"certificateId": "cert3_1234",
						"certificateName": "Test Certificate3",
						"certificateStatus": "READY_FOR_USE",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2025-10-05T11:30:45.654321Z",
						"csrExpirationDate": "2026-10-24T09:01:34Z",
						"csrPem": null,
						"keySize": "2048",
						"keyType": "RSA",
						"sans": [
							"test3-example.com",
							"www.test3-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": null,
						"signedCertificateNotValidAfterDate": null,
						"signedCertificateNotValidBeforeDate": null,
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test3-example.com",
							"country": "US",
							"locality": "San Francisco",
							"state": "California"
						},
						"trustChainPem": null
					},
					{
						"accountId": "test-account-id",
						"certificateId": "cert4_1234",
						"certificateName": "Test Certificate4",
						"certificateStatus": "READY_FOR_USE",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2023-10-05T11:30:45.654321Z",
						"csrExpirationDate": "2024-10-24T09:01:34Z",
						"csrPem": null,
						"keySize": "P-256",
						"keyType": "ECDSA",
						"sans": [
							"test4-example.com",
							"www.test4-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": "O=test organization LA,L=Los Angeles,ST=California,C=US",
						"signedCertificateNotValidAfterDate": null,
						"signedCertificateNotValidBeforeDate": null,
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test4-example.com",
							"country": "US",
							"locality": "Los Angeles",
							"organization": "test organization LA",
							"state": "California"
						},
						"trustChainPem": null
					}
				],
				"links": {
					"self": "/ccm/v1/certificates?page=1&pageSize=10",
					"next": null,
					"previous": null
				},
				"metadata": {
					"totalItems": 4,
					"totalPages": 1
				}
			}`,
			expectedPath: "/ccm/v1/certificates",
		},
		"200 OK - with domain filtering": {
			params: ListCertificatesRequest{
				ContractID: "A-123",
				GroupID:    "1234",
				Domain:     "test3-example.com",
			},
			expectedResponse: &ListCertificatesResponse{
				Certificates: []Certificate{
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert3_1234",
						CertificateName:                     "Test Certificate3",
						CertificateStatus:                   "PENDING_CSR_GENERATION",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2025-10-05T11:30:45.654321Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
						CSRPEM:                              nil,
						KeySize:                             "2048",
						KeyType:                             "RSA",
						SANs:                                []string{"test3-example.com", "www.test3-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             nil,
						SignedCertificateNotValidAfterDate:  nil,
						SignedCertificateNotValidBeforeDate: nil,
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName: ptr.To("test3-example.com"),
							Country:    ptr.To("US"),
							Locality:   ptr.To("San Francisco"),
							State:      ptr.To("California"),
						},
						TrustChainPEM: nil,
					},
				},
				Links: Links{
					Self:     "/ccm/v1/certificates?page=1&pageSize=10",
					Next:     nil,
					Previous: nil,
				},
				Metadata: ListMetadata{
					TotalItems: 1,
					TotalPages: 1,
				},
			},
			responseStatus: 200,
			responseBody: `
			{
				"certificates": [
					{
						"accountId": "test-account-id",
						"certificateId": "cert3_1234",
						"certificateName": "Test Certificate3",
						"certificateStatus": "PENDING_CSR_GENERATION",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2025-10-05T11:30:45.654321Z",
						"csrExpirationDate": "2026-10-24T09:01:34Z",
						"csrPem": null,
						"keySize": "2048",
						"keyType": "RSA",
						"sans": [
							"test3-example.com",
							"www.test3-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": null,
						"signedCertificateNotValidAfterDate": null,
						"signedCertificateNotValidBeforeDate": null,
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test3-example.com",
							"country": "US",
							"locality": "San Francisco",
							"state": "California"
						},
						"trustChainPem": null
					}
				],
				"links": {
					"self": "/ccm/v1/certificates?page=1&pageSize=10",
					"next": null,
					"previous": null
				},
				"metadata": {
					"totalItems": 1,
					"totalPages": 1
				}
			}`,
			expectedPath: "/ccm/v1/certificates?contractId=A-123&domain=test3-example.com&groupId=1234",
		},
		"200 OK - with status filtering": {
			params: ListCertificatesRequest{
				CertificateStatus: []CertificateStatus{StatusActive, StatusReadyForUse},
			},
			expectedResponse: &ListCertificatesResponse{
				Certificates: []Certificate{
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert1_1234",
						CertificateName:                     "Test Certificate1",
						CertificateStatus:                   "ACTIVE",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
						CSRPEM:                              nil,
						KeySize:                             "2048",
						KeyType:                             "RSA",
						SANs:                                []string{"test-example.com", "www.test-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             nil,
						SignedCertificateNotValidAfterDate:  ptr.To(test.NewTimeFromString(t, "2027-11-22T12:11:31Z")),
						SignedCertificateNotValidBeforeDate: ptr.To(test.NewTimeFromString(t, "2025-08-22T11:11:31Z")),
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName: ptr.To("test-example.com"),
							Country:    ptr.To("US"),
							Locality:   ptr.To("Cambridge"),
							State:      ptr.To("Massachusetts"),
						},
						TrustChainPEM: nil,
					},
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert3_1234",
						CertificateName:                     "Test Certificate3",
						CertificateStatus:                   "READY_FOR_USE",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2025-10-05T11:30:45.654321Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
						CSRPEM:                              nil,
						KeySize:                             "2048",
						KeyType:                             "RSA",
						SANs:                                []string{"test3-example.com", "www.test3-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             nil,
						SignedCertificateNotValidAfterDate:  nil,
						SignedCertificateNotValidBeforeDate: nil,
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName: ptr.To("test3-example.com"),
							Country:    ptr.To("US"),
							Locality:   ptr.To("San Francisco"),
							State:      ptr.To("California"),
						},
						TrustChainPEM: nil,
					},
				},
				Links: Links{
					Self:     "/ccm/v1/certificates?page=1&pageSize=10",
					Next:     nil,
					Previous: nil,
				},
				Metadata: ListMetadata{
					TotalItems: 3,
					TotalPages: 1,
				},
			},
			responseStatus: 200,
			responseBody: `
			{
				"certificates": [
					{
						"accountId": "test-account-id",
						"certificateId": "cert1_1234",
						"certificateName": "Test Certificate1",
						"certificateStatus": "ACTIVE",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2025-08-22T09:01:32.607357Z",
						"csrExpirationDate": "2026-10-24T09:01:34Z",
						"csrPem": null,
						"keySize": "2048",
						"keyType": "RSA",
						"sans": [
							"test-example.com",
							"www.test-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": null,
						"signedCertificateNotValidAfterDate": "2027-11-22T12:11:31Z",
						"signedCertificateNotValidBeforeDate": "2025-08-22T11:11:31Z",
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test-example.com",
							"country": "US",
							"locality": "Cambridge",
							"state": "Massachusetts"
						},
						"trustChainPem": null
					},
					{
						"accountId": "test-account-id",
						"certificateId": "cert3_1234",
						"certificateName": "Test Certificate3",
						"certificateStatus": "READY_FOR_USE",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2025-10-05T11:30:45.654321Z",
						"csrExpirationDate": "2026-10-24T09:01:34Z",
						"csrPem": null,
						"keySize": "2048",
						"keyType": "RSA",
						"sans": [
							"test3-example.com",
							"www.test3-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": null,
						"signedCertificateNotValidAfterDate": null,
						"signedCertificateNotValidBeforeDate": null,
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test3-example.com",
							"country": "US",
							"locality": "San Francisco",
							"state": "California"
						},
						"trustChainPem": null
					}
				],
				"links": {
					"self": "/ccm/v1/certificates?page=1&pageSize=10",
					"next": null,
					"previous": null
				},
				"metadata": {
					"totalItems": 3,
					"totalPages": 1
				}
			}`,
			expectedPath: "/ccm/v1/certificates?certificateStatus=ACTIVE%2CREADY_FOR_USE",
		},
		"200 OK - with certificate name filtering": {
			params: ListCertificatesRequest{
				CertificateName: "Test Certificate1",
			},
			expectedResponse: &ListCertificatesResponse{
				Certificates: []Certificate{
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert1_1234",
						CertificateName:                     "Test Certificate1",
						CertificateStatus:                   "ACTIVE",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
						CSRPEM:                              nil,
						KeySize:                             "2048",
						KeyType:                             "RSA",
						SANs:                                []string{"test-example.com", "www.test-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             nil,
						SignedCertificateNotValidAfterDate:  ptr.To(test.NewTimeFromString(t, "2027-11-22T12:11:31Z")),
						SignedCertificateNotValidBeforeDate: ptr.To(test.NewTimeFromString(t, "2025-08-22T11:11:31Z")),
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName: ptr.To("test-example.com"),
							Country:    ptr.To("US"),
							Locality:   ptr.To("Cambridge"),
							State:      ptr.To("Massachusetts"),
						},
						TrustChainPEM: nil,
					},
				},
				Links: Links{
					Self:     "/ccm/v1/certificates?page=1&pageSize=10",
					Next:     nil,
					Previous: nil,
				},
				Metadata: ListMetadata{
					TotalItems: 1,
					TotalPages: 1,
				},
			},
			responseStatus: 200,
			responseBody: `
			{
				"certificates": [
					{
						"accountId": "test-account-id",
						"certificateId": "cert1_1234",
						"certificateName": "Test Certificate1",
						"certificateStatus": "ACTIVE",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2025-08-22T09:01:32.607357Z",
						"csrExpirationDate": "2026-10-24T09:01:34Z",
						"csrPem": null,
						"keySize": "2048",
						"keyType": "RSA",
						"sans": [
							"test-example.com",
							"www.test-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": null,
						"signedCertificateNotValidAfterDate": "2027-11-22T12:11:31Z",
						"signedCertificateNotValidBeforeDate": "2025-08-22T11:11:31Z",
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test-example.com",
							"country": "US",
							"locality": "Cambridge",
							"state": "Massachusetts"
						},
						"trustChainPem": null
					}
				],
				"links": {
					"self": "/ccm/v1/certificates?page=1&pageSize=10",
					"next": null,
					"previous": null
				},
				"metadata": {
					"totalItems": 1,
					"totalPages": 1
				}
			}`,
			expectedPath: "/ccm/v1/certificates?certificateName=Test+Certificate1",
		},
		"200 OK - with includeCertificateMaterials set to true and issuer filtering": {
			params: ListCertificatesRequest{
				IncludeCertificateMaterials: true,
				Issuer:                      "test organization",
			},
			expectedResponse: &ListCertificatesResponse{
				Certificates: []Certificate{
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert2_1234",
						CertificateName:                     "Test Certificate2",
						CertificateStatus:                   "CSR_READY",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2025-09-15T10:20:30.123456Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
						CSRPEM:                              nil,
						KeySize:                             "P-256",
						KeyType:                             "ECDSA",
						SANs:                                []string{"test2-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             ptr.To("O=test organization NY,L=New York,ST=NY,C=US"),
						SignedCertificateNotValidAfterDate:  ptr.To(test.NewTimeFromString(t, "2027-11-22T12:11:31Z")),
						SignedCertificateNotValidBeforeDate: ptr.To(test.NewTimeFromString(t, "2025-08-22T11:11:31Z")),
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName:   ptr.To("test2-example.com"),
							Country:      ptr.To("US"),
							Locality:     ptr.To("New York"),
							Organization: ptr.To("test organization NY"),
							State:        ptr.To("New York"),
						},
						TrustChainPEM: ptr.To("-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"),
					},
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert4_1234",
						CertificateName:                     "Test Certificate4",
						CertificateStatus:                   "READY_FOR_USE",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2023-10-05T11:30:45.654321Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2024-10-24T09:01:34Z"),
						CSRPEM:                              ptr.To("-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n"),
						KeySize:                             "P-256",
						KeyType:                             "ECDSA",
						SANs:                                []string{"test4-example.com", "www.test4-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             ptr.To("O=test organization LA,L=Los Angeles,ST=California,C=US"),
						SignedCertificateNotValidAfterDate:  nil,
						SignedCertificateNotValidBeforeDate: nil,
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName:   ptr.To("test4-example.com"),
							Country:      ptr.To("US"),
							Locality:     ptr.To("Los Angeles"),
							Organization: ptr.To("test organization LA"),
							State:        ptr.To("California"),
						},
						TrustChainPEM: nil,
					},
				},
				Links: Links{
					Self:     "/ccm/v1/certificates?page=1&pageSize=10",
					Next:     nil,
					Previous: nil,
				},
				Metadata: ListMetadata{
					TotalItems: 3,
					TotalPages: 1,
				},
			},
			responseStatus: 200,
			responseBody: `
			{
				"certificates": [
					{
						"accountId": "test-account-id",	
						"certificateId": "cert2_1234",
						"certificateName": "Test Certificate2",
						"certificateStatus": "CSR_READY",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2025-09-15T10:20:30.123456Z",
						"csrExpirationDate": "2026-10-24T09:01:34Z",
						"csrPem": null,
						"keySize": "P-256",
						"keyType": "ECDSA",
						"sans": [
							"test2-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": "O=test organization NY,L=New York,ST=NY,C=US",
						"signedCertificateNotValidAfterDate": "2027-11-22T12:11:31Z",
						"signedCertificateNotValidBeforeDate": "2025-08-22T11:11:31Z",
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test2-example.com",
							"country": "US",
							"locality": "New York",
							"organization": "test organization NY",
							"state": "New York"
						},
						"trustChainPem": "-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"
					},
					{
						"accountId": "test-account-id",
						"certificateId": "cert4_1234",
						"certificateName": "Test Certificate4",
						"certificateStatus": "READY_FOR_USE",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2023-10-05T11:30:45.654321Z",
						"csrExpirationDate": "2024-10-24T09:01:34Z",
						"csrPem": "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
						"keySize": "P-256",
						"keyType": "ECDSA",
						"sans": [
							"test4-example.com",
							"www.test4-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": "O=test organization LA,L=Los Angeles,ST=California,C=US",
						"signedCertificateNotValidAfterDate": null,
						"signedCertificateNotValidBeforeDate": null,
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test4-example.com",
							"country": "US",
							"locality": "Los Angeles",
							"organization": "test organization LA",
							"state": "California"
						},
						"trustChainPem": null
					}
				],
				"links": {
					"self": "/ccm/v1/certificates?page=1&pageSize=10",
					"next": null,
					"previous": null
				},
				"metadata": {
					"totalItems": 3,
					"totalPages": 1
				}
			}`,
			expectedPath: "/ccm/v1/certificates?includeCertificateMaterials=true&issuer=test+organization",
		},
		"200 OK - with expiringInDays set to less than 0 to find and return expired certificates": {
			params: ListCertificatesRequest{
				ExpiringInDays: ptr.To(int64(-1)),
			},
			expectedResponse: &ListCertificatesResponse{
				Certificates: []Certificate{
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert4_1234",
						CertificateName:                     "Test Certificate4",
						CertificateStatus:                   "READY_FOR_USE",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2023-10-05T11:30:45.654321Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2024-10-24T09:01:34Z"),
						CSRPEM:                              ptr.To("-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n"),
						KeySize:                             "P-256",
						KeyType:                             "ECDSA",
						SANs:                                []string{"test4-example.com", "www.test4-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             ptr.To("O=test organization LA,L=Los Angeles,ST=California,C=US"),
						SignedCertificateNotValidAfterDate:  nil,
						SignedCertificateNotValidBeforeDate: nil,
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName:   ptr.To("test4-example.com"),
							Country:      ptr.To("US"),
							Locality:     ptr.To("Los Angeles"),
							Organization: ptr.To("test organization LA"),
							State:        ptr.To("California"),
						},
						TrustChainPEM: nil,
					},
				},
				Links: Links{
					Self:     "/ccm/v1/certificates?page=1&pageSize=10",
					Next:     nil,
					Previous: nil,
				},
				Metadata: ListMetadata{
					TotalItems: 1,
					TotalPages: 1,
				},
			},
			responseStatus: 200,
			responseBody: `
			{
				"certificates": [
					{
						"accountId": "test-account-id",
						"certificateId": "cert4_1234",
						"certificateName": "Test Certificate4",
						"certificateStatus": "READY_FOR_USE",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2023-10-05T11:30:45.654321Z",
						"csrExpirationDate": "2024-10-24T09:01:34Z",
						"csrPem": "-----BEGIN CERTIFICATE REQUEST-----\nexample-PEM\n-----END CERTIFICATE REQUEST-----\n",
						"keySize": "P-256",
						"keyType": "ECDSA",
						"sans": [
							"test4-example.com",
							"www.test4-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": "O=test organization LA,L=Los Angeles,ST=California,C=US",
						"signedCertificateNotValidAfterDate": null,
						"signedCertificateNotValidBeforeDate": null,
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test4-example.com",
							"country": "US",
							"locality": "Los Angeles",
							"organization": "test organization LA",
							"state": "California"
						},
						"trustChainPem": null
					}
				],
				"links": {
					"self": "/ccm/v1/certificates?page=1&pageSize=10",
					"next": null,
					"previous": null
				},
				"metadata": {
					"totalItems": 1,
					"totalPages": 1
				}
			}`,
			expectedPath: "/ccm/v1/certificates?expiringInDays=-1",
		},
		"200 OK - with pagination and sorting by certificate name": {
			params: ListCertificatesRequest{
				PageSize: 2,
				Page:     2,
				Sort:     "-certificateName",
			},
			expectedResponse: &ListCertificatesResponse{
				Certificates: []Certificate{
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert2_1234",
						CertificateName:                     "Test Certificate2",
						CertificateStatus:                   "CSR_READY",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2025-09-15T10:20:30.123456Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
						CSRPEM:                              nil,
						KeySize:                             "P-256",
						KeyType:                             "ECDSA",
						SANs:                                []string{"test2-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             ptr.To("O=test organization,L=New York,ST=NY,C=US"),
						SignedCertificateNotValidAfterDate:  ptr.To(test.NewTimeFromString(t, "2027-11-22T12:11:31Z")),
						SignedCertificateNotValidBeforeDate: ptr.To(test.NewTimeFromString(t, "2025-08-22T11:11:31Z")),
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName:   ptr.To("test2-example.com"),
							Country:      ptr.To("US"),
							Locality:     ptr.To("New York"),
							Organization: ptr.To("test organization"),
							State:        ptr.To("New York"),
						},
						TrustChainPEM: ptr.To("-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"),
					},
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert1_1234",
						CertificateName:                     "Test Certificate1",
						CertificateStatus:                   "ACTIVE",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
						CSRPEM:                              nil,
						KeySize:                             "2048",
						KeyType:                             "RSA",
						SANs:                                []string{"test-example.com", "www.test-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             nil,
						SignedCertificateNotValidAfterDate:  ptr.To(test.NewTimeFromString(t, "2027-11-22T12:11:31Z")),
						SignedCertificateNotValidBeforeDate: ptr.To(test.NewTimeFromString(t, "2025-08-22T11:11:31Z")),
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName: ptr.To("test-example.com"),
							Country:    ptr.To("US"),
							Locality:   ptr.To("Cambridge"),
							State:      ptr.To("Massachusetts"),
						},
						TrustChainPEM: nil,
					},
				},
				Links: Links{
					Self:     "/ccm/v1/certificates?sort=-certificateName&page=2&pageSize=2",
					Next:     nil,
					Previous: ptr.To("/ccm/v1/certificates?sort=-certificateName&page=1&pageSize=2"),
				},
				Metadata: ListMetadata{
					TotalItems: 4,
					TotalPages: 2,
				},
			},
			responseStatus: 200,
			responseBody: `
			{
				"certificates": [
					{
						"accountId": "test-account-id",
						"certificateId": "cert2_1234",
						"certificateName": "Test Certificate2",
						"certificateStatus": "CSR_READY",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2025-09-15T10:20:30.123456Z",
						"csrExpirationDate": "2026-10-24T09:01:34Z",
						"csrPem": null,
						"keySize": "P-256",
						"keyType": "ECDSA",
						"sans": [
							"test2-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": "O=test organization,L=New York,ST=NY,C=US",
						"signedCertificateNotValidAfterDate": "2027-11-22T12:11:31Z",
						"signedCertificateNotValidBeforeDate": "2025-08-22T11:11:31Z",
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test2-example.com",
							"country": "US",
							"locality": "New York",
							"organization": "test organization",
							"state": "New York"
						},
						"trustChainPem": "-----BEGIN CERTIFICATE-----\nexample-trust-chain-PEM\n-----END CERTIFICATE-----\n"
					},
					{
						"accountId": "test-account-id",
						"certificateId": "cert1_1234",
						"certificateName": "Test Certificate1",
						"certificateStatus": "ACTIVE",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2025-08-22T09:01:32.607357Z",
						"csrExpirationDate": "2026-10-24T09:01:34Z",
						"csrPem": null,
						"keySize": "2048",
						"keyType": "RSA",
						"sans": [
							"test-example.com",
							"www.test-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": null,
						"signedCertificateNotValidAfterDate": "2027-11-22T12:11:31Z",
						"signedCertificateNotValidBeforeDate": "2025-08-22T11:11:31Z",
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test-example.com",
							"country": "US",
							"locality": "Cambridge",
							"state": "Massachusetts"
						},
						"trustChainPem": null
					}
				],
				"links": {
					"self": "/ccm/v1/certificates?sort=-certificateName&page=2&pageSize=2",
					"next": null,
					"previous": "/ccm/v1/certificates?sort=-certificateName&page=1&pageSize=2"
				},
				"metadata": {
					"totalItems": 4,
					"totalPages": 2
				}
			}`,
			expectedPath: "/ccm/v1/certificates?page=2&pageSize=2&sort=-certificateName",
		},
		"200 OK - with pagination and keyType filtering": {
			params: ListCertificatesRequest{
				KeyType:  CryptographicAlgorithmRSA,
				PageSize: 1,
				Page:     1,
			},
			expectedResponse: &ListCertificatesResponse{
				Certificates: []Certificate{
					{
						AccountID:                           "test-account-id",
						CertificateID:                       "cert1_1234",
						CertificateName:                     "Test Certificate1",
						CertificateStatus:                   "ACTIVE",
						CertificateType:                     "THIRD_PARTY",
						CreatedBy:                           "jkowalski",
						CreatedDate:                         test.NewTimeFromString(t, "2025-08-22T09:01:32.607357Z"),
						CSRExpirationDate:                   test.NewTimeFromString(t, "2026-10-24T09:01:34Z"),
						CSRPEM:                              nil,
						KeySize:                             "2048",
						KeyType:                             "RSA",
						SANs:                                []string{"test-example.com", "www.test-example.com"},
						SecureNetwork:                       "ENHANCED_TLS",
						SignedCertificateIssuer:             nil,
						SignedCertificateNotValidAfterDate:  ptr.To(test.NewTimeFromString(t, "2027-11-22T12:11:31Z")),
						SignedCertificateNotValidBeforeDate: ptr.To(test.NewTimeFromString(t, "2025-08-22T11:11:31Z")),
						SignedCertificatePEM:                nil,
						SignedCertificateSHA256Fingerprint:  nil,
						SignedCertificateSerialNumber:       nil,
						Subject: &Subject{
							CommonName: ptr.To("test-example.com"),
							Country:    ptr.To("US"),
							Locality:   ptr.To("Cambridge"),
							State:      ptr.To("Massachusetts"),
						},
						TrustChainPEM: nil,
					},
				},
				Links: Links{
					Self:     "/ccm/v1/certificates?keyType=RSA&page=1&pageSize=1",
					Next:     ptr.To("/ccm/v1/certificates?keyType=RSA&page=2&pageSize=1"),
					Previous: nil,
				},
				Metadata: ListMetadata{
					TotalItems: 2,
					TotalPages: 2,
				},
			},
			responseStatus: 200,
			responseBody: `
			{
				"certificates": [
					{
						"accountId": "test-account-id",
						"certificateId": "cert1_1234",
						"certificateName": "Test Certificate1",
						"certificateStatus": "ACTIVE",
						"certificateType": "THIRD_PARTY",
						"createdBy": "jkowalski",
						"createdDate": "2025-08-22T09:01:32.607357Z",
						"csrExpirationDate": "2026-10-24T09:01:34Z",
						"csrPem": null,
						"keySize": "2048",
						"keyType": "RSA",
						"sans": [
							"test-example.com",
							"www.test-example.com"
						],
						"secureNetwork": "ENHANCED_TLS",
						"signedCertificateIssuer": null,
						"signedCertificateNotValidAfterDate": "2027-11-22T12:11:31Z",
						"signedCertificateNotValidBeforeDate": "2025-08-22T11:11:31Z",
						"signedCertificatePem": null,
						"signedCertificateSha256Fingerprint": null,
						"signedCertificateSerialNumber": null,
						"subject": {
							"commonName": "test-example.com",
							"country": "US",
							"locality": "Cambridge",
							"state": "Massachusetts"
						},
						"trustChainPem": null
					}
				],
				"links": {
					"self": "/ccm/v1/certificates?keyType=RSA&page=1&pageSize=1",
					"next": "/ccm/v1/certificates?keyType=RSA&page=2&pageSize=1",
					"previous": null
				},
				"metadata": {
					"totalItems": 2,
					"totalPages": 2
				}
			}`,
			expectedPath: "/ccm/v1/certificates?keyType=RSA&page=1&pageSize=1",
		},
		"validation error - invalid certificate status": {
			params: ListCertificatesRequest{
				CertificateStatus: []CertificateStatus{"INVALID_STATUS"},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "listing certificates: struct validation: CertificateStatus: list '[INVALID_STATUS]' contains invalid element 'INVALID_STATUS'. "+
					"Each element must be one of: 'ACTIVE', 'READY_FOR_USE', 'CSR_READY'", err.Error())
				assert.ErrorIs(t, err, ErrListCertificates)
				assert.ErrorIs(t, err, ErrStructValidation)
			},
		},
		"validation error - invalid key type": {
			params: ListCertificatesRequest{
				KeyType: "INVALID_KEY",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "listing certificates: struct validation: KeyType: value 'INVALID_KEY' is invalid. Must be either 'RSA' or 'ECDSA'", err.Error())
				assert.ErrorIs(t, err, ErrListCertificates)
				assert.ErrorIs(t, err, ErrStructValidation)
			},
		},
		"validation error - page size less than 1": {
			params: ListCertificatesRequest{
				PageSize: -1,
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "listing certificates: struct validation: PageSize: must be 1 or greater", err.Error())
				assert.ErrorIs(t, err, ErrListCertificates)
				assert.ErrorIs(t, err, ErrStructValidation)
			},
		},
		"validation error - page size greater than 100": {
			params: ListCertificatesRequest{
				PageSize: 101,
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "listing certificates: struct validation: PageSize: cannot be greater than 100", err.Error())
				assert.ErrorIs(t, err, ErrListCertificates)
				assert.ErrorIs(t, err, ErrStructValidation)
			},
		},
		"validation error - page value less than 1": {
			params: ListCertificatesRequest{
				Page: -1,
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "listing certificates: struct validation: Page: must be 1 or greater", err.Error())
				assert.ErrorIs(t, err, ErrListCertificates)
				assert.ErrorIs(t, err, ErrStructValidation)
			},
		},
		"validation error - invalid field for sort": {
			params: ListCertificatesRequest{
				Sort: "invalid_sort",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "listing certificates: struct validation: Sort: must be a comma-separated list of fields, optionally prefixed by + or - (e.g. +createdDate,-certificateName)", err.Error())
				assert.ErrorIs(t, err, ErrListCertificates)
				assert.ErrorIs(t, err, ErrStructValidation)
			},
		},
		"validation error - invalid prefix for sort": {
			params: ListCertificatesRequest{
				Sort: "*createdDate",
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "listing certificates: struct validation: Sort: must be a comma-separated list of fields, optionally prefixed by + or - (e.g. +createdDate,-certificateName)", err.Error())
				assert.ErrorIs(t, err, ErrListCertificates)
				assert.ErrorIs(t, err, ErrStructValidation)
			},
		},
		"500 internal server error - assert that error is ErrListCertificates": {
			params:         ListCertificatesRequest{},
			responseStatus: 500,
			responseBody: `
			{
				"type": "internal_error",
				"title": "Internal Server Error",
				"detail": "Error retrieving certificates",
				"status": 500
			}`,
			expectedPath: "/ccm/v1/certificates",
			withError: func(t *testing.T, err error) {
				want := fmt.Errorf("%w: %w", ErrListCertificates, &Error{
					Type:   "internal_error",
					Title:  "Internal Server Error",
					Detail: "Error retrieving certificates",
					Status: http.StatusInternalServerError,
				})
				assert.EqualError(t, err, want.Error(), "want: %s; got: %s", want, err)
				assert.ErrorIs(t, err, ErrListCertificates)
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tc.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodGet, r.Method)
				w.WriteHeader(tc.responseStatus)
				_, err := w.Write([]byte(tc.responseBody))
				assert.NoError(t, err)
			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.ListCertificates(context.Background(), tc.params)

			if tc.withError != nil {
				tc.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedResponse, result)
		})
	}
}

func TestSortValidationRule(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		sortValue string
		hasError  bool
	}{
		"valid sort value - single field, ascending": {
			sortValue: "+modifiedDate",
			hasError:  false,
		},
		"valid sort value - single field, descending": {
			sortValue: "-certificateName",
			hasError:  false,
		},
		"valid sort value - single field, without prefix": {
			sortValue: "modifiedDate",
			hasError:  false,
		},
		"valid sort value - multiple fields, mixed order": {
			sortValue: "+certificateName,-expirationDate,-createdDate",
			hasError:  false,
		},
		"valid sort value - empty string": {
			sortValue: "",
			hasError:  true,
		},
		"invalid sort value - invalid field": {
			sortValue: "invalidField",
			hasError:  true,
		},
		"invalid sort value - invalid prefix": {
			sortValue: "*createdDate",
			hasError:  true,
		},
		"invalid sort value - invalid separator": {
			sortValue: "+createdDate|-certificateName",
			hasError:  true,
		},
		"invalid sort value - multiple fields, mixed order": {
			sortValue: "+certificateName,-modifiedBy,-createdDate",
			hasError:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := sortValidationRule(tc.sortValue)
			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
