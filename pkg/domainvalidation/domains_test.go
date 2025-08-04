package domainvalidation

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/internal/test"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/ptr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListDomains(t *testing.T) {
	tests := map[string]struct {
		params           ListDomainsRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *ListDomainsResponse
		withError        func(*testing.T, error)
	}{
		"200 OK - no arguments, multiple various results": {
			params:         ListDomainsRequest{},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "metadata": {
        "hasPrevious": false,
        "hasNext": true,
        "page": 1,
        "pageSize": 10,
        "totalItems": 11
    },
    "domains": [
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom1.test",
            "validationScope": "HOST",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:27:19Z",
            "validationChallenge": {
                "dnsCname": "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
                "challengeToken": "t0ken1",
                "challengeTokenExpiresDate": "2025-08-05T13:27:19Z",
                "httpRedirectFrom": "https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1",
                "httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"
            }
        },
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom2.test",
            "validationScope": "HOST",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:26:58Z",
            "validationChallenge": {
                "dnsCname": "ac.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.dom2.test.validate-akdv.net",
                "challengeToken": "t0ken2",
                "challengeTokenExpiresDate": "2025-08-05T13:26:58Z",
                "httpRedirectFrom": "https://dom2.test/.well-known/akamai/akamai-challenge/r4dirFrom2",
                "httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken2"
            }
        },
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom3.test",
            "validationScope": "HOST",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:26:50Z",
            "validationChallenge": {
                "dnsCname": "ac.abababababababababababababababab.dom3.test.validate-akdv.net",
                "challengeToken": "t0ken3",
                "challengeTokenExpiresDate": "2025-08-05T13:26:50Z",
                "httpRedirectFrom": "https://dom3.test/.well-known/akamai/akamai-challenge/r4dirFrom3",
                "httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken3"
            }
        },
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom4.test",
            "validationScope": "HOST",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:26:50Z",
            "validationChallenge": {
                "dnsCname": "ac.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.dom4.test.validate-akdv.net",
                "challengeToken": "t0ken4",
                "challengeTokenExpiresDate": "2025-08-05T13:26:50Z",
                "httpRedirectFrom": "https://dom4.test/.well-known/akamai/akamai-challenge/r4dirFrom4",
                "httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken4"
            }
        },
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom5.test",
            "validationScope": "HOST",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:26:50Z",
            "validationChallenge": {
                "dnsCname": "ac.abababababababababababababababab.dom5.test.validate-akdv.net",
                "challengeToken": "t0ken5",
                "challengeTokenExpiresDate": "2025-08-05T13:26:50Z",
                "httpRedirectFrom": "https://dom5.test/.well-known/akamai/akamai-challenge/r4dirFrom5",
                "httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken5"
            }
        },
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom6.test",
            "validationScope": "WILDCARD",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:26:50Z",
            "validationChallenge": {
                "dnsCname": "ac.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.dom6.test.validate-akdv.net",
                "challengeToken": "t0ken6",
                "challengeTokenExpiresDate": "2025-08-05T13:26:50Z"
            }
        },
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom7.test",
            "validationScope": "DOMAIN",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:26:50Z",
            "validationChallenge": {
                "dnsCname": "ac.abababababababababababababababab.dom7.test.validate-akdv.net",
                "challengeToken": "t0ken7",
                "challengeTokenExpiresDate": "2025-08-05T13:26:50Z"
            }
        },
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom8.test",
            "validationScope": "HOST",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:26:29Z",
            "validationChallenge": {
                "dnsCname": "ac.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.dom8.test.validate-akdv.net",
                "challengeToken": "t0ken8",
                "challengeTokenExpiresDate": "2025-08-05T13:26:29Z",
                "httpRedirectFrom": "https://dom8.test/.well-known/akamai/akamai-challenge/r4dirFrom8",
                "httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken8"
            }
        },
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom9.test",
            "validationScope": "HOST",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:26:29Z",
            "validationChallenge": {
                "dnsCname": "ac.abababababababababababababababab.dom9.test.validate-akdv.net",
                "challengeToken": "t0ken9",
                "challengeTokenExpiresDate": "2025-08-05T13:26:29Z",
                "httpRedirectFrom": "https://dom9.test/.well-known/akamai/akamai-challenge/r4dirFrom9",
                "httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken9"
            }
        },
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom10.test",
            "validationScope": "DOMAIN",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:26:29Z",
            "validationChallenge": {
                "dnsCname": "ac.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.dom10.test.validate-akdv.net",
                "challengeToken": "t0ken10",
                "challengeTokenExpiresDate": "2025-08-05T13:26:29Z"
            }
        }
    ],
    "links": [
        {
            "rel": "self",
            "href": "/domain-validation-service/api/v1/domains?page=1&pageSize=10"
        },
        {
            "rel": "next",
            "href": "/domain-validation-service/api/v1/domains?page=2&pageSize=10"
        }
    ]
}`,
			expectedPath: "/domain-validation/v1/domains",
			expectedResponse: &ListDomainsResponse{
				Metadata: Metadata{
					HasPrevious: false,
					HasNext:     true,
					Page:        1,
					PageSize:    10,
					TotalItems:  11,
				},
				Domains: []DomainItem{
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom1.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:27:19Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
							ChallengeToken:            "t0ken1",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:27:19Z"),
							HTTPRedirectFrom:          ptr.To("https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"),
						},
					},
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom2.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:26:58Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.dom2.test.validate-akdv.net",
							ChallengeToken:            "t0ken2",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:26:58Z"),
							HTTPRedirectFrom:          ptr.To("https://dom2.test/.well-known/akamai/akamai-challenge/r4dirFrom2"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken2"),
						},
					},
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom3.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:26:50Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.abababababababababababababababab.dom3.test.validate-akdv.net",
							ChallengeToken:            "t0ken3",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:26:50Z"),
							HTTPRedirectFrom:          ptr.To("https://dom3.test/.well-known/akamai/akamai-challenge/r4dirFrom3"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken3"),
						},
					},
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom4.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:26:50Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.dom4.test.validate-akdv.net",
							ChallengeToken:            "t0ken4",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:26:50Z"),
							HTTPRedirectFrom:          ptr.To("https://dom4.test/.well-known/akamai/akamai-challenge/r4dirFrom4"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken4"),
						},
					},
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom5.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:26:50Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.abababababababababababababababab.dom5.test.validate-akdv.net",
							ChallengeToken:            "t0ken5",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:26:50Z"),
							HTTPRedirectFrom:          ptr.To("https://dom5.test/.well-known/akamai/akamai-challenge/r4dirFrom5"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken5"),
						},
					},
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom6.test",
						ValidationScope:         "WILDCARD",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:26:50Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.dom6.test.validate-akdv.net",
							ChallengeToken:            "t0ken6",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:26:50Z"),
						},
					},
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom7.test",
						ValidationScope:         "DOMAIN",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:26:50Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.abababababababababababababababab.dom7.test.validate-akdv.net",
							ChallengeToken:            "t0ken7",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:26:50Z"),
						},
					},
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom8.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:26:29Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.dom8.test.validate-akdv.net",
							ChallengeToken:            "t0ken8",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:26:29Z"),
							HTTPRedirectFrom:          ptr.To("https://dom8.test/.well-known/akamai/akamai-challenge/r4dirFrom8"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken8"),
						},
					},
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom9.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:26:29Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.abababababababababababababababab.dom9.test.validate-akdv.net",
							ChallengeToken:            "t0ken9",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:26:29Z"),
							HTTPRedirectFrom:          ptr.To("https://dom9.test/.well-known/akamai/akamai-challenge/r4dirFrom9"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken9"),
						},
					},
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom10.test",
						ValidationScope:         "DOMAIN",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:26:29Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.dom10.test.validate-akdv.net",
							ChallengeToken:            "t0ken10",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:26:29Z"),
						},
					},
				},
				Links: []Link{
					{
						Rel:  "self",
						Href: "/domain-validation-service/api/v1/domains?page=1&pageSize=10",
					},
					{
						Rel:  "next",
						Href: "/domain-validation-service/api/v1/domains?page=2&pageSize=10",
					},
				},
			},
		},
		"200 OK - explicit page and pageSize": {
			params:         ListDomainsRequest{Page: ptr.To(int64(1)), PageSize: ptr.To(int64(10))},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "metadata": {
        "hasPrevious": false,
        "hasNext": false,
        "page": 1,
        "pageSize": 10,
        "totalItems": 1
    },
    "domains": [
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom1.test",
            "validationScope": "HOST",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:27:19Z",
            "validationChallenge": {
                "dnsCname": "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
                "challengeToken": "t0ken1",
                "challengeTokenExpiresDate": "2025-08-05T13:27:19Z",
                "httpRedirectFrom": "https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1",
                "httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"
            }
        }
    ],
    "links": [
        {
            "rel": "self",
            "href": "/domain-validation-service/api/v1/domains?page=1&pageSize=10"
        }
    ]
}`,
			expectedPath: "/domain-validation/v1/domains?page=1&pageSize=10",
			expectedResponse: &ListDomainsResponse{
				Metadata: Metadata{
					HasPrevious: false,
					HasNext:     false,
					Page:        1,
					PageSize:    10,
					TotalItems:  1,
				},
				Domains: []DomainItem{
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom1.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:27:19Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
							ChallengeToken:            "t0ken1",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:27:19Z"),
							HTTPRedirectFrom:          ptr.To("https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"),
						},
					},
				},
				Links: []Link{
					{
						Rel:  "self",
						Href: "/domain-validation-service/api/v1/domains?page=1&pageSize=10",
					},
				},
			},
		},
		"200 OK - explicit paginate, page and pageSize": {
			params: ListDomainsRequest{
				Paginate: ptr.To(true),
				Page:     ptr.To(int64(1)),
				PageSize: ptr.To(int64(10)),
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "metadata": {
        "hasPrevious": false,
        "hasNext": false,
        "page": 1,
        "pageSize": 10,
        "totalItems": 1
    },
    "domains": [
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom1.test",
            "validationScope": "HOST",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:27:19Z",
            "validationChallenge": {
                "dnsCname": "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
                "challengeToken": "t0ken1",
                "challengeTokenExpiresDate": "2025-08-05T13:27:19Z",
                "httpRedirectFrom": "https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1",
                "httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"
            }
        }
    ],
    "links": [
        {
            "rel": "self",
            "href": "/domain-validation-service/api/v1/domains?page=1&pageSize=10"
        }
    ]
}`,
			expectedPath: "/domain-validation/v1/domains?page=1&pageSize=10&paginate=true",
			expectedResponse: &ListDomainsResponse{
				Metadata: Metadata{
					HasPrevious: false,
					HasNext:     false,
					Page:        1,
					PageSize:    10,
					TotalItems:  1,
				},
				Domains: []DomainItem{
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom1.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:27:19Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
							ChallengeToken:            "t0ken1",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:27:19Z"),
							HTTPRedirectFrom:          ptr.To("https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"),
						},
					},
				},
				Links: []Link{
					{
						Rel:  "self",
						Href: "/domain-validation-service/api/v1/domains?page=1&pageSize=10",
					},
				},
			},
		},
		"200 OK - only paginate": {
			params: ListDomainsRequest{
				Paginate: ptr.To(true),
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "metadata": {
        "hasPrevious": false,
        "hasNext": false,
        "page": 1,
        "pageSize": 10,
        "totalItems": 1
    },
    "domains": [
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom1.test",
            "validationScope": "HOST",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:27:19Z",
            "validationChallenge": {
                "dnsCname": "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
                "challengeToken": "t0ken1",
                "challengeTokenExpiresDate": "2025-08-05T13:27:19Z",
                "httpRedirectFrom": "https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1",
                "httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"
            }
        }
    ],
    "links": [
        {
            "rel": "self",
            "href": "/domain-validation-service/api/v1/domains?page=1&pageSize=10"
        }
    ]
}`,
			expectedPath: "/domain-validation/v1/domains?paginate=true",
			expectedResponse: &ListDomainsResponse{
				Metadata: Metadata{
					HasPrevious: false,
					HasNext:     false,
					Page:        1,
					PageSize:    10,
					TotalItems:  1,
				},
				Domains: []DomainItem{
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom1.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:27:19Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
							ChallengeToken:            "t0ken1",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:27:19Z"),
							HTTPRedirectFrom:          ptr.To("https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"),
						},
					},
				},
				Links: []Link{
					{
						Rel:  "self",
						Href: "/domain-validation-service/api/v1/domains?page=1&pageSize=10",
					},
				},
			},
		},
		"200 OK - only pageSize": {
			params: ListDomainsRequest{
				PageSize: ptr.To(int64(10)),
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "metadata": {
        "hasPrevious": false,
        "hasNext": false,
        "page": 1,
        "pageSize": 10,
        "totalItems": 1
    },
    "domains": [
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom1.test",
            "validationScope": "HOST",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:27:19Z",
            "validationChallenge": {
                "dnsCname": "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
                "challengeToken": "t0ken1",
                "challengeTokenExpiresDate": "2025-08-05T13:27:19Z",
                "httpRedirectFrom": "https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1",
                "httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"
            }
        }
    ],
    "links": [
        {
            "rel": "self",
            "href": "/domain-validation-service/api/v1/domains?page=1&pageSize=10"
        }
    ]
}`,
			expectedPath: "/domain-validation/v1/domains?pageSize=10",
			expectedResponse: &ListDomainsResponse{
				Metadata: Metadata{
					HasPrevious: false,
					HasNext:     false,
					Page:        1,
					PageSize:    10,
					TotalItems:  1,
				},
				Domains: []DomainItem{
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom1.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:27:19Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
							ChallengeToken:            "t0ken1",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:27:19Z"),
							HTTPRedirectFrom:          ptr.To("https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"),
						},
					},
				},
				Links: []Link{
					{
						Rel:  "self",
						Href: "/domain-validation-service/api/v1/domains?page=1&pageSize=10",
					},
				},
			},
		},
		"200 OK - only page": {
			params: ListDomainsRequest{
				Page: ptr.To(int64(1)),
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "metadata": {
        "hasPrevious": false,
        "hasNext": false,
        "page": 1,
        "pageSize": 10,
        "totalItems": 1
    },
    "domains": [
        {
            "accountId": "1-ACCOUN",
            "domainName": "dom1.test",
            "validationScope": "HOST",
            "domainStatus": "REQUEST_ACCEPTED",
            "validationRequestedBy": "someuser",
            "validationRequestedDate": "2025-08-04T13:27:19Z",
            "validationChallenge": {
                "dnsCname": "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
                "challengeToken": "t0ken1",
                "challengeTokenExpiresDate": "2025-08-05T13:27:19Z",
                "httpRedirectFrom": "https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1",
                "httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"
            }
        }
    ],
    "links": [
        {
            "rel": "self",
            "href": "/domain-validation-service/api/v1/domains?page=1&pageSize=10"
        }
    ]
}`,
			expectedPath: "/domain-validation/v1/domains?page=1",
			expectedResponse: &ListDomainsResponse{
				Metadata: Metadata{
					HasPrevious: false,
					HasNext:     false,
					Page:        1,
					PageSize:    10,
					TotalItems:  1,
				},
				Domains: []DomainItem{
					{
						AccountID:               "1-ACCOUN",
						DomainName:              "dom1.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationRequestedBy:   "someuser",
						ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:27:19Z"),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
							ChallengeToken:            "t0ken1",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:27:19Z"),
							HTTPRedirectFrom:          ptr.To("https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"),
						},
					},
				},
				Links: []Link{
					{
						Rel:  "self",
						Href: "/domain-validation-service/api/v1/domains?page=1&pageSize=10",
					},
				},
			},
		},
		"validation - page or pageSize without paging": {
			params: ListDomainsRequest{
				Paginate: ptr.To(false),
				Page:     ptr.To(int64(1)),
				PageSize: ptr.To(int64(10)),
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "list domains: struct validation:\nPage: must be empty when Paginate is false\nPageSize: must be empty when Paginate is false", err.Error())
			},
		},
		"validation - pageSize too small": {
			params: ListDomainsRequest{
				PageSize: ptr.To(int64(1)),
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "list domains: struct validation:\nPageSize: must be no less than 10", err.Error())
			},
		},
		"validation - pageSize too big": {
			params: ListDomainsRequest{
				PageSize: ptr.To(int64(1001)),
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "list domains: struct validation:\nPageSize: must be no greater than 1000", err.Error())
			},
		},
		"500 internal server error": {
			params:         ListDomainsRequest{},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
		{
		   "type": "internal_error",
		   "title": "Internal Server Error",
		   "detail": "Error making request",
		   "status": 500
		}
		`,
			expectedPath: "/domain-validation/v1/domains",
			withError: func(t *testing.T, e error) {
				err := Error{
					Type:   "internal_error",
					Title:  "Internal Server Error",
					Detail: "Error making request",
					Status: http.StatusInternalServerError,
				}
				assert.Equal(t, true, err.Is(e))
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tc.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodGet, r.Method)
				w.WriteHeader(tc.responseStatus)
				_, err := w.Write([]byte(tc.responseBody))
				assert.NoError(t, err)

			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.ListDomains(context.Background(), tc.params)
			if tc.withError != nil {
				tc.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedResponse, result)
		})
	}
}

func TestGetDomain(t *testing.T) {
	tests := map[string]struct {
		params           GetDomainRequest
		responseStatus   int
		responseBody     string
		expectedPath     string
		expectedResponse *GetDomainResponse
		withError        func(*testing.T, error)
	}{
		"200 OK - only required arguments - not validated": {
			params: GetDomainRequest{
				DomainName:      "dom1.test",
				ValidationScope: ValidationScopeHost,
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "accountId": "1-ACCOUN",
	"domainName": "dom1.test",
	"validationScope": "HOST",
	"domainStatus": "REQUEST_ACCEPTED",
	"validationRequestedBy": "someuser",
	"validationRequestedDate": "2025-08-04T13:27:19Z",
	"validationChallenge": {
		"dnsCname": "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
		"challengeToken": "t0ken1",
		"challengeTokenExpiresDate": "2025-08-05T13:27:19Z",
		"httpRedirectFrom": "https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1",
		"httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"
	}
}`,
			expectedPath: "/domain-validation/v1/domains/dom1.test?validationScope=HOST",
			expectedResponse: &GetDomainResponse{
				AccountID:               "1-ACCOUN",
				DomainName:              "dom1.test",
				ValidationScope:         "HOST",
				DomainStatus:            "REQUEST_ACCEPTED",
				ValidationRequestedBy:   "someuser",
				ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:27:19Z"),
				ValidationChallenge: &ValidationChallenge{
					DNSCname:                  "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
					ChallengeToken:            "t0ken1",
					ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:27:19Z"),
					HTTPRedirectFrom:          ptr.To("https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1"),
					HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"),
				},
			},
		},
		"200 OK - only required arguments - not validated and minimal challenges": {
			params: GetDomainRequest{
				DomainName:      "dom1.test",
				ValidationScope: ValidationScopeHost,
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "accountId": "1-ACCOUN",
	"domainName": "dom1.test",
	"validationScope": "HOST",
	"domainStatus": "REQUEST_ACCEPTED",
	"validationRequestedBy": "someuser",
	"validationRequestedDate": "2025-08-04T13:27:19Z",
	"validationChallenge": {
		"dnsCname": "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
		"challengeToken": "t0ken1",
		"challengeTokenExpiresDate": "2025-08-05T13:27:19Z"
	}
}`,
			expectedPath: "/domain-validation/v1/domains/dom1.test?validationScope=HOST",
			expectedResponse: &GetDomainResponse{
				AccountID:               "1-ACCOUN",
				DomainName:              "dom1.test",
				ValidationScope:         "HOST",
				DomainStatus:            "REQUEST_ACCEPTED",
				ValidationRequestedBy:   "someuser",
				ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:27:19Z"),
				ValidationChallenge: &ValidationChallenge{
					DNSCname:                  "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
					ChallengeToken:            "t0ken1",
					ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:27:19Z"),
				},
			},
		},
		"200 OK - with status history - not validated": {
			params: GetDomainRequest{
				DomainName:                 "dom1.test",
				ValidationScope:            ValidationScopeHost,
				IncludeDomainStatusHistory: true,
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "accountId": "1-ACCOUN",
	"domainName": "dom1.test",
	"validationScope": "HOST",
	"domainStatus": "VALIDATION_IN_PROGRESS",
	"validationRequestedBy": "someuser",
	"validationRequestedDate": "2025-08-04T13:27:19Z",
	"validationChallenge": {
		"dnsCname": "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
		"challengeToken": "t0ken1",
		"challengeTokenExpiresDate": "2025-08-05T13:27:19Z",
		"httpRedirectFrom": "https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1",
		"httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"
	},
	"domainStatusHistory": [
        {
            "domainStatus": "REQUEST_ACCEPTED",
            "modifiedUser": "someuser",
            "modifiedDate": "2025-08-04T11:49:53Z"
        },
        {
            "domainStatus": "VALIDATION_IN_PROGRESS",
            "message": "DNS verification failed.",
            "modifiedUser": "someuser",
            "modifiedDate": "2025-08-04T11:50:53Z"
        }
    ]
}`,
			expectedPath: "/domain-validation/v1/domains/dom1.test?includeDomainStatusHistory=true&validationScope=HOST",
			expectedResponse: &GetDomainResponse{
				AccountID:               "1-ACCOUN",
				DomainName:              "dom1.test",
				ValidationScope:         "HOST",
				DomainStatus:            "VALIDATION_IN_PROGRESS",
				ValidationRequestedBy:   "someuser",
				ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:27:19Z"),
				ValidationChallenge: &ValidationChallenge{
					DNSCname:                  "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
					ChallengeToken:            "t0ken1",
					ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:27:19Z"),
					HTTPRedirectFrom:          ptr.To("https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1"),
					HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"),
				},
				DomainStatusHistory: []DomainStatusHistory{
					{
						DomainStatus: "REQUEST_ACCEPTED",
						ModifiedUser: "someuser",
						ModifiedDate: test.NewTimeFromString(t, "2025-08-04T11:49:53Z"),
					},
					{
						DomainStatus: "VALIDATION_IN_PROGRESS",
						Message:      ptr.To("DNS verification failed."),
						ModifiedUser: "someuser",
						ModifiedDate: test.NewTimeFromString(t, "2025-08-04T11:50:53Z"),
					},
				},
			},
		},
		"200 OK - validated": {
			params: GetDomainRequest{
				DomainName:      "dom1.test",
				ValidationScope: ValidationScopeHost,
			},
			responseStatus: http.StatusOK,
			responseBody: `
{
    "accountId": "1-ACCOUN",
	"domainName": "dom1.test",
	"validationScope": "HOST",
	"domainStatus": "VALIDATED",
	"validationMethod": "SYSTEM",
	"validationRequestedBy": "someuser",
	"validationRequestedDate": "2025-08-04T13:27:19Z",
	"validationCompletedDate": "2025-08-05T11:56:07Z"
}`,
			expectedPath: "/domain-validation/v1/domains/dom1.test?validationScope=HOST",
			expectedResponse: &GetDomainResponse{
				AccountID:               "1-ACCOUN",
				DomainName:              "dom1.test",
				ValidationScope:         "HOST",
				DomainStatus:            "VALIDATED",
				ValidationMethod:        ptr.To("SYSTEM"),
				ValidationRequestedBy:   "someuser",
				ValidationRequestedDate: test.NewTimeFromString(t, "2025-08-04T13:27:19Z"),
				ValidationCompletedDate: ptr.To(test.NewTimeFromString(t, "2025-08-05T11:56:07Z")),
			},
		},
		"validation - no arguments": {
			params: GetDomainRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "get domain: struct validation:\nDomainName: cannot be blank\nValidationScope: cannot be blank", err.Error())
			},
		},
		"validation - incorrect ValidationScope ": {
			params: GetDomainRequest{
				DomainName:      "dom1.test",
				ValidationScope: ValidationScope("incorrect"),
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "get domain: struct validation:\nValidationScope: value 'incorrect' is invalid. Must be one of: 'HOST', 'DOMAIN' or 'WILDCARD'", err.Error())
			},
		},
		"500 internal server error": {
			params: GetDomainRequest{
				DomainName:      "dom1.test",
				ValidationScope: ValidationScopeDomain,
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
		{
		   "type": "internal_error",
		   "title": "Internal Server Error",
		   "detail": "Error making request",
		   "status": 500
		}
		`,
			expectedPath: "/domain-validation/v1/domains/dom1.test?validationScope=DOMAIN",
			withError: func(t *testing.T, e error) {
				err := Error{
					Type:   "internal_error",
					Title:  "Internal Server Error",
					Detail: "Error making request",
					Status: http.StatusInternalServerError,
				}
				assert.Equal(t, true, err.Is(e))
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tc.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodGet, r.Method)
				w.WriteHeader(tc.responseStatus)
				_, err := w.Write([]byte(tc.responseBody))
				assert.NoError(t, err)

			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.GetDomain(context.Background(), tc.params)
			if tc.withError != nil {
				tc.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedResponse, result)
		})
	}
}

func TestSearchDomains(t *testing.T) {
	tests := map[string]struct {
		params              SearchDomainsRequest
		responseStatus      int
		responseBody        string
		expectedPath        string
		expectedRequestBody string
		expectedResponse    *SearchDomainsResponse
		withError           func(*testing.T, error)
	}{
		"200 OK - several different elements in search without details": {
			params: SearchDomainsRequest{
				Body: SearchDomainsBody{Domains: []SearchDomain{
					{
						DomainName:      "dom1.test",
						ValidationScope: ValidationScopeHost,
					},
					{
						DomainName:      "dom2.test",
						ValidationScope: ValidationScopeDomain,
					},
				}},
			},
			expectedRequestBody: `{"domains":[{"domainName":"dom1.test","validationScope":"HOST"},{"domainName":"dom2.test","validationScope":"DOMAIN"}]}`,
			responseStatus:      http.StatusOK,
			responseBody: `
{
	"domains": [
		{
			"domainName": "dom1.test",
			"validationScope": "HOST",
			"domainStatus": "REQUEST_ACCEPTED",
			"validationLevel": "FQDN"
		},
		{
			"domainName": "dom2.test",
			"validationScope": "HOST",
			"domainStatus": "VALIDATED",
			"validationLevel": "FQDN"
		}
	]
}`,
			expectedPath: "/domain-validation/v1/domains/search",
			expectedResponse: &SearchDomainsResponse{
				Domains: []SearchDomainItem{
					{
						DomainName:      "dom1.test",
						ValidationScope: "HOST",
						DomainStatus:    "REQUEST_ACCEPTED",
						ValidationLevel: "FQDN",
					},
					{
						DomainName:      "dom2.test",
						ValidationScope: "HOST",
						DomainStatus:    "VALIDATED",
						ValidationLevel: "FQDN",
					},
				},
			},
		},
		"200 OK - several different elements in search with details": {
			params: SearchDomainsRequest{
				IncludeAll: true,
				Body: SearchDomainsBody{Domains: []SearchDomain{
					{
						DomainName:      "dom1.test",
						ValidationScope: ValidationScopeHost,
					},
					{
						DomainName:      "dom2.test",
						ValidationScope: ValidationScopeDomain,
					},
				}},
			},
			expectedRequestBody: `{"domains":[{"domainName":"dom1.test","validationScope":"HOST"},{"domainName":"dom2.test","validationScope":"DOMAIN"}]}`,
			responseStatus:      http.StatusOK,
			responseBody: `
{
	"domains": [
		{
			"accountId": "1-ACCOUN",
			"domainName": "dom1.test",
			"validationScope": "HOST",
			"domainStatus": "REQUEST_ACCEPTED",
			"validationLevel": "FQDN",
			"validationMethod": "DNS_TXT",
			"validationRequestedBy": "someuser",
			"validationRequestedDate": "2025-08-04T13:27:19Z",
			"validationChallenge": {
				"dnsCname": "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
				"challengeToken": "t0ken1",
				"challengeTokenExpiresDate": "2025-08-05T13:27:19Z",
				"httpRedirectFrom": "https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1",
				"httpRedirectTo": "https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"
			}
		},
		{
			"accountId": "1-ACCOUN",
			"domainName": "dom2.test",
			"validationScope": "HOST",
			"domainStatus": "VALIDATED",
			"validationLevel": "FQDN",
			"validationMethod": "SYSTEM",
			"validationRequestedBy": "someuser",
			"validationRequestedDate": "2025-08-04T13:27:19Z",
			"validationCompletedDate": "2025-08-05T11:56:07Z"
		}
	]
}`,
			expectedPath: "/domain-validation/v1/domains/search?includeAll=true",
			expectedResponse: &SearchDomainsResponse{
				Domains: []SearchDomainItem{
					{
						AccountID:               ptr.To("1-ACCOUN"),
						DomainName:              "dom1.test",
						ValidationScope:         "HOST",
						DomainStatus:            "REQUEST_ACCEPTED",
						ValidationLevel:         "FQDN",
						ValidationMethod:        ptr.To("DNS_TXT"),
						ValidationRequestedBy:   ptr.To("someuser"),
						ValidationRequestedDate: ptr.To(test.NewTimeFromString(t, "2025-08-04T13:27:19Z")),
						ValidationChallenge: &ValidationChallenge{
							DNSCname:                  "ac.abababababababababababababababab.dom1.test.validate-akdv.net",
							ChallengeToken:            "t0ken1",
							ChallengeTokenExpiresDate: test.NewTimeFromString(t, "2025-08-05T13:27:19Z"),
							HTTPRedirectFrom:          ptr.To("https://dom1.test/.well-known/akamai/akamai-challenge/r4dirFrom1"),
							HTTPRedirectTo:            ptr.To("https://validation.akamai.com/.well-known/akamai/akamai-challenge/t0ken1"),
						},
					},
					{
						AccountID:               ptr.To("1-ACCOUN"),
						DomainName:              "dom2.test",
						ValidationScope:         "HOST",
						DomainStatus:            "VALIDATED",
						ValidationLevel:         "FQDN",
						ValidationMethod:        ptr.To("SYSTEM"),
						ValidationRequestedBy:   ptr.To("someuser"),
						ValidationRequestedDate: ptr.To(test.NewTimeFromString(t, "2025-08-04T13:27:19Z")),
						ValidationCompletedDate: ptr.To(test.NewTimeFromString(t, "2025-08-05T11:56:07Z")),
					},
				},
			},
		},
		"validation - no arguments": {
			params: SearchDomainsRequest{},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "search domains: struct validation:\nBody: {\n\tDomains: cannot be blank\n}", err.Error())
			},
		},
		"validation - empty domain": {
			params: SearchDomainsRequest{
				Body: SearchDomainsBody{Domains: []SearchDomain{
					{},
				}},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "search domains: struct validation:\nBody: {\n\tDomains[0]: {\n\t\tDomainName: cannot be blank\n\t\tValidationScope: cannot be blank\n\t}\n}", err.Error())
			},
		},
		"validation - incorrect ValidationScope": {
			params: SearchDomainsRequest{
				Body: SearchDomainsBody{Domains: []SearchDomain{
					{
						DomainName:      "dom1.test",
						ValidationScope: ValidationScope("incorrect"),
					},
				}},
			},
			withError: func(t *testing.T, err error) {
				assert.Equal(t, "search domains: struct validation:\nBody: {\n\tDomains[0]: {\n\t\tValidationScope: value 'incorrect' is invalid. Must be one of: 'HOST', 'DOMAIN' or 'WILDCARD'\n\t}\n}", err.Error())
			},
		},
		"500 internal server error": {
			params: SearchDomainsRequest{
				Body: SearchDomainsBody{
					Domains: []SearchDomain{
						{
							DomainName:      "dom1.test",
							ValidationScope: ValidationScopeDomain,
						},
					},
				},
			},
			responseStatus: http.StatusInternalServerError,
			responseBody: `
		{
		   "type": "internal_error",
		   "title": "Internal Server Error",
		   "detail": "Error making request",
		   "status": 500
		}
		`,
			expectedPath: "/domain-validation/v1/domains/search",
			withError: func(t *testing.T, e error) {
				err := Error{
					Type:   "internal_error",
					Title:  "Internal Server Error",
					Detail: "Error making request",
					Status: http.StatusInternalServerError,
				}
				assert.Equal(t, true, err.Is(e))
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tc.expectedPath, r.URL.String())
				assert.Equal(t, http.MethodPost, r.Method)
				if len(tc.expectedRequestBody) > 0 {
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					assert.Equal(t, tc.expectedRequestBody, string(body))
				}

				w.WriteHeader(tc.responseStatus)
				_, err := w.Write([]byte(tc.responseBody))
				assert.NoError(t, err)

			}))
			client := mockAPIClient(t, mockServer)
			result, err := client.SearchDomains(context.Background(), tc.params)
			if tc.withError != nil {
				tc.withError(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedResponse, result)
		})
	}
}
