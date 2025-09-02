package ccm

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/edgegrid"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockAPIClient(t *testing.T, mockServer *httptest.Server) CCM {
	serverURL, err := url.Parse(mockServer.URL)
	require.NoError(t, err)
	certPool := x509.NewCertPool()
	certPool.AddCert(mockServer.Certificate())
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}
	s, err := session.New(session.WithClient(httpClient), session.WithSigner(&edgegrid.Config{Host: serverURL.Host}))
	assert.NoError(t, err)
	return Client(s)
}

func TestClient(t *testing.T) {
	t.Parallel()
	sess, err := session.New()
	require.NoError(t, err)
	tests := map[string]struct {
		options  []Option
		expected *ccm
	}{
		"no options provided, return default": {
			options: nil,
			expected: &ccm{
				Session: sess,
			},
		},
		"option provided, overwrite session": {
			options: []Option{func(c *ccm) {
				c.Session = nil
			}},
			expected: &ccm{
				Session: nil,
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			res := Client(sess, test.options...)
			assert.Equal(t, res, test.expected)
		})
	}
}
