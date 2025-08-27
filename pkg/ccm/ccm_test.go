package ccm

import (
	"testing"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
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
