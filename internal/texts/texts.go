// Package texts provides utility functions for working with text and string-like types.
package texts

import "strings"

// JoinStringBased is a generic version of strings.Join that works with any type based on string.
// It converts the elements to string before joining them with the given separator.
func JoinStringBased[T ~string](elems []T, sep string) string {
	ss := make([]string, len(elems))
	for i, v := range elems {
		ss[i] = string(v)
	}
	return strings.Join(ss, sep)
}
