//go:build !unix

package kek

import "errors"

// Lock is not available on this platform; rotations need it.
func Lock(string) (func(), error) {
	return nil, errors.New("kek: ring locking needs a Unix platform")
}
