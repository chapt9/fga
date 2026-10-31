//go:build unix

package kek

import (
	"os"
	"syscall"
)

// Lock takes an exclusive lock on the ring file at path, held through a
// lock file beside it, and returns its release. A rotation holds it from
// reading the ring until its catalog step is done, so rotations of the
// same or different tenants cannot overwrite each other's versions
// (review v3 F07).
func Lock(path string) (func(), error) {
	f, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
