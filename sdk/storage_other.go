//go:build !windows

package authlyx

import (
	"errors"
	"os"
)

func showUpdate(heading, body, link string) {}

func NewWindowsProtectedStore(string) (Store, error) {
	return nil, errors.New("WindowsProtectedStore requires Windows; supply a platform-protected Store")
}

func readDevice() (name, kind, baseboard, uuid string) {
	name, _ = os.Hostname()
	return name, "", "", ""
}
