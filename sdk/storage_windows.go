//go:build windows

package authlyx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

type WindowsProtectedStore struct{ directory string }

func NewWindowsProtectedStore(directory string) (*WindowsProtectedStore, error) {
	path, e := filepath.Abs(directory)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(path, 0700); e != nil {
		return nil, e
	}
	return &WindowsProtectedStore{path}, nil
}

type dataBlob struct {
	size uint32
	data *byte
}

var crypt32 = syscall.NewLazyDLL("crypt32.dll")
var protectData = crypt32.NewProc("CryptProtectData")
var unprotectData = crypt32.NewProc("CryptUnprotectData")
var localFree = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")
var messageBox = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
var shellExecute = syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")

func showUpdate(heading, body, link string) {
	text, e1 := syscall.UTF16PtrFromString(body)
	caption, e2 := syscall.UTF16PtrFromString(heading)
	if e1 != nil || e2 != nil {
		return
	}
	flags := uintptr(0x40 | 0x40000 | 0x10000)
	if link != "" {
		flags |= 0x4
	}
	answer, _, _ := messageBox.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(caption)), flags)
	if answer != 6 || link == "" {
		return
	}
	verb, _ := syscall.UTF16PtrFromString("open")
	target, e := syscall.UTF16PtrFromString(link)
	if e == nil {
		shellExecute.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)), 0, 0, 1)
	}
}

func blob(v []byte) dataBlob {
	if len(v) == 0 {
		return dataBlob{}
	}
	return dataBlob{uint32(len(v)), &v[0]}
}
func dpapi(name string, value []byte, protect bool) ([]byte, error) {
	entropy := []byte(name)
	source, extra, output := blob(value), blob(entropy), dataBlob{}
	operation := unprotectData
	if protect {
		operation = protectData
	}
	result, _, _ := operation.Call(uintptr(unsafe.Pointer(&source)), 0, uintptr(unsafe.Pointer(&extra)), 0, 0, 1, uintptr(unsafe.Pointer(&output)))
	runtime.KeepAlive(value)
	runtime.KeepAlive(entropy)
	if result == 0 {
		return nil, errors.New("protected state could not be read or saved")
	}
	defer localFree.Call(uintptr(unsafe.Pointer(output.data)))
	return append([]byte(nil), unsafe.Slice(output.data, int(output.size))...), nil
}
func (s *WindowsProtectedStore) file(name string) string {
	return filepath.Join(s.directory, hash([]byte(name))+".dat")
}
func (s *WindowsProtectedStore) Load(ctx context.Context, name string) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	b, e := os.ReadFile(s.file(name))
	if os.IsNotExist(e) {
		return "", nil
	}
	if e != nil {
		return "", e
	}
	if len(b) > 1048576 {
		return "", errors.New("protected state is too large")
	}
	plain, e := dpapi(name, b, false)
	if e == nil && len(plain) == 0 {
		e = errors.New("protected state is empty")
	}
	return string(plain), e
}
func (s *WindowsProtectedStore) Save(ctx context.Context, name, value string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	b, e := dpapi(name, []byte(value), true)
	if e != nil {
		return e
	}
	file, e := os.CreateTemp(s.directory, ".authlyx-*.tmp")
	if e != nil {
		return e
	}
	temp := file.Name()
	defer os.Remove(temp)
	if _, e = file.Write(b); e == nil {
		e = file.Sync()
	}
	closeError := file.Close()
	if e != nil {
		return e
	}
	if closeError != nil {
		return closeError
	}
	return os.Rename(temp, s.file(name))
}
func (s *WindowsProtectedStore) Delete(ctx context.Context, name string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	e := os.Remove(s.file(name))
	if os.IsNotExist(e) {
		return nil
	}
	return e
}

var firmwareTable = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")

func readDevice() (name, kind, baseboard, uuid string) {
	name, kind = os.Getenv("COMPUTERNAME"), "Windows"
	size, _, _ := firmwareTable.Call(0x52534D42, 0, 0, 0)
	if size <= 8 {
		return
	}
	raw := make([]byte, size)
	if got, _, _ := firmwareTable.Call(0x52534D42, 0, uintptr(unsafe.Pointer(&raw[0])), size); got != size {
		return
	}
	end := 8 + int(uint32(raw[4])|uint32(raw[5])<<8|uint32(raw[6])<<16|uint32(raw[7])<<24)
	if end > len(raw) {
		end = len(raw)
	}
	for p := 8; p+4 <= end; {
		table, header := raw[p], int(raw[p+1])
		if header < 4 || p+header > end {
			break
		}
		stringsEnd := p + header
		for stringsEnd+1 < end && !(raw[stringsEnd] == 0 && raw[stringsEnd+1] == 0) {
			stringsEnd++
		}
		parts := splitStrings(raw[p+header : stringsEnd])
		textAt := func(index byte) string {
			if index == 0 || int(index) > len(parts) {
				return ""
			}
			return parts[index-1]
		}
		switch {
		case table == 1 && header >= 0x18:
			u := raw[p+8 : p+24]
			uuid = fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15])
		case table == 2 && header >= 8 && baseboard == "":
			baseboard = textAt(raw[p+7])
		case table == 3 && header >= 6 && kind == "Windows":
			kind = chassisType(int(raw[p+5] & 0x7F))
		}
		p = stringsEnd + 2
		if table == 127 {
			break
		}
	}
	return
}

func splitStrings(data []byte) []string {
	var parts []string
	start := 0
	for i, b := range data {
		if b == 0 {
			parts = append(parts, string(data[start:i]))
			start = i + 1
		}
	}
	if start < len(data) {
		parts = append(parts, string(data[start:]))
	}
	return parts
}
