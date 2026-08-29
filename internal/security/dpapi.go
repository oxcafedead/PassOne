package security

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPIKeyProtector encrypts data with the Windows Data Protection API
// (CryptProtectData), scoped to the current user session.
type DPAPIKeyProtector struct{}

const (
	crptProtectUIForbidden   = 0x1
	crptProtectVerifyProtect = 0x40
)

var (
	crypt32                = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

// dataBlob mirrors the Windows DATA_BLOB structure.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

func emptyBlob() *dataBlob {
	return &dataBlob{}
}

func bytesToBlob(b []byte) *dataBlob {
	if len(b) == 0 {
		return emptyBlob()
	}
	return &dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func (d *dataBlob) toBytes() []byte {
	if d == nil || d.pbData == nil || d.cbData == 0 {
		return nil
	}
	return unsafe.Slice(d.pbData, d.cbData)
}

func (d *dataBlob) free() {
	if d != nil && d.pbData != nil {
		// CryptProtectData/CryptUnprotectData allocate the output blob with
		// LocalAlloc, so it must be released with LocalFree (kernel32).
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(d.pbData)))
	}
}

// Protect seals data with the Windows Data Protection API for the current
// user session.
func (p *DPAPIKeyProtector) Protect(data []byte) ([]byte, error) {
	in := bytesToBlob(data) // points into Go-managed memory: never free
	var out dataBlob        // allocated by CryptProtectData via LocalAlloc: must free
	// CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_VERIFY_PROTECTION
	r0, _, e1 := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(in)),
		0,
		0, // entropy
		0, // reserved
		0, // no prompt structure
		uintptr(crptProtectUIForbidden|crptProtectVerifyProtect),
		uintptr(unsafe.Pointer(&out)),
	)
	if r0 == 0 {
		return nil, e1
	}
	result := make([]byte, len(out.toBytes()))
	copy(result, out.toBytes())
	out.free()
	return result, nil
}

// Unprotect reverses Protect using the Windows Data Protection API.
func (p *DPAPIKeyProtector) Unprotect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("no data to unprotect")
	}
	in := bytesToBlob(data) // points into Go-managed memory: never free
	var out dataBlob        // allocated by CryptUnprotectData via LocalAlloc: must free
	r0, _, e1 := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(in)),
		0,
		0, // entropy
		0, // reserved
		0, // no prompt structure
		uintptr(crptProtectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	if r0 == 0 {
		return nil, e1
	}
	result := make([]byte, len(out.toBytes()))
	copy(result, out.toBytes())
	out.free()
	return result, nil
}
