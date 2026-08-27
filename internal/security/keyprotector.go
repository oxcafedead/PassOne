package security

// KeyProtector protects application-level secrets at rest using an
// operating-system mechanism (currently Windows DPAPI).
type KeyProtector interface {
	Protect(data []byte) ([]byte, error)
	Unprotect(data []byte) ([]byte, error)
}
