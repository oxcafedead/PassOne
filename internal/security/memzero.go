package security

import "crypto/rand"

// Zero overwrites b with random bytes. This is BEST EFFORT only: Go is a
// garbage-collected language and provides no hard guarantee that copies made
// by the runtime are zeroized. It is still useful to reduce the lifetime of
// sensitive material before it becomes unreachable.
func Zero(b []byte) {
	if len(b) == 0 {
		return
	}
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = 0
		}
	}
}
