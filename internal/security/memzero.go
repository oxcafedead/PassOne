package security

import (
	"crypto/rand"
	"math/big"
)

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

// ZeroInt overwrites the mantissa of x in place and leaves x holding a
// canonical zero. Like Zero it is BEST EFFORT: math/big may have produced
// short-lived copies of the value that this cannot reach. Unlike Zero it
// writes zeros rather than random words, because the overwritten value is
// being replaced by a plain zero anyway, so there is nothing to disguise.
func ZeroInt(x *big.Int) {
	if x == nil {
		return
	}
	// Bits returns the mantissa itself, not a copy, so writing through the
	// slice overwrites the integer in place. SetInt64(0) then truncates that
	// same array to length 0 without reallocating it.
	words := x.Bits()
	for i := range words {
		words[i] = 0
	}
	x.SetInt64(0)
}
