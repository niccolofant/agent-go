package idl

import (
	"math/big"
	"strconv"
)

// Hash hashes a string to a number.
// ( Sum_(i=0..k) utf8(id)[i] * 223^(k-i) ) mod 2^32 where k = |utf8(id)|-1
func Hash(s string) *big.Int {
	return new(big.Int).SetUint64(uint64(hashUint32(s)))
}

func HashString(s string) string {
	return strconv.FormatUint(uint64(hashUint32(s)), 10)
}

func hashUint32(s string) uint32 {
	var hash uint32
	for i := 0; i < len(s); i++ {
		hash = hash*223 + uint32(s[i])
	}
	return hash
}
