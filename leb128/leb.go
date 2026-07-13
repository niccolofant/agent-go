package leb128

import (
	"bytes"
	"fmt"
	"math/big"
)

// AppendUnsignedUint64 appends the unsigned LEB128 encoding of v to dst and
// returns the extended slice. Allocation-free when dst has spare capacity (a
// uint64 needs at most 10 bytes). Matches EncodeUnsigned: zero encodes as 0x00.
func AppendUnsignedUint64(dst []byte, v uint64) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		dst = append(dst, b)
		if v == 0 {
			return dst
		}
	}
}

// DecodeUnsigned converts the byte slice back to an unsigned integer.
func DecodeUnsigned(r *bytes.Reader) (*big.Int, error) {
	var value uint64
	for shift := uint(0); ; shift += 7 {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		payload := uint64(b & 0x7f)
		if shift < 63 || shift == 63 && payload <= 1 {
			value |= payload << shift
			if b < 0x80 {
				return new(big.Int).SetUint64(value), nil
			}
			continue
		}

		// The value exceeds uint64. Continue with arbitrary precision only for
		// this uncommon path, retaining the low bits accumulated above.
		out := new(big.Int).SetUint64(value)
		term := new(big.Int).SetUint64(payload)
		term.Lsh(term, shift)
		out.Or(out, term)
		for b >= 0x80 {
			shift += 7
			b, err = r.ReadByte()
			if err != nil {
				return nil, err
			}
			term.SetUint64(uint64(b & 0x7f))
			term.Lsh(term, shift)
			out.Or(out, term)
		}
		return out, nil
	}
}

// decodeUnsignedBytes decodes a complete unsigned LEB128 byte slice without
// allocating a reader.
func decodeUnsignedBytes(bs []byte) *big.Int {
	var value uint64
	for i, b := range bs {
		shift := uint(i * 7)
		payload := uint64(b & 0x7f)
		if shift < 63 || shift == 63 && payload <= 1 {
			value |= payload << shift
			continue
		}

		out := new(big.Int).SetUint64(value)
		term := new(big.Int)
		for j := i; j < len(bs); j++ {
			term.SetUint64(uint64(bs[j] & 0x7f))
			term.Lsh(term, uint(j*7))
			out.Or(out, term)
		}
		return out
	}
	return new(big.Int).SetUint64(value)
}

// LEB128 represents an unsigned number encoded using (unsigned) LEB128.
type LEB128 []byte

// EncodeUnsigned encodes an unsigned integer.
func EncodeUnsigned(n *big.Int) (LEB128, error) {
	v := new(big.Int).Set(n)
	if v.Sign() < 0 {
		return nil, fmt.Errorf("can not leb128 encode negative values")
	}
	var bs []byte
	for {
		i := new(big.Int).And(v, x7F)
		v = v.Div(v, x80)
		if v.Cmp(x00) == 0 {
			b := i.Bytes()
			if len(b) == 0 {
				return []byte{0}, nil
			}
			return append(bs, b...), nil
		} else {
			b := new(big.Int).Or(i, x80)
			bs = append(bs, b.Bytes()...)
		}
	}
}
