package leb128

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
)

// AppendSignedInt64 appends the signed LEB128 encoding of v to dst and returns
// the extended slice. Allocation-free when dst has spare capacity (an int64
// needs at most 10 bytes). Matches EncodeSigned.
func AppendSignedInt64(dst []byte, v int64) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7 // arithmetic shift keeps the sign
		done := (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0)
		if !done {
			b |= 0x80
		}
		dst = append(dst, b)
		if done {
			return dst
		}
	}
}

// DecodeSigned converts the byte slice back to a signed integer. It consumes
// only the LEB128 bytes from r, leaving the reader positioned right after.
func DecodeSigned(r *bytes.Reader) (*big.Int, error) {
	var (
		prefix [10]byte
		value  uint64
		shift  uint
	)
	for i := 0; i < 9; i++ {
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("too short")
			}
			return nil, err
		}
		prefix[i] = b
		value |= uint64(b&0x7f) << shift
		shift += 7
		if b < 0x80 {
			if b&0x40 != 0 {
				value |= ^uint64(0) << shift
			}
			return big.NewInt(int64(value)), nil
		}
	}

	// Ten bytes are enough for every int64. The final payload must be pure
	// sign extension: 0x00 for non-negative values or 0x7f for negatives.
	b, err := r.ReadByte()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("too short")
		}
		return nil, err
	}
	prefix[9] = b
	if b < 0x80 && (b == 0x00 || b == 0x7f) {
		if b == 0x7f {
			value |= uint64(1) << 63
		}
		return big.NewInt(int64(value)), nil
	}

	bs := append([]byte(nil), prefix[:]...)
	for b >= 0x80 {
		b, err = r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("too short")
			}
			return nil, err
		}
		bs = append(bs, b)
	}
	return decodeSignedBytes(bs), nil
}

func decodeSignedBytes(bs []byte) *big.Int {
	last := bs[len(bs)-1]
	if last&0x40 == 0 {
		return decodeUnsignedBytes(bs)
	}
	l := len(bs) - 1
	v := new(big.Int)
	for i := l; i >= 0; i-- {
		v = v.Mul(v, x80)
		v = v.Add(v, big.NewInt(int64(0x80-(bs[i]&0x7F)-1)))
	}
	v = v.Mul(v, big.NewInt(-1))
	v = v.Add(v, big.NewInt(-1))
	return v
}

// EncodeSigned encodes a signed integer.
func EncodeSigned(n *big.Int) (LEB128, error) {
	v := new(big.Int).Set(n)
	neg := v.Sign() < 0
	if neg {
		v = v.Mul(v, big.NewInt(-1))
		v = v.Add(v, big.NewInt(-1))
	}
	var bs []byte
	for {
		b := byte(v.Int64() % 0x80)
		if neg {
			b = 0x80 - b - 1
		}
		v = v.Div(v, x80)
		if (neg && v.Sign() == 0 && b&0x40 != 0) ||
			(!neg && v.Sign() == 0 && b&0x40 == 0) {
			return append(bs, b), nil
		} else {
			bs = append(bs, b|0x80)
		}
	}
}

// SLEB128 represents a signed number encoded using signed LEB128.
type SLEB128 []byte
