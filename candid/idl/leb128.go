package idl

import (
	"bytes"
)

func readLEB128(r *bytes.Reader) ([]byte, error) {
	var raw []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		raw = append(raw, b)
		if b < 0x80 {
			return raw, nil
		}
	}
}
