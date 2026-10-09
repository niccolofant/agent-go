package idl_test

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/niccolofant/agent-go/candid/idl"
	"github.com/niccolofant/agent-go/leb128"
	"github.com/niccolofant/agent-go/principal"
)

func ExamplePrincipal() {
	p := principal.MustDecode("aaaaa-aa")
	test([]idl.Type{idl.NewOptionalType(new(idl.PrincipalType))}, []any{p})
	// Output:
	// 4449444c016e680100010100
}

func TestPrincipalType_UnmarshalGo(t *testing.T) {
	var nt idl.PrincipalType

	var p principal.Principal
	if err := idl.UnmarshalGo(nt, principal.AnonymousID, &p); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Raw, principal.AnonymousID.Raw) {
		t.Error(p)
	}
	var empty []byte
	if err := idl.UnmarshalGo(nt, empty, &p); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Raw, empty) {
		t.Error(p)
	}

	var a any
	if err := idl.UnmarshalGo(nt, true, &a); err == nil {
		t.Fatal("expected error")
	} else {
		if _, ok := err.(*idl.UnmarshalGoError); !ok {
			t.Fatal("expected UnmarshalGoError")
		}
	}
}

func TestPrincipalType_ReadDecodeOwnership(t *testing.T) {
	var typ idl.PrincipalType
	for _, size := range []int{0, 1, 29} {
		body := bytes.Repeat([]byte{0xa5}, size)
		raw := append([]byte{1, byte(size)}, body...)
		for _, tail := range [][]byte{nil, {0xff}} {
			input := append(append([]byte(nil), raw...), tail...)
			r := bytes.NewReader(input)
			read, err := typ.Read(r)
			if err != nil || !bytes.Equal(read, raw) || r.Len() != len(tail) {
				t.Fatalf("Read size=%d: %x, remaining=%d, error=%v", size, read, r.Len(), err)
			}
			r.Reset(input)
			decoded, err := typ.Decode(r)
			if err != nil || r.Len() != len(tail) {
				t.Fatalf("Decode size=%d: remaining=%d, error=%v", size, r.Len(), err)
			}
			p := decoded.(principal.Principal)
			if !bytes.Equal(p.Raw, body) {
				t.Fatalf("Decode size=%d: %x", size, p.Raw)
			}
			if size > 0 {
				input[2] ^= 1
				if !bytes.Equal(p.Raw, body) || !bytes.Equal(read, raw) {
					t.Fatal("returned bytes alias input")
				}
			}
		}
	}
	// Preserve noncanonical but valid unsigned LEB128 length bytes in RawMessage.
	raw := []byte{1, 0x81, 0, 0xa5}
	if got, err := typ.Read(bytes.NewReader(raw)); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("raw length changed: %x, %v", got, err)
	}
}

func TestPrincipalType_RejectsInvalidLengths(t *testing.T) {
	var typ idl.PrincipalType
	for _, length := range []*big.Int{
		big.NewInt(3),
		new(big.Int).Lsh(big.NewInt(1), 32),
		new(big.Int).Lsh(big.NewInt(1), 63),
		new(big.Int).Lsh(big.NewInt(1), 64),
		new(big.Int).Lsh(big.NewInt(1), 128),
	} {
		encoded, err := leb128.EncodeUnsigned(length)
		if err != nil {
			t.Fatal(err)
		}
		raw := append([]byte{1}, encoded...)
		raw = append(raw, 0, 0)
		if _, err := typ.Decode(bytes.NewReader(raw)); err == nil || !strings.HasPrefix(err.Error(), "invalid length ") {
			t.Fatalf("Decode length=%s: %v", length, err)
		}
		if _, err := typ.Read(bytes.NewReader(raw)); err == nil || !strings.HasPrefix(err.Error(), "invalid length ") {
			t.Fatalf("Read length=%s: %v", length, err)
		}
	}
}
