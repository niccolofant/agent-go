package idl_test

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/niccolofant/agent-go/candid"
	"github.com/niccolofant/agent-go/candid/idl"
)

// ulebNeg is ULEB128 for 2^63: its low 64 bits are negative as int64, so an
// unchecked Int64() yields a negative length and make() panics.
var ulebNeg = []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}

// A malformed length from an untrusted canister response must produce an error,
// never a panic.
func TestDecode_MalformedLength_NoPanic(t *testing.T) {
	svcType := idl.NewServiceType(map[string]*idl.FunctionType{})
	for _, tc := range []struct {
		name string
		typ  idl.Type
		body []byte
	}{
		{"vector", idl.NewVectorType(idl.Nat8Type()), ulebNeg},
		{"text", new(idl.TextType), ulebNeg},
		{"service", svcType, append([]byte{0x01}, ulebNeg...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("PANIC decoding malformed %s: %v", tc.name, rec)
				}
			}()
			if _, err := tc.typ.Decode(bytes.NewReader(tc.body)); err == nil {
				t.Errorf("expected error for malformed %s length, got nil", tc.name)
			}
		})
	}
}

func TestHash(t *testing.T) {
	if h := idl.Hash("foo"); h.Cmp(big.NewInt(5097222)) != 0 {
		t.Errorf("expected '5097222', got '%s'", h)
	}
	if h := idl.Hash("bar"); h.Cmp(big.NewInt(4895187)) != 0 {
		t.Errorf("expected '4895187', got '%s'", h)
	}
	for _, value := range []string{"naive", "naive field", "naive-field", "na\u00efve"} {
		want := referenceCandidHash(value)
		if got := idl.Hash(value); got.Cmp(want) != 0 {
			t.Errorf("Hash(%q) = %s, want %s", value, got, want)
		}
		if got := idl.HashString(value); got != want.String() {
			t.Errorf("HashString(%q) = %s, want %s", value, got, want)
		}
	}
}

func referenceCandidHash(s string) *big.Int {
	var hash uint32
	for _, b := range []byte(s) {
		hash = hash*223 + uint32(b)
	}
	return new(big.Int).SetUint64(uint64(hash))
}

func test(types []idl.Type, args []any) {
	e, err := candid.Encode(types, args)
	if err != nil {
		fmt.Println("enc:", err)
		return
	}
	fmt.Printf("%x\n", e)

	ts, vs, err := candid.Decode(e)
	if err != nil {
		fmt.Println("dec:", err)
		return
	}
	for i, v := range ts {
		if v.String() != types[i].String() {
			fmt.Println("types:", v, types[i])
		}
	}
	for i, v := range vs {
		if fmt.Sprintf("%v", v) != fmt.Sprintf("%v", args[i]) {
			fmt.Println("args:", v, args[i])
		}
	}
}

func test_(types []idl.Type, args []any) {
	e, err := candid.Encode(types, args)
	if err != nil {
		fmt.Println("enc:", err)
		return
	}
	fmt.Printf("%x\n", e)

	if _, _, err := candid.Decode(e); err != nil {
		fmt.Println("dec:", err)
		return
	}
}
