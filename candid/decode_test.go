package candid

import (
	"math/big"
	"testing"

	"github.com/aviate-labs/agent-go/candid/idl"
)

func TestDecodeRaw(t *testing.T) {
	type Example struct {
		N idl.Nat `ic:"nat"`
	}
	bi := big.NewInt(100)
	e, err := Marshal([]any{Example{N: idl.NewBigNat(bi)}})
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := Unmarshal(e, []any{&v}); err != nil {
		t.Fatal(err)
	}
	type ExampleRaw struct {
		N idl.RawMessage `ic:"nat"`
	}
	var r ExampleRaw
	if err := Unmarshal(e, []any{&r}); err != nil {
		t.Fatal(err)
	}
	var n idl.Nat
	if err := r.N.Unmarshal(&n); err != nil {
		t.Fatal(err)
	}
	if n.BigInt() == nil || n.BigInt().Cmp(bi) != 0 {
		t.Error(n)
	}
}
