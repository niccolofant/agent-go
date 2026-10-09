package candid

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/niccolofant/agent-go/leb128"
)

func TestDecodeTypeLengthsRejectMalformed(t *testing.T) {
	// Each prefix ends immediately before a declaration count or byte length.
	prefixes := map[string][]byte{
		"type table":     {},
		"future body":    {1, 0x67},
		"legacy opcode":  {1, 0x72},
		"arguments":      {0},
		"record fields":  {1, 0x6c},
		"variant fields": {1, 0x6b},
		"function args":  {1, 0x6a},
		"function rets":  {1, 0x6a, 0},
		"annotations":    {1, 0x6a, 0, 0},
		"methods":        {1, 0x69},
		"method name":    {1, 0x69, 1},
	}
	lengths := []*big.Int{
		big.NewInt(3), // Only two bytes remain, even before parsing the tail.
		new(big.Int).Lsh(big.NewInt(1), 31),
		new(big.Int).Lsh(big.NewInt(1), 63),
		new(big.Int).Lsh(big.NewInt(1), 64),
		new(big.Int).Lsh(big.NewInt(1), 128),
	}
	for name, prefix := range prefixes {
		for _, length := range lengths {
			t.Run(name+"/"+length.String(), func(t *testing.T) {
				encoded, err := leb128.EncodeUnsigned(length)
				if err != nil {
					t.Fatal(err)
				}
				raw := append([]byte("DIDL"), prefix...)
				raw = append(raw, encoded...)
				raw = append(raw, 0, 0)
				if _, _, err := Decode(raw); err == nil || !strings.HasPrefix(err.Error(), "invalid type length ") {
					t.Fatalf("Decode did not reject the impossible length: %v", err)
				}
				if err := Unmarshal(raw, nil); err == nil || !strings.HasPrefix(err.Error(), "invalid type length ") {
					t.Fatalf("Unmarshal did not reject the impossible length: %v", err)
				}
			})
		}
	}
}

func TestDecodeTypeLengthsFuzzRegression(t *testing.T) {
	// A 17-byte TacoDEX fuzz input formerly attempted a multi-GB allocation.
	raw := []byte("DIDL\xe5\x8a\x0br\x88\xd3\xe5\x8a\x0brm\x00\x01\xee")
	if _, _, err := Decode(raw); err == nil {
		t.Fatal("accepted malformed type table")
	}
	if err := Unmarshal(raw, nil); err == nil {
		t.Fatal("accepted malformed type table")
	}
}

func TestDecodeTypeLengthsValidAndTruncated(t *testing.T) {
	for name, body := range map[string][]byte{
		"empty":          {0, 0},
		"future empty":   {1, 0x67, 0, 0},
		"future body":    {1, 0x67, 3, 0xaa, 0xbb, 0xcc, 0},
		"empty record":   {1, 0x6c, 0, 1, 0},
		"empty variant":  {1, 0x6b, 0, 0},
		"null args":      {0, 3, 0x7f, 0x7f, 0x7f},
		"function":       {1, 0x6a, 0, 0, 0, 0},
		"query function": {1, 0x6a, 0, 0, 1, 1, 0},
		"empty service":  {1, 0x69, 0, 0},
		"service":        {2, 0x6a, 0, 0, 0, 0x69, 1, 1, 'x', 0, 0},
		"empty name":     {2, 0x6a, 0, 0, 0, 0x69, 1, 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte("DIDL"), body...)
			if _, _, err := Decode(raw); err != nil {
				t.Fatal(err)
			}
			for n := range len(raw) {
				if _, _, err := Decode(raw[:n]); err == nil {
					t.Fatalf("accepted truncated declaration at byte %d", n)
				}
			}
		})
	}
}

func TestDecodeTypeLengthAllocations(t *testing.T) {
	raw := []byte{1, 0}
	r := bytes.NewReader(raw)
	unbounded := testing.AllocsPerRun(100, func() {
		r.Reset(raw)
		if _, err := leb128.DecodeUnsigned(r); err != nil {
			t.Fatal(err)
		}
	})
	bounded := testing.AllocsPerRun(100, func() {
		r.Reset(raw)
		if _, err := decodeTypeLength(r); err != nil {
			t.Fatal(err)
		}
	})
	if bounded != unbounded {
		t.Fatalf("bounded %v allocations; original %v", bounded, unbounded)
	}
}

func TestDecodeInvalidRecursiveTypeError(t *testing.T) {
	// First resolve a self-reference, then fail on an out-of-range reference.
	// Reporting the error must not recursively format the partial type graph.
	for name, body := range map[string][]byte{
		"record":  {1, 0x6c, 2, 0, 0, 1, 1, 0},
		"variant": {1, 0x6b, 2, 0, 0, 1, 1, 0},
		"func":    {1, 0x6a, 2, 0, 1, 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte("DIDL"), body...)
			prefix := "unable to resolve " + name + ":"
			if _, _, err := Decode(raw); err == nil || !strings.HasPrefix(err.Error(), prefix) {
				t.Fatalf("Decode: %v", err)
			}
			if err := Unmarshal(raw, nil); err == nil || !strings.HasPrefix(err.Error(), prefix) {
				t.Fatalf("Unmarshal: %v", err)
			}
		})
	}
}
