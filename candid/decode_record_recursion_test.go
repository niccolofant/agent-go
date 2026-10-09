package candid

import (
	"errors"
	"testing"

	"github.com/niccolofant/agent-go/candid/idl"
)

func TestDecodeUninhabitedRecords(t *testing.T) {
	for name, body := range map[string][]byte{
		"self":                         {1, 0x6c, 1, 0, 0, 1, 0},
		"mutual":                       {2, 0x6c, 1, 0, 1, 0x6c, 1, 0, 0, 1, 0},
		"mandatory ancestor":           {2, 0x6c, 1, 0, 0, 0x6c, 1, 0, 0, 1, 1},
		"consuming field before cycle": {1, 0x6c, 2, 0, 0x7d, 1, 0, 1, 0, 42},
		"present optional":             {2, 0x6c, 1, 0, 0, 0x6e, 0, 1, 1, 1},
		"nonempty vector":              {2, 0x6c, 1, 0, 0, 0x6d, 0, 1, 1, 1, 0},
		"selected variant":             {2, 0x6c, 1, 0, 0, 0x6b, 2, 0, 0, 1, 0x7f, 1, 1, 0},
	} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte("DIDL"), body...)
			if _, _, err := Decode(raw); !errors.Is(err, idl.ErrUninhabitedRecord) {
				t.Fatalf("Decode: %v", err)
			}
			var blob idl.RawMessage
			if err := Unmarshal(raw, []any{&blob}); !errors.Is(err, idl.ErrUninhabitedRecord) {
				t.Fatalf("raw: %v", err)
			}
			var dst struct{}
			if err := Unmarshal(raw, []any{&dst}); !errors.Is(err, idl.ErrUninhabitedRecord) {
				t.Fatalf("typed: %v", err)
			}
		})
	}
}

func TestUninhabitedRecordFuzzRegression(t *testing.T) {
	raw := []byte("DIDL\x03l\x02\nx0xA\x00l\x01\xaa0\x02\x02}\x020\xd7")
	var n idl.Nat
	var projected struct{}
	if err := Unmarshal(raw, []any{&n, &projected}); !errors.Is(err, idl.ErrUninhabitedRecord) {
		t.Fatalf("unknown-field skip: %v", err)
	}
	if _, _, err := Decode(raw); !errors.Is(err, idl.ErrUninhabitedRecord) {
		t.Fatalf("generic: %v", err)
	}
	var blob idl.RawMessage
	if err := Unmarshal(raw, []any{&n, &blob}); !errors.Is(err, idl.ErrUninhabitedRecord) {
		t.Fatalf("raw: %v", err)
	}
}

func TestUnvisitedUninhabitedRecordsRemainValid(t *testing.T) {
	for name, body := range map[string][]byte{
		"unused type":      {1, 0x6c, 1, 0, 0, 0},
		"absent optional":  {2, 0x6c, 1, 0, 0, 0x6e, 0, 1, 1, 0},
		"empty vector":     {2, 0x6c, 1, 0, 0, 0x6d, 0, 1, 1, 0},
		"unchosen variant": {2, 0x6c, 1, 0, 0, 0x6b, 2, 0, 0, 1, 0x7f, 1, 1, 1},
	} {
		t.Run(name, func(t *testing.T) {
			data := append([]byte("DIDL"), body...)
			ts, _, err := Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			var raw idl.RawMessage
			var values []any
			if len(ts) > 0 {
				values = []any{&raw}
			}
			if err := Unmarshal(data, values); err != nil {
				t.Fatal("raw", err)
			}
		})
	}
}

func TestValidRecursiveListAndForwardRecords(t *testing.T) {
	// type 0 = record {0:nat; 1:opt type 0}; type 1 = opt type 0.
	raw := []byte{'D', 'I', 'D', 'L', 2, 0x6c, 2, 0, 0x7d, 1, 1, 0x6e, 0, 1, 1}
	for range 1000 {
		raw = append(raw, 1, 42)
	}
	raw = append(raw, 0)
	type node struct {
		Head idl.Nat `ic:"0"`
		Tail *node   `ic:"1"`
	}
	var list *node
	if err := Unmarshal(raw, []any{&list}); err != nil {
		t.Fatal(err)
	}
	count := 0
	for n := list; n != nil; n = n.Tail {
		count++
		if n.Head.BigInt().Int64() != 42 {
			t.Fatal("head")
		}
	}
	if count != 1000 {
		t.Fatal(count)
	}
	if _, _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
	var blob idl.RawMessage
	if err := Unmarshal(raw, []any{&blob}); err != nil {
		t.Fatal(err)
	}
	// Forward references alone are not cycles.
	raw = []byte{'D', 'I', 'D', 'L', 2, 0x6c, 1, 0, 1, 0x6c, 1, 0, 0x7d, 1, 0, 42}
	var nested struct {
		Inner struct {
			N idl.Nat `ic:"0"`
		} `ic:"0"`
	}
	if err := Unmarshal(raw, []any{&nested}); err != nil || nested.Inner.N.BigInt().Int64() != 42 {
		t.Fatal(err)
	}
}

func TestRecursiveRecordSkipAndTypedBranches(t *testing.T) {
	for _, present := range []byte{0, 1} {
		raw := []byte{'D', 'I', 'D', 'L', 3, 0x6c, 1, 0, 0, 0x6e, 0, 0x6c, 1, 0, 1, 1, 2, present}
		var ignored struct{}
		var projected struct {
			Optional *struct{} `ic:"0"`
		}
		for _, dst := range []any{&ignored, &projected} {
			err := Unmarshal(raw, []any{dst})
			if (present == 0 && err != nil) || (present == 1 && !errors.Is(err, idl.ErrUninhabitedRecord)) {
				t.Fatalf("present=%d dst=%T: %v", present, dst, err)
			}
		}
	}
	for _, selected := range []byte{0, 1} {
		opt := []byte{'D', 'I', 'D', 'L', 2, 0x6c, 1, 0, 0, 0x6e, 0, 1, 1, selected}
		vec := []byte{'D', 'I', 'D', 'L', 2, 0x6c, 1, 0, 0, 0x6d, 0, 1, 1, selected, 0}
		variant := []byte{'D', 'I', 'D', 'L', 2, 0x6c, 1, 0, 0, 0x6b, 2, 0, 0, 1, 0x7f, 1, 1, 1 - selected}
		var optional *struct{}
		var vector []struct{}
		var choice struct {
			Cycle *struct{} `ic:"0,variant"`
			None  *idl.Null `ic:"1,variant"`
		}
		for _, tc := range []struct {
			raw []byte
			dst any
		}{{opt, &optional}, {vec, &vector}, {variant, &choice}} {
			err := Unmarshal(tc.raw, []any{tc.dst})
			if (selected == 0 && err != nil) || (selected == 1 && !errors.Is(err, idl.ErrUninhabitedRecord)) {
				t.Fatalf("selected=%d dst=%T: %v", selected, tc.dst, err)
			}
		}
	}
}

func TestRecursiveListWithForwardRecordDependency(t *testing.T) {
	// The forward nested record causes classification, but recursion via opt
	// still allows a finite list value.
	raw := []byte{'D', 'I', 'D', 'L', 3, 0x6c, 2, 0, 2, 1, 1, 0x6e, 0, 0x6c, 1, 0, 0x7d, 1, 1}
	for range 1000 {
		raw = append(raw, 1, 42)
	}
	raw = append(raw, 0)
	type node struct {
		Head struct {
			N idl.Nat `ic:"0"`
		} `ic:"0"`
		Tail *node `ic:"1"`
	}
	var list *node
	if err := Unmarshal(raw, []any{&list}); err != nil {
		t.Fatal(err)
	}
	count := 0
	for n := list; n != nil; n = n.Tail {
		count++
		if n.Head.N.BigInt().Int64() != 42 {
			t.Fatal("head")
		}
	}
	if count != 1000 {
		t.Fatal(count)
	}
	if _, _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
	var blob idl.RawMessage
	if err := Unmarshal(raw, []any{&blob}); err != nil {
		t.Fatal(err)
	}
}
