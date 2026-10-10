package hashtree_test

import (
	"testing"

	"github.com/niccolofant/agent-go/certification/hashtree"
)

func TestDeserializeEmptyNodes(t *testing.T) {
	for _, raw := range [][]byte{
		{0x80}, {0xf6}, {0x9f, 0xff},
		{0x83, 1, 0x80, 0x81, 0}, {0x83, 1, 0x81, 0, 0x80},
		{0x83, 2, 0x41, 'a', 0x80},
	} {
		if node, err := hashtree.Deserialize(raw); err == nil || node != nil {
			t.Fatalf("accepted empty node %x: %v %v", raw, node, err)
		}
	}
	if node, err := hashtree.DeserializeNode(nil); err == nil || node != nil {
		t.Fatal("accepted nil node")
	}
	if node, err := hashtree.Deserialize([]byte{0x81, 0}); err != nil || node == nil {
		t.Fatal("rejected valid empty-tree node", err)
	}
}

func FuzzDeserializeTree(f *testing.F) {
	for _, raw := range [][]byte{{0x80}, {0xf6}, {0x81, 0}, {0x82, 3, 0x41, 'a'}, {0x83, 2, 0x41, 'a', 0x80}, {0x83, 1, 0x81, 0, 0x81, 0}} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		node, err := hashtree.Deserialize(raw)
		if err != nil {
			return
		}
		if node == nil {
			t.Fatal("nil parsed tree")
		}
		encoded, err := hashtree.Serialize(node)
		if err != nil {
			t.Fatal(err)
		}
		roundtrip, err := hashtree.Deserialize(encoded)
		if err != nil || roundtrip.Reconstruct() != node.Reconstruct() {
			t.Fatal("tree digest changed", err)
		}
	})
}
