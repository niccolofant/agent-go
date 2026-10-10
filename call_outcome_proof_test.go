package agent

import (
	"bytes"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/certification/hashtree"
)

func TestCallOutcomePruningPreservesSignature(t *testing.T) {
	a, p, sk := outcomeFixture(t)
	stamp := hashtree.Leaf(outcomeNat(uint64(outcomeNow.UnixNano())))
	fields := map[string]hashtree.Node{"status": hashtree.Leaf("replied"), "reply": hashtree.Leaf("ok")}
	subtree := outcomeFields(fields)
	tree := outcomeTree(p.id, subtree, stamp)
	original := outcomeWire(t, sk, tree, nil)
	var wire map[string]cbor.RawMessage
	if err := cbor.Unmarshal(original, &wire); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		tree hashtree.Node
		want CallStatus
	}{
		{"reply", outcomeTree(p.id, outcomeFields(map[string]hashtree.Node{"status": fields["status"], "reply": hashtree.Pruned(fields["reply"].Reconstruct())}), stamp), ""},
		{"status", outcomeTree(p.id, outcomeFields(map[string]hashtree.Node{"status": hashtree.Pruned(fields["status"].Reconstruct()), "reply": fields["reply"]}), stamp), CallStatusUnproven},
		{"request", outcomeTree(p.id, hashtree.Pruned(subtree.Reconstruct()), stamp), CallStatusUnproven},
		{"time", outcomeFields(map[string]hashtree.Node{"request_status": hashtree.Labeled{Label: p.id[:], Tree: subtree}, "time": hashtree.Pruned(stamp.Reconstruct())}), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.tree.Reconstruct() != tree.Reconstruct() {
				t.Fatal("pruning changed digest")
			}
			wire["tree"] = preparedMarshal(t, hashtree.NewHashTree(tc.tree))
			o, err := a.verifyCallCertificateAt(p, preparedMarshal(t, wire), outcomePolicy, outcomeNow)
			if tc.want == "" {
				if o != nil || !errors.Is(err, ErrInvalidCallCertificate) {
					t.Fatalf("accepted incomplete proof: %v", err)
				}
				return
			}
			if err != nil || o.Status() != tc.want {
				t.Fatalf("pruned status: %v", err)
			}
		})
	}
	// Prove absence between two visible siblings, then prune a boundary. The
	// same valid signature now supports only uncertainty, not absence.
	left, right := p.id, p.id
	left[0]--
	right[0]++
	l := hashtree.Labeled{Label: left[:], Tree: hashtree.Empty{}}
	r := hashtree.Labeled{Label: right[:], Tree: hashtree.Empty{}}
	tree = outcomeFields(map[string]hashtree.Node{"request_status": hashtree.Fork{LeftTree: l, RightTree: r}, "time": stamp})
	raw := outcomeWire(t, sk, tree, nil)
	o, err := a.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow)
	if err != nil || o.Status() != CallStatusAbsent {
		t.Fatalf("absence: %v", err)
	}
	if _, ok := o.SubnetID(); ok {
		t.Fatal("root-signed proof has a delegated subnet")
	}
	if err := cbor.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	wire["tree"] = preparedMarshal(t, hashtree.NewHashTree(outcomeFields(map[string]hashtree.Node{"request_status": hashtree.Fork{LeftTree: hashtree.Pruned(l.Reconstruct()), RightTree: r}, "time": stamp})))
	o, err = a.verifyCallCertificateAt(p, preparedMarshal(t, wire), outcomePolicy, outcomeNow)
	if err != nil || o.Status() != CallStatusUnproven {
		t.Fatalf("pruned absence boundary: %v", err)
	}
}

func TestCallOutcomeDelegatedKeyConfusion(t *testing.T) {
	a, p, rootKey := outcomeFixture(t)
	subnetKey, der := callCertificateSigner(t)
	subnet := []byte{9, 1}
	stamp := outcomeNat(uint64(outcomeNow.UnixNano()))
	ranges := hashtree.Leaf(preparedMarshal(t, [][]any{{p.canister.Raw, p.canister.Raw}}))
	for _, tc := range []string{"valid", "outer root signed", "delegation subnet signed", "wrong subnet", "pruned key", "outer absent"} {
		t.Run(tc, func(t *testing.T) {
			label := bytes.Clone(subnet)
			if tc == "wrong subnet" {
				label[0]++
			}
			var key hashtree.Node = hashtree.Leaf(der)
			if tc == "pruned key" {
				key = hashtree.Pruned(key.Reconstruct())
			}
			delegationTree := outcomeFields(map[string]hashtree.Node{
				"subnet":         hashtree.Labeled{Label: label, Tree: outcomeFields(map[string]hashtree.Node{"public_key": key, "canister_ranges": ranges})},
				"request_status": hashtree.Labeled{Label: p.id[:], Tree: outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("replied"), "reply": hashtree.Leaf("wrong tree")})},
				"time":           hashtree.Leaf(stamp),
			})
			delegator := rootKey
			if tc == "delegation subnet signed" {
				delegator = subnetKey
			}
			delegation := map[string]any{"subnet_id": subnet, "certificate": outcomeWire(t, delegator, delegationTree, nil)}
			var outer hashtree.Node = outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("done")})
			if tc == "outer absent" {
				outer = hashtree.Empty{}
			}
			signer := subnetKey
			if tc == "outer root signed" {
				signer = rootKey
			}
			raw := outcomeWire(t, signer, outcomeTree(p.id, outer, stamp), delegation)
			o, err := a.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow)
			if tc != "valid" && tc != "outer absent" {
				if o != nil || !errors.Is(err, ErrInvalidCallCertificate) {
					t.Fatalf("key confusion accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc == "outer absent" && o.Status() != CallStatusAbsent {
				t.Fatal("used status from delegation")
			}
			got, ok := o.SubnetID()
			if !ok || !bytes.Equal(got.Raw, subnet) {
				t.Fatal("attesting subnet")
			}
			got.Raw[0] ^= 1
			got, _ = o.SubnetID()
			if !bytes.Equal(got.Raw, subnet) {
				t.Fatal("subnet alias")
			}
		})
	}
}

func TestCallOutcomeStrictWireAndContext(t *testing.T) {
	a, p, sk := outcomeFixture(t)
	stamp := outcomeNat(uint64(outcomeNow.UnixNano()))
	for _, status := range []string{"absent", "unproven", "Replied", "replied\x00"} {
		raw := outcomeWire(t, sk, outcomeTree(p.id, outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf(status)}), stamp), nil)
		if o, err := a.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow); o != nil || !errors.Is(err, ErrInvalidCallCertificate) {
			t.Fatal("synthetic status accepted")
		}
	}
	raw := outcomeWire(t, sk, outcomeTree(p.id, outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("done")}), stamp), nil)
	var wire map[string]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if raw[0] != 0xa2 {
		t.Fatal("fixture map size")
	}
	duplicate := append([]byte{0xa3}, raw[1:]...)
	duplicate = append(duplicate, preparedMarshal(t, "signature")...)
	duplicate = append(duplicate, wire["signature"]...)
	indefinite := append([]byte{0xbf}, raw[1:]...)
	indefinite = append(indefinite, 0xff)
	for _, bad := range [][]byte{duplicate, indefinite} {
		if o, err := a.verifyCallCertificateAt(p, bad, outcomePolicy, outcomeNow); o != nil || !errors.Is(err, ErrInvalidCallCertificate) {
			t.Fatal("wire ambiguity accepted")
		}
	}
	for _, aa := range []*Agent{nil, {}, preparedAgent(t, preparedIdentity(t, 5))} {
		if o, err := aa.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow); o != nil || !errors.Is(err, ErrCallCertificateContext) {
			t.Fatal("bad context classification")
		}
	}
	if o, err := a.verifyCallCertificateAt(p, raw, CallCertificateOptions{}, outcomeNow); o != nil || !errors.Is(err, ErrCallCertificateContext) {
		t.Fatal("bad policy classification")
	}
	if n, ok := callNatural([]byte{0x81, 0}); !ok || n != 1 {
		t.Fatal("certified overlong LEB128 rejected")
	}
}
