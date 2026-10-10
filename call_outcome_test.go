package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sort"
	"sync"
	"testing"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/certification/bls"
	"github.com/niccolofant/agent-go/certification/hashtree"
	"github.com/niccolofant/agent-go/principal"
)

var outcomeNow = time.Unix(1800000000, 123)
var outcomePolicy = CallCertificateOptions{MaxAge: time.Minute, MaxFutureSkew: time.Second}

func outcomeFixture(tb testing.TB) (*Agent, *PreparedCall, *bls.SecretKey) {
	tb.Helper()
	sk, root := callCertificateSigner(tb)
	a := preparedAgent(tb, preparedIdentity(tb, 77))
	a.rootKey = root
	_, _, raw := preparedFixture(tb, a)
	p, err := a.RestorePreparedCall(raw)
	if err != nil {
		tb.Fatal(err)
	}
	return a, p, sk
}

func outcomeNat(n uint64) []byte { return binary.AppendUvarint(nil, n) }

func outcomeFields(fields map[string]hashtree.Node) hashtree.Node {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var root hashtree.Node
	for _, key := range keys {
		n := hashtree.Labeled{Label: []byte(key), Tree: fields[key]}
		if root == nil {
			root = n
		} else {
			root = hashtree.Fork{LeftTree: root, RightTree: n}
		}
	}
	if root == nil {
		return hashtree.Empty{}
	}
	return root
}

func outcomeTree(id RequestID, status hashtree.Node, ns []byte) hashtree.Node {
	return outcomeFields(map[string]hashtree.Node{
		"request_status": hashtree.Labeled{Label: id[:], Tree: status},
		"time":           hashtree.Leaf(ns),
	})
}

func outcomeWire(tb testing.TB, sk *bls.SecretKey, tree hashtree.Node, delegation any) []byte {
	tb.Helper()
	root := tree.Reconstruct()
	sig, err := sk.Sign(append(hashtree.DomainSeparator("ic-state-root"), root[:]...))
	if err != nil {
		tb.Fatal(err)
	}
	affine := bls12381.G1Affine(*sig)
	rawSig := affine.Bytes()
	wire := map[string]any{"tree": hashtree.NewHashTree(tree), "signature": rawSig[:]}
	if delegation != nil {
		wire["delegation"] = delegation
	}
	return preparedMarshal(tb, wire)
}

func TestCallOutcomeStatuses(t *testing.T) {
	a, p, sk := outcomeFixture(t)
	for _, status := range []CallStatus{CallStatusReceived, CallStatusProcessing, CallStatusDone, CallStatusReplied, CallStatusRejected, CallStatusAbsent, CallStatusUnproven} {
		t.Run(string(status), func(t *testing.T) {
			fields := map[string]hashtree.Node{"status": hashtree.Leaf(status)}
			if status == CallStatusReplied {
				fields["reply"] = hashtree.Leaf([]byte{})
			}
			if status == CallStatusRejected {
				fields["reject_code"] = hashtree.Leaf(outcomeNat(300)) // full unsigned LEB128, not just its first byte
				fields["reject_message"] = hashtree.Leaf("reject after partial work")
				fields["error_code"] = hashtree.Leaf("IC0503")
			}
			var node hashtree.Node = outcomeFields(fields)
			if status == CallStatusAbsent {
				node = hashtree.Empty{}
			}
			if status == CallStatusUnproven {
				node = hashtree.Pruned{1}
			}
			raw := outcomeWire(t, sk, outcomeTree(p.id, node, outcomeNat(uint64(outcomeNow.UnixNano()))), nil)
			o, err := a.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow)
			if err != nil {
				t.Fatal(err)
			}
			if o.Status() != status || o.RequestID() != p.id || !o.CertifiedAt().Equal(outcomeNow) ||
				!o.Sender().Equal(p.sender) || !o.CanisterID().Equal(p.canister) || o.RootKeyHash() != p.rootHash || !bytes.Equal(o.Certificate(), raw) {
				t.Fatal("outcome identity mismatch")
			}
			if reply, ok := o.Reply(); ok != (status == CallStatusReplied) || len(reply) != 0 {
				t.Fatal("reply presence")
			}
			if r, ok := o.Rejection(); ok != (status == CallStatusRejected) || (ok && (r.Code != 300 || r.Message != "reject after partial work" || r.ErrorCode != "IC0503")) {
				t.Fatal("rejection presence/content")
			}
		})
	}
}

func TestCallOutcomeInvalidResponseFields(t *testing.T) {
	a, p, sk := outcomeFixture(t)
	for name, fields := range map[string]map[string]hashtree.Node{
		"unknown status":     {"status": hashtree.Leaf("success")},
		"empty status":       {"status": hashtree.Leaf([]byte{})},
		"branch status":      {"status": outcomeFields(map[string]hashtree.Node{"x": hashtree.Leaf("replied")})},
		"missing reply":      {"status": hashtree.Leaf("replied")},
		"pruned reply":       {"status": hashtree.Leaf("replied"), "reply": hashtree.Pruned{1}},
		"missing rejection":  {"status": hashtree.Leaf("rejected")},
		"code trailing":      {"status": hashtree.Leaf("rejected"), "reject_code": hashtree.Leaf{5, 0}, "reject_message": hashtree.Leaf("x")},
		"code zero":          {"status": hashtree.Leaf("rejected"), "reject_code": hashtree.Leaf{0}, "reject_message": hashtree.Leaf("x")},
		"bad text":           {"status": hashtree.Leaf("rejected"), "reject_code": hashtree.Leaf{5}, "reject_message": hashtree.Leaf{0xff}},
		"unknown error code": {"status": hashtree.Leaf("rejected"), "reject_code": hashtree.Leaf{5}, "reject_message": hashtree.Leaf("x"), "error_code": hashtree.Pruned{1}},
	} {
		t.Run(name, func(t *testing.T) {
			raw := outcomeWire(t, sk, outcomeTree(p.id, outcomeFields(fields), outcomeNat(uint64(outcomeNow.UnixNano()))), nil)
			if o, err := a.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow); o != nil || !errors.Is(err, ErrInvalidCallCertificate) {
				t.Fatalf("accepted bad fields: %v", err)
			}
		})
	}
	fields := outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("rejected"), "reject_code": hashtree.Leaf{5}, "reject_message": hashtree.Leaf([]byte{})})
	raw := outcomeWire(t, sk, outcomeTree(p.id, fields, outcomeNat(uint64(outcomeNow.UnixNano()))), nil)
	if o, err := a.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow); err != nil || o.Status() != CallStatusRejected {
		t.Fatalf("optional error code: %v", err)
	}
}

func TestCallOutcomeBindingAndOwnership(t *testing.T) {
	a, p, sk := outcomeFixture(t)
	raw := outcomeWire(t, sk, outcomeTree(p.id, outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("replied"), "reply": hashtree.Leaf("DIDL app error")}), outcomeNat(uint64(outcomeNow.UnixNano()))), nil)
	want := bytes.Clone(raw)
	o, err := a.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{raw, o.Certificate(), o.Sender().Raw, o.CanisterID().Raw} {
		b[0] ^= 1
	}
	r, _ := o.Reply()
	r[0] ^= 1
	r, _ = o.Reply()
	if !bytes.Equal(o.Certificate(), want) || string(r) != "DIDL app error" || !o.Sender().Equal(p.sender) || !o.CanisterID().Equal(p.canister) {
		t.Fatal("mutable alias")
	}
	other := preparedAgent(t, preparedIdentity(t, 88))
	other.rootKey = a.rootKey
	if v, err := other.verifyCallCertificateAt(p, want, outcomePolicy, outcomeNow); v != nil || err == nil {
		t.Fatal("wrong sender accepted")
	}
	other = preparedAgent(t, preparedIdentity(t, 77))
	if v, err := other.verifyCallCertificateAt(p, want, outcomePolicy, outcomeNow); v != nil || err == nil {
		t.Fatal("wrong root context accepted")
	}
	for _, invalid := range []*PreparedCall{nil, {}} {
		if v, err := a.verifyCallCertificateAt(invalid, want, outcomePolicy, outcomeNow); v != nil || err == nil {
			t.Fatal("unauthenticated call accepted")
		}
	}
	wrongID := p.id
	wrongID[0] ^= 1
	wrong := outcomeWire(t, sk, outcomeTree(wrongID, outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("replied"), "reply": hashtree.Leaf("not our reply")}), outcomeNat(uint64(outcomeNow.UnixNano()))), nil)
	v, err := a.verifyCallCertificateAt(p, wrong, outcomePolicy, outcomeNow)
	if err != nil || v.Status() != CallStatusAbsent {
		t.Fatalf("different request: %v", err)
	}
	wrongSigner, _ := callCertificateSigner(t)
	badSig := outcomeWire(t, wrongSigner, outcomeTree(p.id, outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("done")}), outcomeNat(uint64(outcomeNow.UnixNano()))), nil)
	if v, err := a.verifyCallCertificateAt(p, badSig, outcomePolicy, outcomeNow); v != nil || err == nil {
		t.Fatal("wrong signer accepted")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				if _, err := a.verifyCallCertificateAt(p, want, outcomePolicy, outcomeNow); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}

func TestCallOutcomeTimePolicy(t *testing.T) {
	a, p, sk := outcomeFixture(t)
	status := outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("processing")})
	for name, ns := range map[string][]byte{
		"zero": {0}, "empty": {}, "unterminated": {0x80}, "trailing": {1, 0},
		"overflow": outcomeNat(math.MaxUint64), "oversized": bytes.Repeat([]byte{0xff}, 11),
		"stale":  outcomeNat(uint64(outcomeNow.Add(-time.Minute - time.Nanosecond).UnixNano())),
		"future": outcomeNat(uint64(outcomeNow.Add(time.Second + time.Nanosecond).UnixNano())),
	} {
		t.Run(name, func(t *testing.T) {
			raw := outcomeWire(t, sk, outcomeTree(p.id, status, ns), nil)
			if o, err := a.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow); o != nil || err == nil {
				t.Fatal("bad time accepted")
			}
		})
	}
	for _, at := range []time.Time{outcomeNow.Add(-time.Minute), outcomeNow, outcomeNow.Add(time.Second)} {
		raw := outcomeWire(t, sk, outcomeTree(p.id, status, outcomeNat(uint64(at.UnixNano()))), nil)
		if _, err := a.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow); err != nil {
			t.Fatal(err)
		}
	}
	raw := outcomeWire(t, sk, outcomeTree(p.id, status, outcomeNat(uint64(time.Now().UnixNano()))), nil)
	if _, err := a.VerifyCallCertificate(p, raw, outcomePolicy); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []CallCertificateOptions{{}, {MaxAge: -1}, {MaxAge: time.Minute, MaxFutureSkew: -1}} {
		if o, err := a.VerifyCallCertificate(p, raw, opts); o != nil || err == nil {
			t.Fatal("bad policy accepted")
		}
	}
	missing := outcomeWire(t, sk, hashtree.Pruned{1}, nil)
	if o, err := a.VerifyCallCertificate(p, missing, outcomePolicy); o != nil || err == nil {
		t.Fatal("missing time accepted")
	}
}

func TestCallOutcomeDelegation(t *testing.T) {
	a, p, rootSigner := outcomeFixture(t)
	subnetSigner, subnetKey := callCertificateSigner(t)
	subnet := principal.Principal{Raw: []byte{9, 1}}
	for _, sharded := range []bool{false, true} {
		for _, inRange := range []bool{false, true} {
			canister := p.CanisterID().Raw
			if !inRange {
				canister = []byte{255}
			}
			ranges := hashtree.Leaf(preparedMarshal(t, [][]any{{canister, canister}}))
			subnetFields := map[string]hashtree.Node{"public_key": hashtree.Leaf(subnetKey)}
			rootFields := map[string]hashtree.Node{"time": hashtree.Leaf(outcomeNat(uint64(outcomeNow.Add(-7 * 24 * time.Hour).UnixNano())))}
			if sharded {
				rootFields["canister_ranges"] = hashtree.Labeled{Label: subnet.Raw, Tree: hashtree.Labeled{Label: canister, Tree: ranges}}
			} else {
				subnetFields["canister_ranges"] = ranges
			}
			rootFields["subnet"] = hashtree.Labeled{Label: subnet.Raw, Tree: outcomeFields(subnetFields)}
			delegation := outcomeWire(t, rootSigner, outcomeFields(rootFields), nil)
			d := map[string]any{"subnet_id": subnet.Raw, "certificate": delegation}
			raw := outcomeWire(t, subnetSigner, outcomeTree(p.id, outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("done")}), outcomeNat(uint64(outcomeNow.UnixNano()))), d)
			o, err := a.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow)
			if inRange && (err != nil || o.Status() != CallStatusDone) {
				t.Fatalf("sharded=%t: %v", sharded, err)
			}
			if !inRange && (err == nil || o != nil) {
				t.Fatal("wrong canister range accepted")
			}
			var child map[string]any
			if err := cbor.Unmarshal(delegation, &child); err != nil {
				t.Fatal(err)
			}
			child["delegation"] = d
			d["certificate"] = preparedMarshal(t, child)
			nested := outcomeWire(t, subnetSigner, outcomeTree(p.id, hashtree.Empty{}, outcomeNat(uint64(outcomeNow.UnixNano()))), d)
			if o, err := a.verifyCallCertificateAt(p, nested, outcomePolicy, outcomeNow); o != nil || err == nil {
				t.Fatal("nested delegation accepted")
			}
		}
	}
}

func TestCallOutcomeDecodeBounds(t *testing.T) {
	a, p, sk := outcomeFixture(t)
	validTree := outcomeTree(p.id, outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("replied"), "reply": hashtree.Leaf("ok")}), outcomeNat(uint64(outcomeNow.UnixNano())))
	raw := outcomeWire(t, sk, validTree, nil)
	var wire map[string]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]cbor.RawMessage){
		"null tree":       func(m map[string]cbor.RawMessage) { m["tree"] = []byte{0xf6} },
		"empty tree":      func(m map[string]cbor.RawMessage) { m["tree"] = []byte{0x80} },
		"null blob":       func(m map[string]cbor.RawMessage) { m["tree"] = preparedMarshal(t, []any{3, nil}) },
		"array blob":      func(m map[string]cbor.RawMessage) { m["tree"] = preparedMarshal(t, []any{3, []any{1, 2}}) },
		"short pruned":    func(m map[string]cbor.RawMessage) { m["tree"] = preparedMarshal(t, []any{4, []byte{1}}) },
		"null delegation": func(m map[string]cbor.RawMessage) { m["delegation"] = []byte{0xf6} },
		"unknown field":   func(m map[string]cbor.RawMessage) { m["extra"] = []byte{0} },
		"short signature": func(m map[string]cbor.RawMessage) { m["signature"] = preparedMarshal(t, []byte{1}) },
		"case":            func(m map[string]cbor.RawMessage) { m["Tree"] = m["tree"]; delete(m, "tree") },
		"deep": func(m map[string]cbor.RawMessage) {
			var n hashtree.Node = hashtree.Empty{}
			for range 65 {
				n = hashtree.Labeled{Label: []byte("x"), Tree: n}
			}
			m["tree"] = preparedMarshal(t, hashtree.NewHashTree(n))
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := make(map[string]cbor.RawMessage)
			for k, v := range wire {
				m[k] = v
			}
			mutate(m)
			if o, err := a.verifyCallCertificateAt(p, preparedMarshal(t, m), outcomePolicy, outcomeNow); o != nil || !errors.Is(err, ErrInvalidCallCertificate) {
				t.Fatalf("bad encoding accepted: %v", err)
			}
		})
	}
	for _, bad := range [][]byte{nil, bytes.Repeat([]byte{0}, MaxCallCertificateBytes+1), append(bytes.Clone(raw), 0), append([]byte{0xd9, 0xd9, 0xf7, 0xd9, 0xd9, 0xf7}, raw...), {0xa2, 0x64, 't', 'r', 'e', 'e', 0x80, 0x64, 't', 'r', 'e', 'e', 0x80}} {
		if o, err := a.verifyCallCertificateAt(p, bad, outcomePolicy, outcomeNow); o != nil || err == nil {
			t.Fatal("bad raw accepted")
		}
	}
	if _, err := a.verifyCallCertificateAt(p, append([]byte{0xd9, 0xd9, 0xf7}, raw...), outcomePolicy, outcomeNow); err != nil {
		t.Fatal(err)
	}
	// CBOR integer encodings need not be shortest-form. Changing representation
	// of the Fork tag preserves the tree and its signature.
	nonminimal := make(map[string]cbor.RawMessage)
	for k, v := range wire {
		nonminimal[k] = v
	}
	if wire["tree"][0] != 0x83 || wire["tree"][1] != 1 {
		t.Fatal("fixture fork")
	}
	nonminimal["tree"] = append([]byte{0x83, 0x18, 1}, wire["tree"][2:]...)
	if _, err := a.verifyCallCertificateAt(p, preparedMarshal(t, nonminimal), outcomePolicy, outcomeNow); err != nil {
		t.Fatal(err)
	}
	for _, b := range []callTreeBudget{{nodes: 0, bytes: 100}, {nodes: 10, bytes: 1}} {
		if _, err := b.decode([]byte{0x81, 0}, 1); err == nil {
			t.Fatal("tree budget ignored")
		}
	}
	var tree hashtree.Node = hashtree.Empty{}
	for range 12 {
		tree = hashtree.Fork{LeftTree: tree, RightTree: tree}
	}
	budget := callTreeBudget{nodes: 4096, bytes: 64 << 20}
	if _, err := budget.decode(preparedMarshal(t, hashtree.NewHashTree(tree)), 1); err == nil {
		t.Fatal("wide tree accepted")
	}
	large := bytes.Repeat([]byte{42}, 2<<20)
	largeRaw := outcomeWire(t, sk, outcomeTree(p.id, outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("replied"), "reply": hashtree.Leaf(large)}), outcomeNat(uint64(outcomeNow.UnixNano()))), nil)
	o, err := a.verifyCallCertificateAt(p, largeRaw, outcomePolicy, outcomeNow)
	if err != nil {
		t.Fatal(err)
	}
	reply, _ := o.Reply()
	if !bytes.Equal(reply, large) {
		t.Fatal("large reply")
	}
	var amplified hashtree.Node = hashtree.Leaf(large)
	for range 40 {
		amplified = hashtree.Labeled{Label: []byte("x"), Tree: amplified}
	}
	budget = callTreeBudget{nodes: 4096, bytes: 64 << 20}
	if _, err := budget.decode(preparedMarshal(t, hashtree.NewHashTree(amplified)), 1); err == nil {
		t.Fatal("recursive byte budget ignored")
	}
}

func FuzzCallOutcome(f *testing.F) {
	a, p, sk := outcomeFixture(f)
	raw := outcomeWire(f, sk, outcomeTree(p.id, outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("replied"), "reply": hashtree.Leaf("ok")}), outcomeNat(uint64(outcomeNow.UnixNano()))), nil)
	f.Add(raw)
	f.Add([]byte{0xa0})
	f.Add([]byte{0x80})
	var seed map[string]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &seed); err != nil {
		f.Fatal(err)
	}
	seed["delegation"] = preparedMarshal(f, map[string]any{"subnet_id": []byte{1}, "certificate": raw})
	f.Add(preparedMarshal(f, seed))
	f.Fuzz(func(t *testing.T, raw []byte) {
		o, err := a.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow)
		if err != nil {
			if o != nil {
				t.Fatal("partial evidence")
			}
			return
		}
		if o.RequestID() != p.id || o.RootKeyHash() != sha256.Sum256(a.rootKey) || o.Status() == "" {
			t.Fatal("unbound evidence")
		}
	})
}

func BenchmarkCallOutcome(b *testing.B) {
	a, p, sk := outcomeFixture(b)
	raw := outcomeWire(b, sk, outcomeTree(p.id, outcomeFields(map[string]hashtree.Node{"status": hashtree.Leaf("replied"), "reply": hashtree.Leaf("DIDL\x00\x00")}), outcomeNat(uint64(outcomeNow.UnixNano()))), nil)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := a.verifyCallCertificateAt(p, raw, outcomePolicy, outcomeNow); err != nil {
			b.Fatal(err)
		}
	}
}
