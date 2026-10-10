package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/identity"
	"github.com/niccolofant/agent-go/principal"
)

type preparedCountingIdentity struct {
	identity.Identity
	signs atomic.Int64
}

func (i *preparedCountingIdentity) Sign(msg []byte) ([]byte, error) {
	i.signs.Add(1)
	return i.Identity.Sign(msg)
}

func preparedIdentity(tb testing.TB, seed byte) identity.Identity {
	tb.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	id, err := identity.NewEd25519Identity(key.Public().(ed25519.PublicKey), key)
	if err != nil {
		tb.Fatal(err)
	}
	return id
}

func preparedAgent(tb testing.TB, id identity.Identity) *Agent {
	tb.Helper()
	a, err := New(Config{Identity: id, ClientConfig: []ClientOption{WithHttpClient(&http.Client{
		Transport: timingTransport(func(*http.Request) (*http.Response, error) {
			tb.Error("prepared call reached network")
			return nil, errors.New("network forbidden")
		}),
	})}})
	if err != nil {
		tb.Fatal(err)
	}
	return a
}

func preparedFixture(tb testing.TB, a *Agent) (Request, RequestID, []byte) {
	tb.Helper()
	// An expired request remains recoverable without minting a new identity.
	req := Request{Type: RequestTypeCall, Sender: a.Sender(),
		CanisterID: principal.MustDecode("ryjl3-tyaaa-aaaaa-aaaba-cai"),
		MethodName: "swap", Arguments: []byte("DIDL\x00\x00"), IngressExpiry: 1, Nonce: []byte{7, 8}}
	id, raw, err := a.sign(req)
	if err != nil {
		tb.Fatal(err)
	}
	return req, *id, raw
}

func preparedMarshal(tb testing.TB, v any) []byte {
	tb.Helper()
	raw, err := cbor.Marshal(v)
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

func preparedMap(tb testing.TB, raw []byte) (map[string]any, map[string]any) {
	tb.Helper()
	var env map[string]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &env); err != nil {
		tb.Fatal(err)
	}
	var content map[string]any
	if err := cbor.Unmarshal(env["content"], &content); err != nil {
		tb.Fatal(err)
	}
	return map[string]any{"content": content, "sender_pubkey": env["sender_pubkey"], "sender_sig": env["sender_sig"]}, content
}

func TestPreparedCallIdentitiesAndOwnership(t *testing.T) {
	p256, err := identity.NewRandomPrime256v1Identity()
	if err != nil {
		t.Fatal(err)
	}
	secp, err := identity.NewRandomSecp256k1Identity()
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]identity.Identity{"ed25519": preparedIdentity(t, 1), "p256": p256, "secp256k1": secp} {
		t.Run(name, func(t *testing.T) {
			counter := &preparedCountingIdentity{Identity: id}
			a := preparedAgent(t, counter)
			req, wantID, raw := preparedFixture(t, a)
			original := bytes.Clone(raw)
			p, err := a.RestorePreparedCall(raw)
			if err != nil {
				t.Fatal(err)
			}
			if p.RequestID() != wantID || p.IngressExpiry() != 1 || p.MethodName() != req.MethodName ||
				!p.Sender().Equal(req.Sender) || !p.CanisterID().Equal(req.CanisterID) ||
				!bytes.Equal(p.Arguments(), req.Arguments) || !bytes.Equal(p.Envelope(), original) ||
				p.RootKeyHash() != sha256.Sum256(a.GetRootKey()) {
				t.Fatal("restored metadata differs")
			}
			for i := range raw {
				raw[i] ^= 0xff
			}
			for _, b := range [][]byte{p.Envelope(), p.Sender().Raw, p.CanisterID().Raw, p.Arguments()} {
				b[0] ^= 1
			}
			if !bytes.Equal(p.Envelope(), original) || !p.Sender().Equal(req.Sender) || !p.CanisterID().Equal(req.CanisterID) || !bytes.Equal(p.Arguments(), req.Arguments) {
				t.Fatal("snapshot has a mutable alias")
			}
			other := preparedAgent(t, counter)
			other.rootKey = []byte("different configured trust root")
			restored, err := other.RestorePreparedCall(p.Envelope())
			if err != nil || restored.RequestID() != wantID || restored.RootKeyHash() == p.RootKeyHash() {
				t.Fatalf("local trust context: %v", err)
			}
			if counter.signs.Load() != 1 {
				t.Fatal("recovery signed a replacement")
			}
			for _, n := range []int{0, 1, 31, 32, 63, 65, 128} {
				env, _ := preparedMap(t, original)
				env["sender_sig"] = make([]byte, n)
				if _, err := a.RestorePreparedCall(preparedMarshal(t, env)); !errors.Is(err, ErrInvalidPreparedCall) {
					t.Fatalf("signature length %d: %v", n, err)
				}
			}
		})
	}
}

func TestPreparedCallExport(t *testing.T) {
	i := &preparedCountingIdentity{Identity: preparedIdentity(t, 1)}
	a := preparedAgent(t, i)
	c, err := a.CreateRawAPIRequest(RequestTypeCall, principal.MustDecode("ryjl3-tyaaa-aaaaa-aaaba-cai"), "swap", []byte{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.ExportCall()
	if err != nil || p.RequestID() != c.RequestID() || p.IngressExpiry() != c.IngressExpiry() || !bytes.Equal(p.Envelope(), c.data) {
		t.Fatalf("export: %v", err)
	}
	for name, change := range map[string]func(*RawAPIRequest){
		"type":    func(c *RawAPIRequest) { c.typ = RequestTypeQuery },
		"id":      func(c *RawAPIRequest) { c.requestID[0] ^= 1 },
		"expiry":  func(c *RawAPIRequest) { c.ingressExpiry++ },
		"method":  func(c *RawAPIRequest) { c.methodName = "other" },
		"routing": func(c *RawAPIRequest) { c.WithEffectiveCanisterID(principal.AnonymousID) },
		"agent":   func(c *RawAPIRequest) { c.a = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *c
			change(&changed)
			if _, err := changed.ExportCall(); !errors.Is(err, ErrInvalidPreparedCall) {
				t.Fatal(err)
			}
		})
	}
	if i.signs.Load() != 1 {
		t.Fatal("export signed again")
	}
}

func TestPreparedCallExportRejectsUnsupportedConstructors(t *testing.T) {
	a := preparedAgent(t, preparedIdentity(t, 1))
	anon := preparedAgent(t, identity.AnonymousIdentity{})
	canister := principal.MustDecode("ryjl3-tyaaa-aaaaa-aaaba-cai")
	for _, tc := range []struct {
		name     string
		a        *Agent
		typ      RequestType
		canister principal.Principal
	}{
		{"anonymous", anon, RequestTypeCall, canister},
		{"management", a, RequestTypeCall, principal.Principal{Raw: []byte{}}},
		{"query", a, RequestTypeQuery, canister},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := tc.a.CreateRawAPIRequest(tc.typ, tc.canister, "swap", []byte{})
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "management" {
				r.WithEffectiveCanisterID(canister)
			}
			if p, err := r.ExportCall(); p != nil || !errors.Is(err, ErrInvalidPreparedCall) {
				t.Fatalf("unsupported export: %v", err)
			}
		})
	}
}

func TestPreparedCallRejectsWireAndSignatureMutations(t *testing.T) {
	a := preparedAgent(t, preparedIdentity(t, 1))
	_, _, raw := preparedFixture(t, a)
	mutations := map[string]func(map[string]any, map[string]any){
		"type":             func(_, c map[string]any) { c["request_type"] = "query" },
		"sender":           func(_, c map[string]any) { c["sender"] = principal.AnonymousID.Raw },
		"key":              func(e, _ map[string]any) { e["sender_pubkey"] = preparedIdentity(t, 2).PublicKey() },
		"signature":        func(e, _ map[string]any) { e["sender_sig"] = make([]byte, 64) },
		"argument":         func(_, c map[string]any) { c["arg"] = []byte("changed") },
		"method":           func(_, c map[string]any) { c["method_name"] = "withdraw" },
		"canister":         func(_, c map[string]any) { c["canister_id"] = []byte{1} },
		"expiry":           func(_, c map[string]any) { c["ingress_expiry"] = uint64(2) },
		"nonce":            func(_, c map[string]any) { c["nonce"] = []byte{1} },
		"float expiry":     func(_, c map[string]any) { c["ingress_expiry"] = float64(1) },
		"negative expiry":  func(_, c map[string]any) { c["ingress_expiry"] = int64(-1) },
		"oversized expiry": func(_, c map[string]any) { c["ingress_expiry"] = uint64(math.MaxUint64) },
		"null expiry":      func(_, c map[string]any) { c["ingress_expiry"] = nil },
		"zero expiry":      func(_, c map[string]any) { c["ingress_expiry"] = 0 },
		"long nonce":       func(_, c map[string]any) { c["nonce"] = make([]byte, 33) },
		"empty nonce":      func(_, c map[string]any) { c["nonce"] = []byte{} },
		"null nonce":       func(_, c map[string]any) { c["nonce"] = nil },
		"array nonce":      func(_, c map[string]any) { c["nonce"] = []uint64{7, 8} },
		"unknown":          func(_, c map[string]any) { c["unknown"] = 1 },
		"paths":            func(_, c map[string]any) { c["paths"] = []any{} },
		"case alias":       func(_, c map[string]any) { c["METHOD_NAME"] = c["method_name"]; delete(c, "method_name") },
		"outer unknown":    func(e, _ map[string]any) { e["unknown"] = 1 },
		"delegation":       func(e, _ map[string]any) { e["sender_delegation"] = []any{} },
		"tagged args":      func(_, c map[string]any) { c["arg"] = cbor.Tag{Number: 55799, Content: c["arg"]} },
	}
	for _, field := range []string{"sender", "canister_id", "arg", "request_type", "method_name", "ingress_expiry"} {
		mutations["missing "+field] = func(_, c map[string]any) { delete(c, field) }
	}
	for _, field := range []string{"sender", "canister_id", "arg", "sender_pubkey", "sender_sig"} {
		for _, array := range []bool{false, true} {
			name := "null " + field
			if array {
				name = "array " + field
			}
			mutations[name] = func(e, c map[string]any) {
				m := c
				if field == "sender_pubkey" || field == "sender_sig" {
					m = e
				}
				if !array {
					m[field] = nil
					return
				}
				var blob []byte
				if err := cbor.Unmarshal(preparedMarshal(t, m[field]), &blob); err != nil {
					t.Fatal(err)
				}
				ints := make([]uint64, len(blob))
				for i, b := range blob {
					ints[i] = uint64(b)
				}
				m[field] = ints
			}
		}
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e, c := preparedMap(t, raw)
			mutate(e, c)
			if p, err := a.RestorePreparedCall(preparedMarshal(t, e)); p != nil || !errors.Is(err, ErrInvalidPreparedCall) {
				t.Fatalf("accepted mutation: %v", err)
			}
		})
	}
	wrong := preparedAgent(t, preparedIdentity(t, 2))
	if _, err := wrong.RestorePreparedCall(raw); !errors.Is(err, ErrInvalidPreparedCall) {
		t.Fatal("wrong identity accepted")
	}
}

func TestPreparedCallUnsupportedSignedRequests(t *testing.T) {
	a := preparedAgent(t, preparedIdentity(t, 1))
	base, _, _ := preparedFixture(t, a)
	for name, mutate := range map[string]func(*Request){
		"foreign sender":        func(r *Request) { r.Sender = preparedIdentity(t, 2).Sender() },
		"anonymous sender":      func(r *Request) { r.Sender = principal.AnonymousID },
		"missing type":          func(r *Request) { r.Type = "" },
		"missing canister":      func(r *Request) { r.CanisterID.Raw = nil },
		"missing expiry":        func(r *Request) { r.IngressExpiry = 0 },
		"expiry above int64":    func(r *Request) { r.IngressExpiry = math.MaxInt64 + 1 },
		"long nonce":            func(r *Request) { r.Nonce = make([]byte, 33) },
		"unicode method":        func(r *Request) { r.MethodName = "\u00e9" },
		"DEL method":            func(r *Request) { r.MethodName = "\x7f" },
		"query":                 func(r *Request) { r.Type = RequestTypeQuery },
		"management":            func(r *Request) { r.CanisterID.Raw = []byte{} },
		"anonymous destination": func(r *Request) { r.CanisterID = principal.AnonymousID },
		"long destination":      func(r *Request) { r.CanisterID.Raw = make([]byte, 30) },
		"missing args":          func(r *Request) { r.Arguments = nil },
		"empty method":          func(r *Request) { r.MethodName = "" },
		"long method":           func(r *Request) { r.MethodName = strings.Repeat("a", 129) },
		"non ASCII method":      func(r *Request) { r.MethodName = "\xff" },
		"space method":          func(r *Request) { r.MethodName = "a b" },
	} {
		t.Run(name, func(t *testing.T) {
			r := base
			mutate(&r)
			_, raw, err := a.sign(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = a.RestorePreparedCall(raw); !errors.Is(err, ErrInvalidPreparedCall) || strings.HasSuffix(err.Error(), ": signature") {
				t.Fatal("unsupported request accepted")
			}
		})
	}
	for _, nonce := range [][]byte{nil, {1}, make([]byte, 32)} {
		r := base
		r.Nonce = nonce
		r.Arguments = []byte{}
		id, raw, err := a.sign(r)
		if err != nil {
			t.Fatal(err)
		}
		p, err := a.RestorePreparedCall(raw)
		if err != nil || p.RequestID() != *id {
			t.Fatalf("valid optional nonce: %v", err)
		}
	}
	anon := preparedAgent(t, identity.AnonymousIdentity{})
	_, _, raw := preparedFixture(t, anon)
	if _, err := anon.RestorePreparedCall(raw); !errors.Is(err, ErrInvalidPreparedCall) {
		t.Fatal("anonymous call accepted")
	}
}

func TestPreparedCallWireAmbiguitiesWithValidSignature(t *testing.T) {
	a := preparedAgent(t, preparedIdentity(t, 1))
	base, _, _ := preparedFixture(t, a)
	base.Nonce = nil
	noExpiry, noMethod, noArg := base, base, base
	noExpiry.IngressExpiry, noMethod.MethodName, noArg.Arguments = 0, "", nil
	for name, tc := range map[string]struct {
		req  Request
		wire func(map[any]any)
	}{
		"control":         {base, func(map[any]any) {}},
		"empty nonce":     {base, func(m map[any]any) { m["nonce"] = []byte{} }},
		"null nonce":      {base, func(m map[any]any) { m["nonce"] = nil }},
		"zero expiry":     {noExpiry, func(m map[any]any) { m["ingress_expiry"] = uint64(0) }},
		"null expiry":     {noExpiry, func(m map[any]any) { m["ingress_expiry"] = nil }},
		"empty method":    {noMethod, func(m map[any]any) { m["method_name"] = "" }},
		"null arg":        {noArg, func(m map[any]any) { m["arg"] = nil }},
		"bytes method":    {base, func(m map[any]any) { m["method_name"] = []byte(base.MethodName) }},
		"bytes type":      {base, func(m map[any]any) { m["request_type"] = []byte("call") }},
		"text arg":        {base, func(m map[any]any) { m["arg"] = string(base.Arguments) }},
		"byte-string key": {base, func(m map[any]any) { m[[3]byte{'a', 'r', 'g'}] = m["arg"]; delete(m, "arg") }},
	} {
		t.Run(name, func(t *testing.T) {
			content := map[any]any{"request_type": base.Type, "sender": base.Sender.Raw, "canister_id": base.CanisterID.Raw,
				"method_name": base.MethodName, "arg": base.Arguments, "ingress_expiry": base.IngressExpiry}
			tc.wire(content)
			sig, err := NewRequestID(tc.req).Sign(a.identity)
			if err != nil {
				t.Fatal(err)
			}
			raw := preparedMarshal(t, map[string]any{"content": content, "sender_pubkey": a.senderPubKey, "sender_sig": sig})
			p, err := a.RestorePreparedCall(raw)
			if name == "control" {
				if err != nil || p.RequestID() != NewRequestID(base) {
					t.Fatalf("invalid control: %v", err)
				}
			} else if p != nil || !errors.Is(err, ErrInvalidPreparedCall) || strings.HasSuffix(err.Error(), ": signature") {
				t.Fatalf("guard bypassed or not reached: %v", err)
			}
		})
	}
}

func TestPreparedCallPositiveBoundariesAndEquivalentEncodings(t *testing.T) {
	a := preparedAgent(t, preparedIdentity(t, 1))
	r, _, _ := preparedFixture(t, a)
	r.MethodName = strings.Repeat("a", 128)
	r.CanisterID.Raw = bytes.Repeat([]byte{1}, 29)
	r.IngressExpiry = math.MaxInt64
	r.Nonce = make([]byte, 32)
	r.Arguments = make([]byte, MaxPreparedCallBytes-1024)
	id, raw, err := a.sign(r)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.RestorePreparedCall(raw)
	if err != nil || p.RequestID() != *id || *id != referenceRequestID(r) {
		t.Fatalf("boundaries: %v", err)
	}
	e, _ := preparedMap(t, raw)
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := em.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	q, err := a.RestorePreparedCall(canonical)
	if err != nil || q.RequestID() != p.RequestID() || !bytes.Equal(q.Envelope(), canonical) {
		t.Fatalf("canonical roundtrip: %v", err)
	}
}

func TestPreparedCallP256EquivalentSignatureSameIdentity(t *testing.T) {
	id, err := identity.NewRandomPrime256v1Identity()
	if err != nil {
		t.Fatal(err)
	}
	a := preparedAgent(t, id)
	_, want, raw := preparedFixture(t, a)
	env, _ := preparedMap(t, raw)
	var sig []byte
	if err := cbor.Unmarshal(env["sender_sig"].(cbor.RawMessage), &sig); err != nil {
		t.Fatal(err)
	}
	s := new(big.Int).SetBytes(sig[32:])
	s.Sub(elliptic.P256().Params().N, s).FillBytes(sig[32:])
	env["sender_sig"] = sig
	reencoded := preparedMarshal(t, env)
	p, err := a.RestorePreparedCall(reencoded)
	if err != nil || p.RequestID() != want || !bytes.Equal(p.Envelope(), reencoded) {
		t.Fatalf("equivalent signature: %v", err)
	}
}

func TestPreparedCallCBORFraming(t *testing.T) {
	a := preparedAgent(t, preparedIdentity(t, 1))
	_, id, raw := preparedFixture(t, a)
	tagged := append([]byte{0xd9, 0xd9, 0xf7}, raw...)
	p, err := a.RestorePreparedCall(tagged)
	if err != nil || p.RequestID() != id || !bytes.Equal(p.Envelope(), tagged) {
		t.Fatalf("tagged envelope: %v", err)
	}
	e, c := preparedMap(t, raw)
	dup := append([]byte(nil), raw...)
	dup[0]++
	dup = append(dup, preparedMarshal(t, "sender_sig")...)
	dup = append(dup, preparedMarshal(t, e["sender_sig"])...)
	content := preparedMarshal(t, c)
	content[0]++
	content = append(content, preparedMarshal(t, "nonce")...)
	content = append(content, preparedMarshal(t, c["nonce"])...)
	e["content"] = cbor.RawMessage(content)
	indef := append([]byte{0xbf}, raw[1:]...)
	indef = append(indef, 0xff)
	for name, bad := range map[string][]byte{
		"empty": nil, "truncated": raw[:len(raw)-1], "trailing": append(bytes.Clone(raw), 0),
		"duplicate outer": dup, "duplicate content": preparedMarshal(t, e),
		"double tag": append([]byte{0xd9, 0xd9, 0xf7}, tagged...), "indefinite": indef,
		"oversized":        make([]byte, MaxPreparedCallBytes+1),
		"huge map header":  {0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"huge blob header": {0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			if p, err := a.RestorePreparedCall(bad); p != nil || !errors.Is(err, ErrInvalidPreparedCall) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

func TestPreparedCallConcurrentRecovery(t *testing.T) {
	i := &preparedCountingIdentity{Identity: preparedIdentity(t, 1)}
	a := preparedAgent(t, i)
	_, id, raw := preparedFixture(t, a)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 10 {
				p, err := a.RestorePreparedCall(raw)
				if err != nil || p.RequestID() != id || !bytes.Equal(p.Envelope(), raw) {
					t.Errorf("concurrent recovery: %v", err)
				}
			}
		})
	}
	wg.Wait()
	if i.signs.Load() != 1 {
		t.Fatal("re-signed during recovery")
	}
}

func FuzzPreparedCallRestore(f *testing.F) {
	a := preparedAgent(f, preparedIdentity(f, 1))
	_, _, seed := preparedFixture(f, a)
	f.Add(seed)
	f.Add([]byte{0xa0})
	f.Add(append([]byte{0xd9, 0xd9, 0xf7}, seed...))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := a.RestorePreparedCall(raw)
		if err != nil {
			if p != nil || !errors.Is(err, ErrInvalidPreparedCall) {
				t.Fatalf("invalid result: %v", err)
			}
			return
		}
		if !bytes.Equal(p.Envelope(), raw) || !p.Sender().Equal(a.Sender()) || p.IngressExpiry() == 0 {
			t.Fatal("bad authenticated result")
		}
		q, err := a.RestorePreparedCall(p.Envelope())
		if err != nil || q.RequestID() != p.RequestID() {
			t.Fatalf("unstable recovery: %v", err)
		}
	})
}

func BenchmarkPreparedCallRestore(b *testing.B) {
	a := preparedAgent(b, preparedIdentity(b, 1))
	_, _, raw := preparedFixture(b, a)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := a.RestorePreparedCall(raw); err != nil {
			b.Fatal(err)
		}
	}
}
