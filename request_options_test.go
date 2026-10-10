package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"math"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	candidcodec "github.com/niccolofant/agent-go/candid"
	"github.com/niccolofant/agent-go/identity"
	"github.com/niccolofant/agent-go/principal"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestRequestOptionsEnvelopeReuse(t *testing.T) {
	raw, err := cbor.Marshal(map[string]any{"status": "replied", "reply": map[string]any{"arg": []byte("reply")}})
	if err != nil {
		t.Fatal(err)
	}
	transport := &recordingQueryTransport{response: raw}
	a, err := New(Config{ClientConfig: []ClientOption{WithHttpClient(&http.Client{Transport: transport})}})
	if err != nil {
		t.Fatal(err)
	}
	opts := RequestOptions{IngressExpiry: time.Now().Add(time.Minute)}
	req, err := a.CreateRawAPIRequestWithOptions(RequestTypeQuery, principal.AnonymousID, "test", nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	id, expiry := req.RequestID(), req.IngressExpiry()
	opts.IngressExpiry = opts.IngressExpiry.Add(time.Hour)
	const fanout = 8
	var wg sync.WaitGroup
	for range fanout {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := req.QueryRawContext(context.Background(), true); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	bodies := transport.Bodies()
	if len(bodies) != fanout {
		t.Fatalf("requests = %d", len(bodies))
	}
	for _, body := range bodies {
		if !bytes.Equal(body, req.data) {
			t.Fatal("fanout did not reuse signed envelope")
		}
	}
	if req.RequestID() != id || req.IngressExpiry() != expiry {
		t.Fatal("request identity mutated on reuse")
	}
}

func TestRequestOptionsSignedExpiryAndConcurrency(t *testing.T) {
	id, err := identity.NewRandomEd25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{Identity: id, IngressExpiry: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	const n = 32
	expiry := time.Now().Add(10 * time.Second)
	var reqs [n]*RawAPIRequest
	var errs [n]error
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reqs[i], errs[i] = a.CreateRawAPIRequestWithOptions(RequestTypeCall, principal.AnonymousID, "test", []byte("input"), RequestOptions{IngressExpiry: expiry.Add(time.Duration(i % 2))})
		}()
	}
	wg.Wait()
	seen := make(map[RequestID]bool)
	for i, req := range reqs {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		want := uint64(expiry.Add(time.Duration(i % 2)).UnixNano())
		if req.IngressExpiry() != want {
			t.Fatalf("expiry %d, want %d", req.IngressExpiry(), want)
		}
		if seen[req.RequestID()] {
			t.Fatal("request identity reused across independently constructed requests")
		}
		seen[req.RequestID()] = true
		verifyOptionsEnvelope(t, req.data, req.RequestID(), want)
	}
	before := time.Now().Add(time.Minute).UnixNano()
	legacy, err := a.CreateRawAPIRequest(RequestTypeCall, principal.AnonymousID, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().Add(time.Minute).UnixNano()
	if legacy.IngressExpiry() < uint64(before) || legacy.IngressExpiry() > uint64(after) {
		t.Fatal("per-request option mutated agent default")
	}
}

func TestRequestOptionsConstructors(t *testing.T) {
	a, err := New(DefaultConfig)
	if err != nil {
		t.Fatal(err)
	}
	opts := RequestOptions{IngressExpiry: time.Now().Add(time.Minute)}
	management := principal.Principal{Raw: []byte{}}
	arg := struct {
		CanisterID principal.Principal `ic:"canister_id"`
	}{principal.AnonymousID}
	candid, err := a.CreateCandidAPIRequestWithOptions(RequestTypeCall, management, "canister_status", opts, arg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(candid.effectiveCanisterID.Raw, principal.AnonymousID.Raw) {
		t.Fatal("management routing lost")
	}
	if candid.IngressExpiry() != uint64(opts.IngressExpiry.UnixNano()) {
		t.Fatal("Candid expiry ignored")
	}
	args := []any{uint64(7), "two arguments"}
	wantArgs, err := candidcodec.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := a.CreateCandidAPIRequest(RequestTypeQuery, principal.AnonymousID, "test", args...)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := a.CreateCandidAPIRequestWithOptions(RequestTypeQuery, principal.AnonymousID, "test", opts, args...)
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []*CandidAPIRequest{legacy, explicit} {
		var envelope struct {
			Content struct {
				Arg []byte `cbor:"arg"`
			} `cbor:"content"`
		}
		if err := cbor.Unmarshal(req.data, &envelope); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(envelope.Content.Arg, wantArgs) {
			t.Fatal("Candid variadic arguments changed")
		}
	}
	proto, err := a.CreateProtoAPIRequestWithOptions(RequestTypeQuery, principal.AnonymousID, "test", &emptypb.Empty{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if proto.IngressExpiry() != uint64(opts.IngressExpiry.UnixNano()) {
		t.Fatal("Protobuf expiry ignored")
	}
	oldProto, err := a.CreateProtoAPIRequest(RequestTypeQuery, principal.AnonymousID, "test", &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if oldProto.IngressExpiry() <= proto.IngressExpiry() {
		t.Fatal("legacy protobuf default changed")
	}
}

func TestRequestOptionsRejectInvalidExpiry(t *testing.T) {
	id := &optionsCountingIdentity{Identity: new(identity.AnonymousIdentity)}
	a, err := New(Config{Identity: id})
	if err != nil {
		t.Fatal(err)
	}
	for _, expiry := range []time.Time{
		time.Now().Add(-time.Second), time.Unix(0, 0), time.Unix(0, -1),
		time.Unix(0, math.MaxInt64).Add(time.Nanosecond), time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2700, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		req, err := a.CreateRawAPIRequestWithOptions(RequestTypeCall, principal.AnonymousID, "test", nil, RequestOptions{IngressExpiry: expiry})
		if !errors.Is(err, ErrInvalidIngressExpiry) || req != nil {
			t.Fatalf("expiry %s: %v, %v", expiry, req, err)
		}
	}
	if id.signs != 0 {
		t.Fatal("invalid expiry reached signer")
	}
	// The client validates timestamp representation, not the network's TTL policy.
	if _, err := a.CreateRawAPIRequestWithOptions(RequestTypeCall, principal.AnonymousID, "test", nil, RequestOptions{IngressExpiry: time.Unix(0, math.MaxInt64)}); err != nil {
		t.Fatal(err)
	}
}

type optionsCountingIdentity struct {
	identity.Identity
	signs int
}

func (id *optionsCountingIdentity) Sign(msg []byte) ([]byte, error) {
	id.signs++
	return id.Identity.Sign(msg)
}

func TestRequestOptionsValidateAfterEncoding(t *testing.T) {
	a, err := New(DefaultConfig)
	if err != nil {
		t.Fatal(err)
	}
	opts := RequestOptions{IngressExpiry: time.Now().Add(20 * time.Millisecond)}
	encode := func([]byte) ([]byte, error) {
		time.Sleep(time.Until(opts.IngressExpiry) + time.Millisecond)
		return nil, nil
	}
	req, err := CreateAPIRequestWithOptions(a, encode, func([]byte, *[]byte) error { return nil }, RequestTypeCall, principal.AnonymousID, principal.AnonymousID, "test", []byte(nil), opts)
	if !errors.Is(err, ErrInvalidIngressExpiry) || req != nil {
		t.Fatalf("expired while encoding: %v, %v", req, err)
	}
	codecErr := errors.New("codec failed")
	_, err = CreateAPIRequestWithOptions(a, func([]byte) ([]byte, error) { return nil, codecErr }, func([]byte, *[]byte) error { return nil }, RequestTypeCall, principal.AnonymousID, principal.AnonymousID, "test", []byte(nil), RequestOptions{})
	if !errors.Is(err, codecErr) {
		t.Fatalf("encoding error = %v", err)
	}
}

func verifyOptionsEnvelope(t *testing.T, raw []byte, id RequestID, expiry uint64) {
	t.Helper()
	var envelope struct {
		Content struct {
			Type     RequestType `cbor:"request_type"`
			Sender   []byte      `cbor:"sender"`
			Canister []byte      `cbor:"canister_id"`
			Method   string      `cbor:"method_name"`
			Arg      []byte      `cbor:"arg"`
			Nonce    []byte      `cbor:"nonce"`
			Expiry   uint64      `cbor:"ingress_expiry"`
		} `cbor:"content"`
		PublicKey []byte `cbor:"sender_pubkey"`
		Signature []byte `cbor:"sender_sig"`
	}
	if err := cbor.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	c := envelope.Content
	if c.Expiry != expiry {
		t.Fatal("signed expiry differs from request getter")
	}
	got := NewRequestID(Request{Type: c.Type, Sender: principal.Principal{Raw: c.Sender}, CanisterID: principal.Principal{Raw: c.Canister}, MethodName: c.Method, Arguments: c.Arg, Nonce: c.Nonce, IngressExpiry: c.Expiry})
	if got != id {
		t.Fatal("request ID differs from signed envelope")
	}
	key, err := x509.ParsePKIXPublicKey(envelope.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key.(ed25519.PublicKey), append([]byte("\x0Aic-request"), id[:]...), envelope.Signature) {
		t.Fatal("bad request signature")
	}
}

func BenchmarkRequestOptionsExpiry(b *testing.B) {
	a, err := New(DefaultConfig)
	if err != nil {
		b.Fatal(err)
	}
	for _, explicit := range []bool{false, true} {
		b.Run(map[bool]string{false: "default", true: "explicit"}[explicit], func(b *testing.B) {
			opts := RequestOptions{}
			if explicit {
				opts.IngressExpiry = time.Now().Add(time.Hour)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := a.requestExpiry(opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
