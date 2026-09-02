package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/niccolofant/agent-go/principal"
)

func TestAPIRequestExposesSignedIdentity(t *testing.T) {
	const ingressExpiry = 2 * time.Minute
	a, err := New(Config{IngressExpiry: ingressExpiry})
	if err != nil {
		t.Fatal(err)
	}

	before := uint64(time.Now().Add(ingressExpiry).UnixNano())
	req, err := a.CreateCandidAPIRequest(RequestTypeCall, principal.AnonymousID, "test")
	if err != nil {
		t.Fatal(err)
	}
	after := uint64(time.Now().Add(ingressExpiry).UnixNano())

	if got := req.RequestID(); got == (RequestID{}) {
		t.Fatal("RequestID returned the zero value")
	}
	if got := req.IngressExpiry(); got < before || got > after {
		t.Fatalf("IngressExpiry = %d, want [%d, %d]", got, before, after)
	}
	if req.RequestID() != req.RequestID() || req.IngressExpiry() != req.IngressExpiry() {
		t.Fatal("signed request identity changed between reads")
	}
}

func TestRequestStatusWithContextCancellation(t *testing.T) {
	a, err := New(DefaultConfig)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = a.RequestStatusWithContext(ctx, principal.AnonymousID, RequestID{1})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RequestStatusWithContext error = %v, want context.Canceled", err)
	}
}
