package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/candid"
	"github.com/niccolofant/agent-go/identity"
	"github.com/niccolofant/agent-go/principal"
)

func TestPreparedQueryCanBeReusedConcurrently(t *testing.T) {
	rawArg, err := candid.Marshal([]any{uint64(42)})
	if err != nil {
		t.Fatal(err)
	}
	rawResponse, err := cbor.Marshal(map[string]any{
		"status": "replied",
		"reply":  map[string]any{"arg": rawArg},
	})
	if err != nil {
		t.Fatal(err)
	}

	const fanout = 16
	transport := &recordingQueryTransport{response: rawResponse}
	host, _ := url.Parse("https://ic0.app")
	a, err := New(Config{
		ClientConfig: []ClientOption{
			WithHostURL(host),
			WithHttpClient(&http.Client{Transport: transport}),
		},
		DisableSignedQueryVerification: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	query, err := a.PrepareQuery(principal.AnonymousID, "prepared", []any{uint64(7)})
	if err != nil {
		t.Fatal(err)
	}

	errs := make(chan error, fanout)
	var wg sync.WaitGroup
	wg.Add(fanout)
	for range fanout {
		go func() {
			defer wg.Done()
			var out uint64
			if err := query.QueryContext(context.Background(), []any{&out}, false); err != nil {
				errs <- err
				return
			}
			if out != 42 {
				errs <- fmt.Errorf("prepared query returned %d, want 42", out)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	bodies := transport.Bodies()
	if len(bodies) != fanout {
		t.Fatalf("requests = %d, want %d", len(bodies), fanout)
	}
	for i := 1; i < len(bodies); i++ {
		if !bytes.Equal(bodies[0], bodies[i]) {
			t.Fatalf("request %d did not reuse the prepared envelope", i)
		}
	}
}

func TestPreparedQueryRawDefersPayloadDecode(t *testing.T) {
	rawArg := []byte("deliberately not Candid")
	rawResponse, err := cbor.Marshal(map[string]any{
		"status": "replied",
		"reply":  map[string]any{"arg": rawArg},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := &recordingQueryTransport{response: rawResponse}
	host, _ := url.Parse("https://ic0.app")
	a, err := New(Config{
		ClientConfig: []ClientOption{
			WithHostURL(host),
			WithHttpClient(&http.Client{Transport: transport}),
		},
		DisableSignedQueryVerification: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	query, err := a.PrepareQuery(principal.AnonymousID, "prepared", nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := query.QueryRawContext(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, rawArg) {
		t.Fatalf("raw reply = %q, want %q", got, rawArg)
	}
}

func TestPreparedQueryRawReturnsBoundaryMetadata(t *testing.T) {
	rawArg := []byte("raw reply")
	rawResponse, err := cbor.Marshal(map[string]any{
		"status": "replied",
		"reply":  map[string]any{"arg": rawArg},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := &recordingQueryTransport{
		response: rawResponse,
		headers: http.Header{
			"X-Ic-Node-Id":             []string{"replica-node"},
			"X-Ic-Subnet-Id":           []string{"subnet-id"},
			"X-Ic-Cache-Status":        []string{"BYPASS"},
			"X-Ic-Cache-Bypass-Reason": []string{"nonce"},
			"X-Ic-Retries":             []string{"2"},
		},
	}
	host, _ := url.Parse("https://ic0.app")
	a, err := New(Config{
		ClientConfig: []ClientOption{
			WithHostURL(host),
			WithHttpClient(&http.Client{Transport: transport}),
		},
		DisableSignedQueryVerification: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	query, err := a.PrepareQuery(principal.AnonymousID, "prepared", nil)
	if err != nil {
		t.Fatal(err)
	}

	got, metadata, err := query.QueryRawContextWithMetadata(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, rawArg) {
		t.Fatalf("raw reply = %q, want %q", got, rawArg)
	}
	want := HTTPResponseMetadata{
		NodeID:            "replica-node",
		SubnetID:          "subnet-id",
		CacheStatus:       "BYPASS",
		CacheBypassReason: "nonce",
		Retries:           2,
	}
	if metadata != want {
		t.Fatalf("metadata = %+v, want %+v", metadata, want)
	}
}

var preparedQuerySink *CandidAPIRequest
var preparedQueryRawSink []byte
var preparedQueryMetadataSink HTTPResponseMetadata

func BenchmarkPrepareQuery(b *testing.B) {
	id, err := identity.NewRandomSecp256k1Identity()
	if err != nil {
		b.Fatal(err)
	}
	a, err := New(Config{Identity: id})
	if err != nil {
		b.Fatal(err)
	}
	in := []any{uint64(7)}

	for _, count := range []int{1, 10} {
		b.Run(fmt.Sprintf("fanout_%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				for range count {
					preparedQuerySink, err = a.PrepareQuery(principal.AnonymousID, "prepared", in)
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func BenchmarkPreparedQueryRawMetadata(b *testing.B) {
	rawResponse, err := cbor.Marshal(map[string]any{
		"status": "replied",
		"reply":  map[string]any{"arg": []byte("reply")},
	})
	if err != nil {
		b.Fatal(err)
	}
	transport := staticQueryTransport{
		response: rawResponse,
		headers: http.Header{
			"X-Ic-Node-Id":      []string{"replica-node"},
			"X-Ic-Subnet-Id":    []string{"subnet-id"},
			"X-Ic-Cache-Status": []string{"BYPASS"},
			"X-Ic-Retries":      []string{"0"},
		},
	}
	host, _ := url.Parse("https://ic0.app")
	a, err := New(Config{
		ClientConfig: []ClientOption{
			WithHostURL(host),
			WithHttpClient(&http.Client{Transport: transport}),
		},
		DisableSignedQueryVerification: true,
	})
	if err != nil {
		b.Fatal(err)
	}
	query, err := a.PrepareQuery(principal.AnonymousID, "prepared", nil)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("body_only", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			preparedQueryRawSink, err = query.QueryRawContext(context.Background(), false)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("with_metadata", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			preparedQueryRawSink, preparedQueryMetadataSink, err =
				query.QueryRawContextWithMetadata(context.Background(), false)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

type recordingQueryTransport struct {
	mu       sync.Mutex
	bodies   [][]byte
	response []byte
	headers  http.Header
}

type staticQueryTransport struct {
	response []byte
	headers  http.Header
}

func (t staticQueryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     t.headers,
		Body:       io.NopCloser(bytes.NewReader(t.response)),
		Request:    req,
	}, nil
}

func (t *recordingQueryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.bodies = append(t.bodies, append([]byte(nil), body...))
	t.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     t.headers.Clone(),
		Body:       io.NopCloser(bytes.NewReader(t.response)),
		Request:    req,
	}, nil
}

func (t *recordingQueryTransport) Bodies() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([][]byte(nil), t.bodies...)
}
