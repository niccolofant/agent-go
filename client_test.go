package agent_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go"
	"github.com/niccolofant/agent-go/principal"
)

func recordingClient(t *testing.T, opts ...agent.ClientOption) (agent.Client, *string) {
	t.Helper()
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		// Minimal replied-call response; ReadState returns the body verbatim.
		body, _ := cbor.Marshal(map[string]any{"status": "replied", "certificate": []byte{}})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	host, _ := url.Parse(srv.URL)
	c := agent.NewClient(append([]agent.ClientOption{agent.WithHostURL(host)}, opts...)...)
	return c, &gotPath
}

func TestClientCallDefaultsToV4(t *testing.T) {
	c, gotPath := recordingClient(t)
	cid := principal.MustDecode("aaaaa-aa")
	if _, err := c.Call(context.Background(), cid, nil); err != nil {
		t.Fatal(err)
	}
	want := "/api/v4/canister/" + cid.Encode() + "/call"
	if *gotPath != want {
		t.Fatalf("got %q, want %q", *gotPath, want)
	}
}

func TestClientReadStateDefaultsToV3(t *testing.T) {
	c, gotPath := recordingClient(t)
	cid := principal.MustDecode("aaaaa-aa")
	if _, err := c.ReadState(context.Background(), cid, nil); err != nil {
		t.Fatal(err)
	}
	want := "/api/v3/canister/" + cid.Encode() + "/read_state"
	if *gotPath != want {
		t.Fatalf("got %q, want %q", *gotPath, want)
	}
}

func TestClientQueryDefaultsToV3(t *testing.T) {
	c, gotPath := recordingClient(t)
	cid := principal.MustDecode("aaaaa-aa")
	if _, err := c.Query(context.Background(), cid, nil); err != nil {
		t.Fatal(err)
	}
	want := "/api/v3/canister/" + cid.Encode() + "/query"
	if *gotPath != want {
		t.Fatalf("got %q, want %q", *gotPath, want)
	}
}

func TestClientLegacyAPI(t *testing.T) {
	cid := principal.MustDecode("aaaaa-aa")

	cCall, callPath := recordingClient(t, agent.WithLegacyAPI())
	if _, err := cCall.Call(context.Background(), cid, nil); err != nil {
		t.Fatal(err)
	}
	if want := "/api/v3/canister/" + cid.Encode() + "/call"; *callPath != want {
		t.Fatalf("call: got %q, want %q", *callPath, want)
	}

	cRead, readPath := recordingClient(t, agent.WithLegacyAPI())
	if _, err := cRead.ReadState(context.Background(), cid, nil); err != nil {
		t.Fatal(err)
	}
	if want := "/api/v2/canister/" + cid.Encode() + "/read_state"; *readPath != want {
		t.Fatalf("read_state: got %q, want %q", *readPath, want)
	}

	cQuery, queryPath := recordingClient(t, agent.WithLegacyAPI())
	if _, err := cQuery.Query(context.Background(), cid, nil); err != nil {
		t.Fatal(err)
	}
	if want := "/api/v2/canister/" + cid.Encode() + "/query"; *queryPath != want {
		t.Fatalf("query: got %q, want %q", *queryPath, want)
	}
}

type throttledHTTPError interface {
	HTTPStatusCode() int
	RetryAfter() time.Duration
}

func TestQueryMetadataExposesRetryAfterAndStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3")
		http.Error(w, "busy", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	host, _ := url.Parse(srv.URL)
	c := agent.NewClient(agent.WithHostURL(host))
	cid := principal.MustDecode("aaaaa-aa")
	_, metadata, err := c.QueryWithMetadata(context.Background(), cid, nil)
	if err == nil {
		t.Fatal("429 query unexpectedly succeeded")
	}
	if metadata.StatusCode != http.StatusTooManyRequests || metadata.RetryAfter != 3*time.Second {
		t.Fatalf("metadata=%+v", metadata)
	}
	var throttled throttledHTTPError
	if !errors.As(err, &throttled) || throttled.HTTPStatusCode() != http.StatusTooManyRequests ||
		throttled.RetryAfter() != 3*time.Second {
		t.Fatalf("error=%T %v", err, err)
	}
}

func TestHTTPErrorCauseAcrossRequestPaths(t *testing.T) {
	cid := principal.MustDecode("aaaaa-aa")
	for _, path := range []string{"query", "query_metadata", "read_state", "subnet_read_state", "call"} {
		for _, cause := range []string{"no_healthy_nodes", "replica_error", "load_shed", "future_cause", ""} {
			t.Run(path+"/"+cause, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if cause != "" {
						w.Header().Set("X-Ic-Error-Cause", cause)
					}
					w.Header().Set("Retry-After", "3")
					http.Error(w, "error: deliberately_different_body", http.StatusServiceUnavailable)
				}))
				defer srv.Close()
				host, _ := url.Parse(srv.URL)
				client := agent.NewClient(agent.WithHostURL(host))
				var err error
				switch path {
				case "query":
					_, err = client.Query(context.Background(), cid, nil)
				case "query_metadata":
					_, _, err = client.QueryWithMetadata(context.Background(), cid, nil)
				case "read_state":
					_, err = client.ReadState(context.Background(), cid, nil)
				case "subnet_read_state":
					_, err = client.ReadSubnetState(context.Background(), cid, nil)
				case "call":
					_, err = client.Call(context.Background(), cid, nil)
				}
				var response interface {
					HTTPStatusCode() int
					RetryAfter() time.Duration
					HTTPErrorCause() string
				}
				if err == nil || !errors.As(fmt.Errorf("request: %w", err), &response) {
					t.Fatalf("missing structured HTTP error: %T %v", err, err)
				}
				if response.HTTPStatusCode() != http.StatusServiceUnavailable || response.RetryAfter() != 3*time.Second || response.HTTPErrorCause() != cause {
					t.Fatalf("status=%d retry=%v cause=%q", response.HTTPStatusCode(), response.RetryAfter(), response.HTTPErrorCause())
				}
				want := "(503) 503 Service Unavailable: error: deliberately_different_body\n"
				if err.Error() != want {
					t.Fatalf("error text changed: got %q, want %q", err.Error(), want)
				}
			})
		}
	}
}
