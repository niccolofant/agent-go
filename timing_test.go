package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/certification/hashtree"
	"github.com/niccolofant/agent-go/principal"
)

func TestTimingConfigDefaultsAndOverrides(t *testing.T) {
	for _, tc := range []struct {
		name                                     string
		cfg                                      Config
		ingress, call, query, certificate, cache time.Duration
	}{
		{"defaults", Config{}, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute, 30 * time.Second},
		{"legacy inheritance", Config{IngressExpiry: 10 * time.Second}, 10 * time.Second, 10 * time.Second, 10 * time.Second, 10 * time.Second, 5 * time.Second},
		{"independent", Config{IngressExpiry: time.Second, CallTimeout: 2 * time.Second, QueryTimeout: 3 * time.Second, CertificateMaxAge: time.Minute}, time.Second, 2 * time.Second, 3 * time.Second, time.Minute, 30 * time.Second},
		{"call only", Config{CallTimeout: time.Second}, 5 * time.Minute, time.Second, 5 * time.Minute, 5 * time.Minute, 30 * time.Second},
		{"query only", Config{QueryTimeout: time.Second}, 5 * time.Minute, 5 * time.Minute, time.Second, 5 * time.Minute, 30 * time.Second},
		{"certificate only", Config{CertificateMaxAge: 4 * time.Second}, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute, 4 * time.Second, 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := New(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if a.ingressExpiry != tc.ingress || a.callTimeout != tc.call || a.queryTimeout != tc.query || a.certificateMaxAge != tc.certificate || a.queryVerificationCache.maxAge != tc.cache {
				t.Fatalf("limits = ingress %s call %s query %s certificate %s cache %s", a.ingressExpiry, a.callTimeout, a.queryTimeout, a.certificateMaxAge, a.queryVerificationCache.maxAge)
			}
			if a.readStateTimeout != 5*time.Second || a.timeout != 10*time.Second || a.delay != time.Second {
				t.Fatal("existing read_state/poll defaults changed")
			}
		})
	}
}

func TestTimingConfigRejectsNegativeBeforeNetwork(t *testing.T) {
	for _, cfg := range []Config{{CallTimeout: -1}, {QueryTimeout: -1}, {CertificateMaxAge: -1}} {
		cfg.FetchRootKey = true
		cfg.ClientConfig = []ClientOption{WithHttpClient(&http.Client{Transport: timingTransport(func(*http.Request) (*http.Response, error) {
			t.Error("invalid timing configuration reached transport")
			return nil, errors.New("unexpected request")
		})})}
		if a, err := New(cfg); err == nil || a != nil {
			t.Fatalf("New(%+v) = %v, %v", cfg, a, err)
		}
	}
}

func TestTimingHTTPDeadlines(t *testing.T) {
	for _, operation := range []string{"call", "query", "read_state", "subnet_read_state"} {
		for _, parent := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/own", true: "/parent"}[parent], func(t *testing.T) {
				ctx := context.Background()
				parentDeadline := time.Now().Add(time.Second)
				if parent {
					var cancel context.CancelFunc
					ctx, cancel = context.WithDeadline(ctx, parentDeadline)
					defer cancel()
				}
				budget := map[string]time.Duration{"call": 2 * time.Second, "query": 3 * time.Second, "read_state": 4 * time.Second, "subnet_read_state": 4 * time.Second}[operation]
				before := time.Now()
				calls := 0
				stop := errors.New("offline transport stopped")
				a, err := New(Config{
					IngressExpiry: 10 * time.Second, CallTimeout: 2 * time.Second, QueryTimeout: 3 * time.Second, ReadStateTimeout: 4 * time.Second,
					ClientConfig: []ClientOption{WithHttpClient(&http.Client{Transport: timingTransport(func(r *http.Request) (*http.Response, error) {
						calls++
						deadline, ok := r.Context().Deadline()
						if !ok {
							t.Fatal("missing HTTP deadline")
						}
						if parent {
							if !deadline.Equal(parentDeadline) {
								t.Fatalf("deadline %s, want parent %s", deadline, parentDeadline)
							}
						} else if deadline.Before(before.Add(budget)) || deadline.After(time.Now().Add(budget)) {
							t.Fatalf("deadline %s not based on %s budget", deadline, budget)
						}
						return nil, stop
					})})},
				})
				if err != nil {
					t.Fatal(err)
				}
				switch operation {
				case "call":
					_, err = a.call(ctx, principal.AnonymousID, nil)
				case "query":
					q, e := a.CreateRawAPIRequestWithOptions(RequestTypeQuery, principal.AnonymousID, "test", nil, RequestOptions{IngressExpiry: time.Now().Add(time.Minute)})
					if e != nil {
						t.Fatal(e)
					}
					_, err = q.QueryRawContext(ctx, true)
				case "read_state":
					_, err = a.readState(ctx, principal.AnonymousID, nil)
				case "subnet_read_state":
					_, err = a.ReadSubnetStateContext(ctx, principal.AnonymousID, nil)
				}
				if !errors.Is(err, stop) || calls != 1 {
					t.Fatalf("result %v, transport calls %d", err, calls)
				}
			})
		}
	}
}

func TestTimingCertificateAgeIndependentOfExpiry(t *testing.T) {
	signer, rootKey := callCertificateSigner(t)
	requestID := RequestID{91}
	reply := []byte("verified")
	old := marshalCertificate(t, signedCallCertificate(t, signer, requestID, reply, time.Now().Add(-time.Minute)))
	fresh := marshalCertificate(t, signedCallCertificate(t, signer, requestID, reply, time.Now()))
	for _, strict := range []bool{false, true} {
		for _, operation := range []string{"call", "read_state", "subnet_read_state"} {
			t.Run(operation+map[bool]string{false: "/short_expiry", true: "/strict_age"}[strict], func(t *testing.T) {
				expiry, age := time.Second, 2*time.Minute
				if strict {
					expiry, age = 5*time.Minute, 30*time.Second
				}
				polls := 0
				a, err := New(Config{
					IngressExpiry: expiry, CertificateMaxAge: age,
					ClientConfig: []ClientOption{WithHttpClient(&http.Client{Transport: timingTransport(func(r *http.Request) (*http.Response, error) {
						if hasPathSuffix(r.URL.Path, "/call") {
							return timingResponse(t, map[string]any{"status": "replied", "certificate": old}), nil
						}
						polls++
						cert := old
						if operation == "call" {
							cert = fresh
						}
						return timingResponse(t, map[string]any{"certificate": cert}), nil
					})})},
				})
				if err != nil {
					t.Fatal(err)
				}
				a.rootKey = rootKey
				switch operation {
				case "call":
					var out []byte
					err = callTestRequest(a, requestID).CallAndWait(&out)
					if err != nil || !bytes.Equal(out, reply) {
						t.Fatalf("call result %q, %v", out, err)
					}
					wantPolls := 0
					if strict {
						wantPolls = 1
					}
					if polls != wantPolls {
						t.Fatalf("polls %d, want %d", polls, wantPolls)
					}
				case "read_state", "subnet_read_state":
					paths := [][]hashtree.Label{{hashtree.Label("time")}}
					if operation == "read_state" {
						_, err = a.readStateCertificate(context.Background(), principal.AnonymousID, paths)
					} else {
						_, err = a.ReadSubnetStateCertificateContext(context.Background(), principal.AnonymousID, paths)
					}
					if strict && err == nil {
						t.Fatal("stale certificate accepted")
					}
					if !strict && err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestTimingCallTimeoutStillReconcilesSameRequest(t *testing.T) {
	signer, rootKey := callCertificateSigner(t)
	var requestID RequestID
	var calls, polls int
	a, err := New(Config{
		IngressExpiry: time.Minute, CallTimeout: time.Nanosecond, PollTimeout: time.Second,
		ClientConfig: []ClientOption{WithHttpClient(&http.Client{Transport: timingTransport(func(r *http.Request) (*http.Response, error) {
			if hasPathSuffix(r.URL.Path, "/call") {
				calls++
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
			polls++
			var envelope struct {
				Content struct {
					Paths [][][]byte `cbor:"paths"`
				} `cbor:"content"`
			}
			raw, e := io.ReadAll(r.Body)
			if e != nil {
				t.Fatal(e)
			}
			if e = cbor.Unmarshal(raw, &envelope); e != nil {
				t.Fatal(e)
			}
			paths := envelope.Content.Paths
			if len(paths) != 1 || len(paths[0]) != 2 || !bytes.Equal(paths[0][1], requestID[:]) {
				t.Fatal("poll did not retain original request ID")
			}
			cert := marshalCertificate(t, signedCallCertificate(t, signer, requestID, []byte("settled"), time.Now()))
			return timingResponse(t, map[string]any{"certificate": cert}), nil
		})})},
	})
	if err != nil {
		t.Fatal(err)
	}
	a.rootKey = rootKey
	req, err := a.CreateRawAPIRequestWithOptions(RequestTypeCall, principal.AnonymousID, "test", nil, RequestOptions{IngressExpiry: time.Now().Add(10 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	requestID = req.RequestID()
	var out []byte
	if err = req.CallAndWait(&out); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || polls != 1 || string(out) != "settled" {
		t.Fatalf("calls %d polls %d out %q", calls, polls, out)
	}
}

type timingTransport func(*http.Request) (*http.Response, error)

func TestTimingQueryVerificationMissSharesDeadline(t *testing.T) {
	stop := errors.New("offline verification lookup stopped")
	var queryDeadline time.Time
	reads := 0
	a, err := New(Config{
		IngressExpiry: time.Minute, QueryTimeout: 2 * time.Second, ReadStateTimeout: 5 * time.Second,
		ClientConfig: []ClientOption{WithHttpClient(&http.Client{Transport: timingTransport(func(r *http.Request) (*http.Response, error) {
			deadline, ok := r.Context().Deadline()
			if !ok {
				t.Fatal("missing deadline")
			}
			if hasPathSuffix(r.URL.Path, "/query") {
				queryDeadline = deadline
				return timingResponse(t, map[string]any{
					"status": "replied", "reply": map[string]any{"arg": []byte("reply")},
					"signatures": []any{map[string]any{"identity": principal.AnonymousID.Raw, "signature": []byte{1}, "timestamp": uint64(time.Now().UnixNano())}},
				}), nil
			}
			reads++
			if queryDeadline.IsZero() || !deadline.Equal(queryDeadline) {
				t.Fatal("verification lookup renewed query budget")
			}
			return nil, stop
		})})},
	})
	if err != nil {
		t.Fatal(err)
	}
	query, err := a.CreateRawAPIRequest(RequestTypeQuery, principal.AnonymousID, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = query.QueryRawContext(context.Background(), false)
	if !errors.Is(err, stop) || reads != 1 {
		t.Fatalf("verification error %v, reads %d", err, reads)
	}
}

func (f timingTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func timingResponse(t testing.TB, value any) *http.Response {
	t.Helper()
	raw, err := cbor.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}
}
