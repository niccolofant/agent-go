package agent

import (
	"context"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/certification"
	"github.com/niccolofant/agent-go/certification/bls"
	"github.com/niccolofant/agent-go/certification/hashtree"
	"github.com/niccolofant/agent-go/leb128"
	"github.com/niccolofant/agent-go/principal"
)

func TestCallAndWaitV4UsesVerifiedCertificate(t *testing.T) {
	requestID := RequestID{1, 2, 3}
	reply := []byte("verified reply")
	signer, rootKey := callCertificateSigner(t)
	certificate := signedCallCertificate(t, signer, requestID, reply, time.Now())
	rawCertificate := marshalCertificate(t, certificate)

	var polls atomic.Int32
	a := callTestAgent(t, rootKey, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case hasPathSuffix(r.URL.Path, "/call"):
			writeCBOR(t, w, map[string]any{"status": "replied", "certificate": rawCertificate})
		case hasPathSuffix(r.URL.Path, "/read_state"):
			polls.Add(1)
			http.Error(w, "unexpected poll", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	})

	var got []byte
	request := callTestRequest(a, requestID)
	if err := request.CallAndWaitWithContext(context.Background(), &got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(reply) {
		t.Fatalf("reply = %q, want %q", got, reply)
	}
	if got := polls.Load(); got != 0 {
		t.Fatalf("read_state polls = %d, want 0", got)
	}
}

func TestCallAndWaitV4InvalidCertificateFallsBackToPoll(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*certification.Certificate)
	}{
		{
			name: "bad signature",
			mutate: func(c *certification.Certificate) {
				c.Signature = append([]byte(nil), c.Signature...)
				c.Signature[0] ^= 0xff
			},
		},
		{
			name: "stale",
			mutate: func(c *certification.Certificate) {
				// The stale certificate is built separately below because changing
				// its certified time after signing would only test the signature.
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requestID := RequestID{4, 5, 6}
			reply := []byte("polled reply")
			signer, rootKey := callCertificateSigner(t)
			valid := signedCallCertificate(t, signer, requestID, reply, time.Now())
			invalid := valid
			if tc.name == "stale" {
				invalid = signedCallCertificate(t, signer, requestID, reply, time.Now().Add(-time.Hour))
			} else {
				tc.mutate(&invalid)
			}

			invalidRaw := marshalCertificate(t, invalid)
			validRaw := marshalCertificate(t, valid)
			var polls atomic.Int32
			a := callTestAgent(t, rootKey, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case hasPathSuffix(r.URL.Path, "/call"):
					writeCBOR(t, w, map[string]any{"status": "replied", "certificate": invalidRaw})
				case hasPathSuffix(r.URL.Path, "/read_state"):
					polls.Add(1)
					writeCBOR(t, w, map[string]any{"certificate": validRaw})
				default:
					http.NotFound(w, r)
				}
			})

			var got []byte
			request := callTestRequest(a, requestID)
			if err := request.CallAndWaitWithContext(context.Background(), &got); err != nil {
				t.Fatal(err)
			}
			if string(got) != string(reply) {
				t.Fatalf("reply = %q, want %q", got, reply)
			}
			if got := polls.Load(); got != 1 {
				t.Fatalf("read_state polls = %d, want 1", got)
			}
		})
	}
}

func TestCallAndWaitRetriesTransientReadStateFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first func(http.ResponseWriter, *http.Request)
	}{
		{
			name: "deadline exceeded",
			first: func(_ http.ResponseWriter, _ *http.Request) {
				time.Sleep(50 * time.Millisecond)
			},
		},
		{
			name: "unexpected EOF",
			first: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "128")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte{0xa1})
			},
		},
		{
			name: "service unavailable",
			first: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "try another boundary node", http.StatusServiceUnavailable)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requestID := RequestID{10, 11, 12}
			reply := []byte("polled after retry")
			signer, rootKey := callCertificateSigner(t)
			certificate := signedCallCertificate(t, signer, requestID, reply, time.Now())
			rawCertificate := marshalCertificate(t, certificate)

			var calls atomic.Int32
			var polls atomic.Int32
			a := callTestAgent(t, rootKey, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case hasPathSuffix(r.URL.Path, "/call"):
					calls.Add(1)
					w.WriteHeader(http.StatusAccepted)
				case hasPathSuffix(r.URL.Path, "/read_state"):
					if polls.Add(1) == 1 {
						tc.first(w, r)
						return
					}
					writeCBOR(t, w, map[string]any{"certificate": rawCertificate})
				default:
					http.NotFound(w, r)
				}
			})
			a.readStateTimeout = 20 * time.Millisecond

			var got []byte
			request := callTestRequest(a, requestID)
			if err := request.CallAndWaitWithContext(context.Background(), &got); err != nil {
				t.Fatal(err)
			}
			if string(got) != string(reply) {
				t.Fatalf("reply = %q, want %q", got, reply)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("update submissions = %d, want 1", got)
			}
			if got := polls.Load(); got != 2 {
				t.Fatalf("read_state polls = %d, want 2", got)
			}
		})
	}
}

func TestCallAndWaitTransientReadStateFailuresRespectPollBudget(t *testing.T) {
	requestID := RequestID{13, 14, 15}
	var calls atomic.Int32
	var polls atomic.Int32
	a := callTestAgent(t, nil, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case hasPathSuffix(r.URL.Path, "/call"):
			calls.Add(1)
			w.WriteHeader(http.StatusAccepted)
		case hasPathSuffix(r.URL.Path, "/read_state"):
			polls.Add(1)
			time.Sleep(30 * time.Millisecond)
		default:
			http.NotFound(w, r)
		}
	})
	a.readStateTimeout = 15 * time.Millisecond
	a.timeout = 75 * time.Millisecond
	a.delay = time.Millisecond

	started := time.Now()
	err := callTestRequest(a, requestID).CallAndWaitWithContext(context.Background(), new([]byte))
	if err == nil || !strings.Contains(err.Error(), "out of time") {
		t.Fatalf("error = %v, want poll timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("poll returned after %v, want bounded by overall budget", elapsed)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("update submissions = %d, want 1", got)
	}
	if got := polls.Load(); got < 2 {
		t.Fatalf("read_state polls = %d, want at least 2", got)
	}
}

func TestCallAndWaitDoesNotRetryNonTransientReadStateFailure(t *testing.T) {
	requestID := RequestID{16, 17, 18}
	var polls atomic.Int32
	a := callTestAgent(t, nil, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case hasPathSuffix(r.URL.Path, "/call"):
			w.WriteHeader(http.StatusAccepted)
		case hasPathSuffix(r.URL.Path, "/read_state"):
			polls.Add(1)
			http.Error(w, "invalid request", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	})

	err := callTestRequest(a, requestID).CallAndWaitWithContext(context.Background(), new([]byte))
	if err == nil || !strings.Contains(err.Error(), "400 Bad Request") {
		t.Fatalf("error = %v, want HTTP 400", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want non-transient HTTP failure", err)
	}
	if got := polls.Load(); got != 1 {
		t.Fatalf("read_state polls = %d, want 1", got)
	}
}

func BenchmarkVerifySynchronousCallCertificate(b *testing.B) {
	requestID := RequestID{7, 8, 9}
	signer, rootKey := callCertificateSigner(b)
	certificate := signedCallCertificate(b, signer, requestID, []byte("reply"), time.Now())
	b.ReportAllocs()
	for b.Loop() {
		if err := certificate.VerifyTime(5 * time.Minute); err != nil {
			b.Fatal(err)
		}
		if err := certification.VerifyCertificate(certificate, principal.AnonymousID, rootKey); err != nil {
			b.Fatal(err)
		}
	}
}

func callTestAgent(t *testing.T, rootKey []byte, handler http.HandlerFunc) *Agent {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	host, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{
		ClientConfig:     []ClientOption{WithHostURL(host)},
		IngressExpiry:    5 * time.Minute,
		PollDelay:        time.Millisecond,
		PollTimeout:      time.Second,
		ReadStateTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	a.rootKey = rootKey
	return a
}

func callTestRequest(a *Agent, requestID RequestID) *APIRequest[struct{}, *[]byte] {
	return &APIRequest[struct{}, *[]byte]{
		a:                   a,
		unmarshal:           func(raw []byte, out *[]byte) error { *out = append((*out)[:0], raw...); return nil },
		typ:                 RequestTypeCall,
		methodName:          "test",
		effectiveCanisterID: principal.AnonymousID,
		requestID:           requestID,
	}
}

func callCertificateSigner(t testing.TB) (*bls.SecretKey, []byte) {
	t.Helper()
	secretKey := bls.NewSecretKeyByCSPRNG()
	if secretKey == nil {
		t.Fatal("bls: failed to generate secret key")
	}
	publicKey := bls12381.G2Affine(*secretKey.PublicKey())
	publicKeyBytes := publicKey.Bytes()
	rootKey, err := certification.PublicBLSKeyToDER(publicKeyBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	return secretKey, rootKey
}

func signedCallCertificate(t testing.TB, secretKey *bls.SecretKey, requestID RequestID, reply []byte, at time.Time) certification.Certificate {
	t.Helper()
	rawTime, err := leb128.EncodeUnsigned(big.NewInt(at.UnixNano()))
	if err != nil {
		t.Fatal(err)
	}

	requestTree := hashtree.Labeled{
		Label: hashtree.Label("request_status"),
		Tree: hashtree.Labeled{
			Label: requestID[:],
			Tree: hashtree.Fork{
				LeftTree:  hashtree.Labeled{Label: hashtree.Label("reply"), Tree: hashtree.Leaf(reply)},
				RightTree: hashtree.Labeled{Label: hashtree.Label("status"), Tree: hashtree.Leaf("replied")},
			},
		},
	}
	tree := hashtree.Fork{
		LeftTree:  requestTree,
		RightTree: hashtree.Labeled{Label: hashtree.Label("time"), Tree: hashtree.Leaf(rawTime)},
	}
	root := tree.Reconstruct()
	message := append(hashtree.DomainSeparator("ic-state-root"), root[:]...)
	signature, err := secretKey.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	signatureAffine := bls12381.G1Affine(*signature)
	signatureBytes := signatureAffine.Bytes()
	return certification.Certificate{
		Tree:      hashtree.NewHashTree(tree),
		Signature: signatureBytes[:],
	}
}

func marshalCertificate(t *testing.T, certificate certification.Certificate) []byte {
	t.Helper()
	raw, err := cbor.Marshal(certificate)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeCBOR(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	raw, err := cbor.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
}

func hasPathSuffix(path, suffix string) bool {
	return len(path) >= len(suffix) && path[len(path)-len(suffix):] == suffix
}
