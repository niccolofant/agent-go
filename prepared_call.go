package agent

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/principal"
)

// MaxPreparedCallBytes bounds the persisted envelope accepted by recovery.
const MaxPreparedCallBytes = 2 << 20

// ErrInvalidPreparedCall means an envelope is malformed, unsupported, does not
// belong to this agent, or fails signature/metadata verification.
var ErrInvalidPreparedCall = errors.New("invalid prepared call")

// PreparedCall is an immutable, authenticated snapshot of a direct signed call.
// It has no submission/retry method. Authentication does not prove the call was
// submitted, accepted or executed, nor authorize its arguments or spending.
// The zero value is not an authenticated call. Slice getters return copies.
// Protect exported bytes as a submission capability while the call is valid.
// Deduplicate by RequestID, not envelope bytes: equivalent CBOR encodings and
// signatures can produce different envelopes for the same request identity.
type PreparedCall struct {
	data     []byte
	sender   principal.Principal
	canister principal.Principal
	method   string
	args     []byte
	id       RequestID
	expiry   uint64
	rootHash [32]byte
}

func (p PreparedCall) Envelope() []byte { return bytes.Clone(p.data) }
func (p PreparedCall) Sender() principal.Principal {
	return principal.Principal{Raw: bytes.Clone(p.sender.Raw)}
}
func (p PreparedCall) CanisterID() principal.Principal {
	return principal.Principal{Raw: bytes.Clone(p.canister.Raw)}
}
func (p PreparedCall) MethodName() string    { return p.method }
func (p PreparedCall) Arguments() []byte     { return bytes.Clone(p.args) }
func (p PreparedCall) RequestID() RequestID  { return p.id }
func (p PreparedCall) IngressExpiry() uint64 { return p.expiry }

// RootKeyHash identifies the agent's configured trust root at verification.
// This is LOCAL context, not a network ID covered by the ingress signature.
// Compare it against independently trusted configuration when persisting and
// restoring; never infer the expected network from the envelope itself.
func (p PreparedCall) RootKeyHash() [32]byte { return p.rootHash }

// ExportCall returns an owned, verified snapshot of this request. It supports
// direct calls signed by the agent's self-authenticating identity, not queries,
// management-canister calls, anonymous calls or delegated envelopes. Existing
// call/query APIs keep their behavior; this opt-in export does no network I/O.
func (c APIRequest[In, Out]) ExportCall() (*PreparedCall, error) {
	if c.a == nil || c.typ != RequestTypeCall {
		return nil, ErrInvalidPreparedCall
	}
	p, err := c.a.RestorePreparedCall(c.data)
	if err != nil {
		return nil, err
	}
	if p.id != c.requestID || p.expiry != c.ingressExpiry || p.method != c.methodName || !p.canister.Equal(c.effectiveCanisterID) {
		return nil, fmt.Errorf("%w: request metadata", ErrInvalidPreparedCall)
	}
	return p, nil
}

var preparedCallDecoder = func() cbor.DecMode {
	dm, err := (cbor.DecOptions{
		DupMapKey:       cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels: 4, MaxArrayElements: 16, MaxMapPairs: 16,
		IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden,
		ExtraReturnErrors:   cbor.ExtraDecErrorUnknownField,
		FieldNameMatching:   cbor.FieldNameMatchingCaseSensitive,
		ByteStringToString:  cbor.ByteStringToStringForbidden,
		FieldNameByteString: cbor.FieldNameByteStringForbidden,
		UTF8:                cbor.UTF8RejectInvalid,
	}).DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

type preparedCallContent struct {
	Type     string          `cbor:"request_type"`
	Sender   preparedBlob    `cbor:"sender"`
	Canister preparedBlob    `cbor:"canister_id"`
	Method   string          `cbor:"method_name"`
	Args     preparedBlob    `cbor:"arg"`
	Expiry   uint64          `cbor:"ingress_expiry"`
	Nonce    cbor.RawMessage `cbor:"nonce"`
}

type preparedCallEnvelope struct {
	Content preparedCallContent `cbor:"content"`
	Key     preparedBlob        `cbor:"sender_pubkey"`
	Sig     preparedBlob        `cbor:"sender_sig"`
}

// []byte decoding also accepts integer arrays; IC blobs must be byte strings.
type preparedBlob []byte

func (b *preparedBlob) UnmarshalCBOR(raw []byte) error {
	if len(raw) == 0 || raw[0]>>5 != 2 {
		return fmt.Errorf("%w: expected byte string", ErrInvalidPreparedCall)
	}
	var decoded []byte
	if err := preparedCallDecoder.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*b = decoded
	return nil
}

// RestorePreparedCall authenticates a bounded persisted envelope against this
// agent's identity and retains its exact bytes, request ID and expiry. It does
// not sign, submit, retry, fetch a key or read request status. Expired calls are
// deliberately accepted for reconciliation: expiry is not non-execution proof.
//
// Supported: definite CBOR maps, optionally prefixed by one self-describe tag;
// direct non-anonymous calls, signatures of 64 bytes (SDK Ed25519/P-256/secp256k1
// identities), method names of 1..128 ASCII bytes in 0x21..0x7e, and absent or
// 1..32-byte nonces. Delegations/unknown fields and explicit empty nonces are
// rejected, not silently discarded from request-ID hashing. Management calls
// need argument-specific routing validation and are outside this API.
// Expiry must be in 1..MaxInt64 Unix nanoseconds. Authentication alone does
// not imply replica acceptance (including network signature/expiry policies).
// The agent's configured identity and root key must remain immutable in use.
// The caller must not mutate raw while this function is running.
func (a *Agent) RestorePreparedCall(raw []byte) (*PreparedCall, error) {
	if a == nil || a.identity == nil || len(a.rootKey) == 0 || len(raw) == 0 || len(raw) > MaxPreparedCallBytes {
		return nil, ErrInvalidPreparedCall
	}
	data := bytes.Clone(raw)
	body := data
	if bytes.HasPrefix(body, []byte{0xd9, 0xd9, 0xf7}) {
		body = body[3:]
	}
	var env preparedCallEnvelope
	if err := preparedCallDecoder.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("%w: CBOR: %v", ErrInvalidPreparedCall, err)
	}
	c := env.Content
	if c.Type != RequestTypeCall || len(c.Canister) == 0 || len(c.Canister) > 29 ||
		bytes.Equal(c.Canister, principal.AnonymousID.Raw) || c.Args == nil ||
		c.Expiry == 0 || c.Expiry > math.MaxInt64 || !preparedMethod(c.Method) ||
		len(env.Key) == 0 || len(env.Key) > 1024 || len(env.Sig) != 64 {
		return nil, fmt.Errorf("%w: fields", ErrInvalidPreparedCall)
	}
	var nonce preparedBlob
	if len(c.Nonce) != 0 {
		if err := preparedCallDecoder.Unmarshal(c.Nonce, &nonce); err != nil || len(nonce) == 0 || len(nonce) > 32 {
			return nil, fmt.Errorf("%w: nonce", ErrInvalidPreparedCall)
		}
	}
	if !bytes.Equal(env.Key, a.senderPubKey) || !bytes.Equal(c.Sender, a.sender.Raw) ||
		!principal.NewSelfAuthenticating(env.Key).Equal(a.sender) {
		return nil, fmt.Errorf("%w: sender/key", ErrInvalidPreparedCall)
	}
	req := Request{Type: c.Type, Sender: principal.Principal{Raw: c.Sender},
		CanisterID: principal.Principal{Raw: c.Canister}, MethodName: c.Method,
		Arguments: c.Args, IngressExpiry: c.Expiry, Nonce: nonce}
	id := NewRequestID(req)
	var message [43]byte
	copy(message[:11], "\x0aic-request")
	copy(message[11:], id[:])
	if !a.identity.Verify(message[:], env.Sig) {
		return nil, fmt.Errorf("%w: signature", ErrInvalidPreparedCall)
	}
	return &PreparedCall{data: data, sender: req.Sender, canister: req.CanisterID,
		method: c.Method, args: c.Args, id: id, expiry: c.Expiry, rootHash: sha256.Sum256(a.rootKey)}, nil
}

func preparedMethod(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
