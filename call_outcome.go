package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	"github.com/niccolofant/agent-go/certification"
	"github.com/niccolofant/agent-go/certification/hashtree"
	"github.com/niccolofant/agent-go/principal"
)

// MaxCallCertificateBytes bounds the complete certificate, including delegation.
const MaxCallCertificateBytes = 4 << 20

// ErrInvalidCallCertificate identifies malformed, incomplete, unauthenticated
// or out-of-policy evidence. It never proves that the call had no effects.
var ErrInvalidCallCertificate = errors.New("invalid call certificate")

// ErrCallCertificateContext indicates invalid policy or an unauthenticated call,
// agent or trust scope. Fix local context; trying another relay cannot fix it.
var ErrCallCertificateContext = errors.New("invalid call certificate context")

// CallStatus describes certified request-status evidence, not economic success.
// The zero value is invalid. Neither absence, rejection nor expiry proves that
// a call had no effects. Done means the response has been forgotten.
type CallStatus string

const (
	CallStatusUnproven   CallStatus = "unproven" // witness prunes the requested path
	CallStatusAbsent     CallStatus = "absent"   // absent in the signing subnet's state
	CallStatusReceived   CallStatus = "received"
	CallStatusProcessing CallStatus = "processing"
	CallStatusReplied    CallStatus = "replied"
	CallStatusRejected   CallStatus = "rejected"
	CallStatusDone       CallStatus = "done"
)

// CallCertificateOptions defines local freshness policy. MaxAge must be
// positive; MaxFutureSkew must be nonnegative. These apply to the response
// certificate, not the long-lived delegation certificate or ingress expiry.
type CallCertificateOptions struct {
	MaxAge        time.Duration
	MaxFutureSkew time.Duration
}

// CallRejection is a certified IC rejection, not a canister application error.
// ErrorCode is optional. A rejection does not prove absence of partial effects.
type CallRejection struct {
	Code      uint64
	Message   string
	ErrorCode string
}

// CertifiedCallOutcome is an immutable verified observation for a PreparedCall.
// Replied still requires venue-specific decoding and settlement reconciliation.
// This type never authorizes retry, reservation release or a balance update.
// Slice getters copy. The zero value carries no verified evidence.
type CertifiedCallOutcome struct {
	id       RequestID
	sender   principal.Principal
	canister principal.Principal
	subnet   principal.Principal
	rootHash [32]byte
	at       time.Time
	status   CallStatus
	reply    []byte
	reject   CallRejection
	proof    []byte
}

func (o CertifiedCallOutcome) RequestID() RequestID { return o.id }
func (o CertifiedCallOutcome) Sender() principal.Principal {
	return principal.Principal{Raw: bytes.Clone(o.sender.Raw)}
}
func (o CertifiedCallOutcome) CanisterID() principal.Principal {
	return principal.Principal{Raw: bytes.Clone(o.canister.Raw)}
}

// SubnetID identifies the delegating certificate's attesting subnet; false
// means root-signed evidence (or a zero outcome). It is not proof of current
// routing after a migration. Absent only describes the signing subnet's state.
func (o CertifiedCallOutcome) SubnetID() (principal.Principal, bool) {
	return principal.Principal{Raw: bytes.Clone(o.subnet.Raw)}, len(o.subnet.Raw) != 0
}
func (o CertifiedCallOutcome) RootKeyHash() [32]byte  { return o.rootHash }
func (o CertifiedCallOutcome) CertifiedAt() time.Time { return o.at }
func (o CertifiedCallOutcome) Status() CallStatus     { return o.status }
func (o CertifiedCallOutcome) Certificate() []byte    { return bytes.Clone(o.proof) }

// Reply returns true even for a certified empty reply. It is opaque Candid or
// other application bytes; an IC reply is not necessarily an application Ok.
func (o CertifiedCallOutcome) Reply() ([]byte, bool) {
	return bytes.Clone(o.reply), o.status == CallStatusReplied
}

func (o CertifiedCallOutcome) Rejection() (CallRejection, bool) {
	return o.reject, o.status == CallStatusRejected
}

// VerifyCallCertificate verifies raw certificate bytes against an authenticated
// PreparedCall and this agent's trust context, without network I/O or signing.
// Pass the inner certificate blob from call/read_state, not the HTTP wrapper.
// It verifies the signature, delegation and (when delegated) canister range,
// timestamp, and request-ID-scoped status. A different request's proof cannot yield a reply for
// this call, but can prove absence or leave its status unproven.
//
// Accepted encoding: definite CBOR with at most one outer self-describe tag on
// each certificate; at most one delegation; hash-tree depth <=64, <=4096 nodes
// across both trees and <=64 MiB aggregate tree decoding work. Unknown fields,
// duplicate keys, null blobs, nested tags and incomplete terminal proofs fail.
// Recursive copies can use up to the work budget plus other buffers/overhead;
// bound concurrent verification of untrusted input. All limits apply before
// cryptographic verification. Expired ingress is allowed for recovery; the
// certificate must still satisfy opts at the time of checking.
// The caller must not mutate raw concurrently, or mutate the agent's trust
// configuration during use. Returned evidence does not itself settle a trade.
// The root is trusted directly; root-signed proofs do not check canister ranges.
// Delegation range authorization is as of that delegation, not current routing.
// Certificate bytes are not canonical: do not deduplicate outcomes by bytes.
func (a *Agent) VerifyCallCertificate(p *PreparedCall, raw []byte, opts CallCertificateOptions) (*CertifiedCallOutcome, error) {
	return a.verifyCallCertificateAt(p, raw, opts, time.Now())
}

func (a *Agent) verifyCallCertificateAt(p *PreparedCall, raw []byte, opts CallCertificateOptions, now time.Time) (*CertifiedCallOutcome, error) {
	if a == nil || p == nil || len(p.data) == 0 || len(a.rootKey) == 0 ||
		p.rootHash != sha256.Sum256(a.rootKey) || !p.sender.Equal(a.sender) ||
		opts.MaxAge <= 0 || opts.MaxFutureSkew < 0 {
		return nil, ErrCallCertificateContext
	}
	if len(raw) == 0 || len(raw) > MaxCallCertificateBytes {
		return nil, ErrInvalidCallCertificate
	}
	proof := bytes.Clone(raw)
	budget := callTreeBudget{nodes: 4096, bytes: 64 << 20}
	cert, err := decodeCallCertificate(proof, true, &budget)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding: %v", ErrInvalidCallCertificate, err)
	}
	rawTime, err := cert.Tree.Lookup(hashtree.Label("time"))
	if err != nil {
		return nil, fmt.Errorf("%w: missing certified time", ErrInvalidCallCertificate)
	}
	ns, ok := callNatural(rawTime)
	if !ok || ns == 0 || ns > math.MaxInt64 {
		return nil, fmt.Errorf("%w: certified time encoding", ErrInvalidCallCertificate)
	}
	at := time.Unix(0, int64(ns))
	if at.Before(now.Add(-opts.MaxAge)) || at.After(now.Add(opts.MaxFutureSkew)) {
		return nil, fmt.Errorf("%w: certified time outside policy", ErrInvalidCallCertificate)
	}
	if err := certification.VerifyCertificate(cert, p.canister, a.rootKey); err != nil {
		return nil, fmt.Errorf("%w: verification: %v", ErrInvalidCallCertificate, err)
	}
	o := &CertifiedCallOutcome{id: p.id, sender: p.Sender(), canister: p.CanisterID(),
		rootHash: p.rootHash, at: at, proof: proof}
	if cert.Delegation != nil {
		o.subnet = principal.Principal{Raw: bytes.Clone(cert.Delegation.SubnetId.Raw)}
	}
	lookup := func(field string) ([]byte, error) {
		return cert.Tree.Lookup(hashtree.Label("request_status"), p.id[:], hashtree.Label(field))
	}
	status, err := lookup("status")
	if err != nil {
		var le hashtree.LookupError
		if errors.As(err, &le) {
			switch le.Type {
			case hashtree.LookupResultAbsent:
				o.status = CallStatusAbsent
				return o, nil
			case hashtree.LookupResultUnknown:
				o.status = CallStatusUnproven
				return o, nil
			}
		}
		return nil, fmt.Errorf("%w: invalid status proof", ErrInvalidCallCertificate)
	}
	o.status = CallStatus(status)
	switch o.status {
	case CallStatusReceived, CallStatusProcessing, CallStatusDone:
		return o, nil
	case CallStatusReplied:
		o.reply, err = lookup("reply")
		if err == nil {
			return o, nil
		}
	case CallStatusRejected:
		code, codeErr := lookup("reject_code")
		message, messageErr := lookup("reject_message")
		errorCode, errorCodeErr := lookup("error_code")
		var le hashtree.LookupError
		if errors.As(errorCodeErr, &le) && le.Type == hashtree.LookupResultAbsent {
			errorCodeErr = nil
		}
		n, valid := callNatural(code)
		if codeErr == nil && messageErr == nil && errorCodeErr == nil && valid && n > 0 && utf8.Valid(message) && utf8.Valid(errorCode) {
			o.reject = CallRejection{Code: n, Message: string(message), ErrorCode: string(errorCode)}
			return o, nil
		}
	}
	return nil, fmt.Errorf("%w: unknown status or incomplete response", ErrInvalidCallCertificate)
}

func callNatural(raw []byte) (uint64, bool) {
	if len(raw) == 0 || len(raw) > binary.MaxVarintLen64 {
		return 0, false
	}
	n, size := binary.Uvarint(raw)
	return n, size == len(raw)
}
