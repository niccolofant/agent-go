package agent

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math/big"

	"github.com/aviate-labs/leb128"
	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/certification"
	"github.com/niccolofant/agent-go/principal"
	"google.golang.org/protobuf/proto"
)

// Query calls a method on a canister and unmarshals the result into the given values.
func (q APIRequest[In, Out]) Query(out Out, skipVerification bool) error {
	return q.QueryContext(q.a.ctx, out, skipVerification)
}

// QueryContext calls a method on a canister and unmarshals the result into the given values.
func (q APIRequest[In, Out]) QueryContext(ctx context.Context, out Out, skipVerification bool) error {
	q.a.logger.Printf("[AGENT] QUERY %s %s", q.effectiveCanisterID, q.methodName)
	if ctx == nil {
		ctx = q.a.ctx
	}
	ctx, cancel := context.WithTimeout(ctx, q.a.ingressExpiry)
	defer cancel()
	rawResp, err := q.a.client.Query(ctx, q.effectiveCanisterID, q.data)
	if err != nil {
		return err
	}
	var resp Response
	if err := cbor.Unmarshal(rawResp, &resp); err != nil {
		return err
	}

	// Verify query signatures.
	if !skipVerification && q.a.verifySignatures {
		if len(resp.Signatures) == 0 {
			return fmt.Errorf("no signatures")
		}
		if len(q.effectiveCanisterID.Raw) == 0 {
			return fmt.Errorf("can not verify signature without effective canister ID")
		}

		keys, err := q.a.queryVerificationKeys(ctx, q.effectiveCanisterID, resp.Signatures)
		if err != nil {
			return err
		}
		for _, signature := range resp.Signatures {
			publicKey, ok := keys.publicKey(signature.Identity)
			if !ok {
				return fmt.Errorf("no public key found for signature identity %s", signature.Identity)
			}
			switch resp.Status {
			case "replied":
				sig, err := certification.RepresentationIndependentHash(
					[]certification.KeyValuePair{
						{Key: "status", Value: resp.Status},
						{Key: "reply", Value: resp.Reply},
						{Key: "timestamp", Value: signature.Timestamp},
						{Key: "request_id", Value: q.requestID[:]},
					},
				)
				if err != nil {
					return err
				}
				if !ed25519.Verify(
					publicKey,
					append([]byte("\x0Bic-response"), sig[:]...),
					signature.Signature,
				) {
					return fmt.Errorf("invalid replied signature")
				}
			case "rejected":
				code, err := leb128.EncodeUnsigned(big.NewInt(int64(resp.RejectCode)))
				if err != nil {
					return err
				}
				sig, err := certification.RepresentationIndependentHash(
					[]certification.KeyValuePair{
						{Key: "status", Value: resp.Status},
						{Key: "reject_code", Value: code},
						{Key: "reject_message", Value: resp.RejectMsg},
						{Key: "error_code", Value: resp.ErrorCode},
						{Key: "timestamp", Value: signature.Timestamp},
						{Key: "request_id", Value: q.requestID[:]},
					},
				)
				if err != nil {
					return err
				}
				if !ed25519.Verify(
					publicKey,
					append([]byte("\x0Bic-response"), sig[:]...),
					signature.Signature,
				) {
					return fmt.Errorf("invalid rejected signature")
				}
			default:
				panic("unreachable")
			}
		}
	}
	switch resp.Status {
	case "replied":
		var reply struct {
			Arg []byte `ic:"arg"`
		}
		if err := cbor.Unmarshal(resp.Reply, &reply); err != nil {
			return err
		}
		return q.unmarshal(reply.Arg, out)
	case "rejected":
		return preprocessingError{
			RejectCode: resp.RejectCode,
			Message:    resp.RejectMsg,
			ErrorCode:  resp.ErrorCode,
		}
	default:
		panic("unreachable")
	}
}

// Query calls a method on a canister and unmarshals the result into the given values.
func (a Agent) Query(canisterID principal.Principal, methodName string, in, out []any) error {
	return a.QueryContext(a.ctx, canisterID, methodName, in, out)
}

// QueryContext calls a method on a canister and unmarshals the result into the given values.
func (a Agent) QueryContext(ctx context.Context, canisterID principal.Principal, methodName string, in, out []any) error {
	query, err := a.CreateCandidAPIRequest(RequestTypeQuery, canisterID, methodName, in...)
	if err != nil {
		return err
	}
	return query.QueryContext(ctx, out, false)
}

// QueryProto calls a method on a canister and unmarshals the result into the given proto message.
func (a Agent) QueryProto(canisterID principal.Principal, methodName string, in, out proto.Message) error {
	return a.QueryProtoContext(a.ctx, canisterID, methodName, in, out)
}

// QueryProtoContext calls a method on a canister and unmarshals the result into the given proto message.
func (a Agent) QueryProtoContext(ctx context.Context, canisterID principal.Principal, methodName string, in, out proto.Message) error {
	query, err := a.CreateProtoAPIRequest(RequestTypeQuery, canisterID, methodName, in)
	if err != nil {
		return err
	}
	return query.QueryContext(ctx, out, true)
}
