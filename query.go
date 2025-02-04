package agent

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math/big"

	"github.com/aviate-labs/leb128"
	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/certification"
	"github.com/niccolofant/agent-go/certification/hashtree"
	"github.com/niccolofant/agent-go/principal"
	"google.golang.org/protobuf/proto"
)

// Query calls a method on a canister and unmarshals the result into the given values.
func (q APIRequest[In, Out]) Query(out Out, skipVerification bool) error {
	q.a.logger.Printf("[AGENT] QUERY %s %s", q.effectiveCanisterID, q.methodName)
	ctx, cancel := context.WithTimeout(q.a.ctx, q.a.ingressExpiry)
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

		for _, signature := range resp.Signatures {
			if len(q.effectiveCanisterID.Raw) == 0 {
				return fmt.Errorf("can not verify signature without effective canister ID")
			}
			c, err := q.a.readStateCertificate(q.effectiveCanisterID, [][]hashtree.Label{{hashtree.Label("subnet")}})
			if err != nil {
				return err
			}
			if err := c.VerifyTime(q.a.ingressExpiry); err != nil {
				return err
			}
			if err := certification.VerifyCertificate(*c, q.effectiveCanisterID, q.a.rootKey); err != nil {
				return err
			}
			subnetID := principal.MustDecode(certification.RootSubnetID)
			if c.Delegation != nil {
				subnetID = c.Delegation.SubnetId
			}
			pk, err := c.Tree.Lookup(hashtree.Label("subnet"), subnetID.Raw, hashtree.Label("node"), signature.Identity.Raw, hashtree.Label("public_key"))
			if err != nil {
				return err
			}
			publicKey, err := certification.PublicED25519KeyFromDER(pk)
			if err != nil {
				return err
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
					*publicKey,
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
					*publicKey,
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
		return fmt.Errorf("(%d) %s: %s", resp.RejectCode, resp.ErrorCode, resp.RejectMsg)
	default:
		panic("unreachable")
	}
}

// Query calls a method on a canister and unmarshals the result into the given values.
func (a Agent) Query(canisterID principal.Principal, methodName string, in, out []any) error {
	query, err := a.CreateCandidAPIRequest(RequestTypeQuery, canisterID, methodName, in...)
	if err != nil {
		return err
	}
	return query.Query(out, false)
}

// QueryProto calls a method on a canister and unmarshals the result into the given proto message.
func (a Agent) QueryProto(canisterID principal.Principal, methodName string, in, out proto.Message) error {
	query, err := a.CreateProtoAPIRequest(RequestTypeQuery, canisterID, methodName, in)
	if err != nil {
		return err
	}
	return query.Query(out, true)
}
