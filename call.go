package agent

import (
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/certification"
	"github.com/niccolofant/agent-go/certification/hashtree"
	"github.com/niccolofant/agent-go/principal"
	"google.golang.org/protobuf/proto"
)

// CallAndWait calls a method on a canister and waits for the result.
func (c APIRequest[_, Out]) CallAndWait(out Out) error {
	c.a.logger.Printf("[AGENT] CALL %s %s (%x)", c.effectiveCanisterID, c.methodName, c.requestID)
	rawCertificate, err := c.a.call(c.effectiveCanisterID, c.data)
	if err != nil {
		if !isTransientError(err) {
			return err
		}
		// EOF/transient: fall through to poll to check if it went through
		rawCertificate = nil
	}

	if len(rawCertificate) != 0 {
		var certificate certification.Certificate
		if err := cbor.Unmarshal(rawCertificate, &certificate); err != nil {
			return err
		}
		path := []hashtree.Label{hashtree.Label("request_status"), c.requestID[:]}
		if raw, err := certificate.Tree.Lookup(append(path, hashtree.Label("reply"))...); err == nil {
			return c.unmarshal(raw, out)
		}

		rejectCode, err := certificate.Tree.Lookup(append(path, hashtree.Label("reject_code"))...)
		if err != nil {
			// Not in tree yet — fall through to poll
			goto poll
		}
		message, _ := certificate.Tree.Lookup(append(path, hashtree.Label("reject_message"))...)
		errorCode, _ := certificate.Tree.Lookup(append(path, hashtree.Label("error_code"))...)
		return preprocessingError{
			RejectCode: uint64FromBytes(rejectCode),
			Message:    string(message),
			ErrorCode:  string(errorCode),
		}
	}


	poll:
	raw, err := c.a.poll(c.effectiveCanisterID, c.requestID)
	if err != nil {
		return err
	}
	return c.unmarshal(raw, out)
}

// Call calls a method on a canister and unmarshals the result into the given values.
func (a Agent) Call(canisterID principal.Principal, methodName string, in []any, out []any) error {
	call, err := a.CreateCandidAPIRequest(RequestTypeCall, canisterID, methodName, in...)
	if err != nil {
		return err
	}
	return call.CallAndWait(out)
}

// CallProto calls a method on a canister and unmarshals the result into the given proto message.
func (a Agent) CallProto(canisterID principal.Principal, methodName string, in, out proto.Message) error {
	call, err := a.CreateProtoAPIRequest(RequestTypeCall, canisterID, methodName, in)
	if err != nil {
		return err
	}
	return call.CallAndWait(out)
}

func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "temporary") ||
		strings.Contains(msg, "TLS handshake")
}