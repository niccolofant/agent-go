package agent

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/certification"
	"github.com/niccolofant/agent-go/certification/hashtree"
	"github.com/niccolofant/agent-go/principal"
)

var callCertificateDecoder = func() cbor.DecMode {
	opts := preparedCallDecoder.DecOptions()
	opts.MaxNestedLevels = 68 // two envelope levels plus the bounded tree
	dm, err := opts.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

// Decode delegation bytes explicitly: generic Certificate.UnmarshalCBOR can
// recurse through certificate blobs outside the CBOR decoder's nesting bound.
func decodeCallCertificate(raw []byte, allowDelegation bool, budget *callTreeBudget) (certification.Certificate, error) {
	var cert certification.Certificate
	if bytes.HasPrefix(raw, []byte{0xd9, 0xd9, 0xf7}) {
		raw = raw[3:]
	}
	var wire struct {
		Tree       cbor.RawMessage `cbor:"tree"`
		Signature  preparedBlob    `cbor:"signature"`
		Delegation cbor.RawMessage `cbor:"delegation"`
	}
	if err := callCertificateDecoder.Unmarshal(raw, &wire); err != nil {
		return cert, err
	}
	if len(wire.Signature) != 48 {
		return cert, fmt.Errorf("signature length")
	}
	root, err := budget.decode(wire.Tree, 1)
	if err != nil {
		return cert, err
	}
	cert.Tree = hashtree.NewHashTree(root)
	cert.Signature = wire.Signature
	if len(wire.Delegation) != 0 {
		if !allowDelegation {
			return cert, fmt.Errorf("nested delegation")
		}
		var d struct {
			Subnet      preparedBlob `cbor:"subnet_id"`
			Certificate preparedBlob `cbor:"certificate"`
		}
		if err := callCertificateDecoder.Unmarshal(wire.Delegation, &d); err != nil {
			return cert, err
		}
		if len(d.Subnet) == 0 || len(d.Subnet) > 29 || len(d.Certificate) == 0 {
			return cert, fmt.Errorf("delegation fields")
		}
		child, err := decodeCallCertificate(d.Certificate, false, budget)
		if err != nil {
			return cert, err
		}
		cert.Delegation = &certification.Delegation{SubnetId: principal.Principal{Raw: d.Subnet}, Certificate: child}
	}
	return cert, nil
}

// RawMessage keeps the structured decoder from materializing an unbounded
// []any graph. Charge every recursive slice before decoding/copying it, so a
// large leaf under many labels cannot amplify allocations without a bound.
type callTreeBudget struct {
	nodes int
	bytes int
}

func (b *callTreeBudget) decode(raw []byte, depth int) (hashtree.Node, error) {
	if len(raw) == 0 || raw[0]>>5 != 4 || depth > 64 || b.nodes <= 0 || len(raw) > b.bytes {
		return nil, fmt.Errorf("tree shape or budget")
	}
	b.nodes--
	b.bytes -= len(raw)
	var parts []cbor.RawMessage
	if err := callCertificateDecoder.Unmarshal(raw, &parts); err != nil {
		return nil, err
	}
	if len(parts) == 0 || len(parts) > 3 || len(parts[0]) == 0 || parts[0][0]>>5 != 0 {
		return nil, fmt.Errorf("tree tag")
	}
	var tag uint64
	if err := callCertificateDecoder.Unmarshal(parts[0], &tag); err != nil || tag > 4 {
		return nil, fmt.Errorf("tree tag")
	}
	if (tag == 0 && len(parts) != 1) || ((tag == 1 || tag == 2) && len(parts) != 3) || (tag >= 3 && len(parts) != 2) {
		return nil, fmt.Errorf("tree arity")
	}
	if tag == 0 {
		return hashtree.Empty{}, nil
	}
	if tag == 1 {
		left, err := b.decode(parts[1], depth+1)
		if err != nil {
			return nil, err
		}
		right, err := b.decode(parts[2], depth+1)
		if err != nil {
			return nil, err
		}
		return hashtree.Fork{LeftTree: left, RightTree: right}, nil
	}
	var blob preparedBlob
	if err := callCertificateDecoder.Unmarshal(parts[1], &blob); err != nil {
		return nil, err
	}
	switch tag {
	case 2:
		child, err := b.decode(parts[2], depth+1)
		if err != nil {
			return nil, err
		}
		return hashtree.Labeled{Label: hashtree.Label(blob), Tree: child}, nil
	case 3:
		return hashtree.Leaf(blob), nil
	default:
		if len(blob) != 32 {
			return nil, fmt.Errorf("pruned digest length")
		}
		return hashtree.Pruned([32]byte(blob)), nil
	}
}
