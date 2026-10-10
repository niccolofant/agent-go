package certification

import (
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/certification/hashtree"
	"github.com/niccolofant/agent-go/principal"
)

func TestVerifyMissingCertificateTree(t *testing.T) {
	for _, raw := range [][]byte{{0xf6}, {0xa0}} {
		var cert Certificate
		if err := cbor.Unmarshal(raw, &cert); err != nil {
			t.Fatal("fixture did not reach signature verification", err)
		}
		if err := VerifyCertificate(cert, principal.AnonymousID, hexToBytes(RootKey)); err == nil || !strings.Contains(err.Error(), "missing certificate tree") {
			t.Fatal("missing certificate tree guard", err)
		}
	}
	var cert Certificate
	if err := cbor.Unmarshal([]byte{0xa1, 0x64, 't', 'r', 'e', 'e', 0xf6}, &cert); err == nil {
		t.Fatal("decoded a null tree")
	}
	if err := cbor.Unmarshal(hexToBytes(SampleCert), &cert); err != nil {
		t.Fatal(err)
	}
	cert.Delegation.Certificate.Tree = hashtree.HashTree{}
	if err := VerifyCertificate(cert, principal.Principal{Raw: hexToBytes("00000000002000000101")}, hexToBytes(RootKey)); err == nil || !strings.Contains(err.Error(), "missing certificate tree") {
		t.Fatal("missing delegation tree guard", err)
	}
}
