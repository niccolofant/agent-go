package identity

import (
	"github.com/niccolofant/agent-go/principal"
)

// AnonymousIdentity is an identity that does not sign messages.
type AnonymousIdentity struct{}

// PublicKey returns the public key of the identity.
func (id AnonymousIdentity) PublicKey() []byte {
	return nil
}

// Sender returns the principal of the identity.
func (id AnonymousIdentity) Sender() principal.Principal {
	return principal.AnonymousID
}

// Sign signs the given message.
func (id AnonymousIdentity) Sign(_ []byte) []byte {
	return nil
}

// ToPEM returns the PEM encoding of the public key.
func (id AnonymousIdentity) ToPEM() ([]byte, error) {
	return nil, nil
}

// Verify verifies the signature of the given message.
func (id AnonymousIdentity) Verify(_, _ []byte) bool {
	return true
}
