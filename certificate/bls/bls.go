package bls

import "github.com/herumi/bls-go-binary/bls"

const (
	dstG1              = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
	publicKeyGenerator = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
)

func init() {
	if err := bls.Init(bls.BLS12_381); err != nil {
		panic(err)
	}

	// Set Ethereum serialization format.
	bls.SetETHserialization(true)
	if err := bls.SetMapToMode(bls.IRTF); err != nil {
		panic(err)
	}

	// Set the generator of G2. see https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-11.html#section-4.2.1
	var gen bls.PublicKey
	if err := gen.SetHexString(publicKeyGenerator); err != nil {
		panic(err)
	}
	if err := bls.SetGeneratorOfPublicKey(&gen); err != nil {
		panic(err)
	}

	if err := bls.SetDstG1(dstG1); err != nil {
		panic(err)
	}
}

type PublicKey = bls.PublicKey

// PublicKeyFromBytes returns a PublicKey from a byte slice.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var pub bls.PublicKey
	return &pub, pub.Deserialize(b)
}

// PublicKeyFromHexString returns a PublicKey from a hex string.
func PublicKeyFromHexString(s string) (*PublicKey, error) {
	var pub bls.PublicKey
	return &pub, pub.DeserializeHexStr(s)
}

type Signature = bls.Sign

// SignatureFromBytes returns a Signature from a byte slice.
func SignatureFromBytes(b []byte) (*Signature, error) {
	var sig bls.Sign
	return &sig, sig.Deserialize(b)
}

// SignatureFromHexString returns a Signature from a hex string.
func SignatureFromHexString(s string) (*Signature, error) {
	var sig bls.Sign
	return &sig, sig.DeserializeHexStr(s)
}
