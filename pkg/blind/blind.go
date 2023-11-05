package blind

import (
	"crypto/rand"
	"log"

	blst "github.com/supranational/blst/bindings/go"
)

// skSize is the number of bits for private key
const skSize = 256

// DST is a domain separator tag used to avoid different attack classes
var DST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

type Scalar = blst.Scalar
type P1Affine = blst.P1Affine
type P2Affine = blst.P2Affine
type PrivateKey = Scalar
type PublicKey = P1Affine
type Signature = P2Affine
type AggregatePublicKey = blst.P1Aggregate
type AggregateSignature = blst.P2Aggregate

// Keygen creates a keypair for blind signer.
func Keygen() (*PrivateKey, *PublicKey) {
	ikm := make([]byte, 32)
	_, err := rand.Read(ikm)
	if err != nil {
		log.Fatal(err.Error())
	}
	sk := blst.KeyGen(ikm)
	pk := new(PublicKey).From(sk)
	return sk, pk
}

// Sign is used by the signer to sign a blinded message.
func Sign(p *P2Affine, sk *PrivateKey) *Signature {
	return blst.P2AffinesMult([]*blst.P2Affine{p}, []*blst.Scalar{sk}, skSize).ToAffine()
}

// Blind is used by the user to blind a message.
func Blind(msg []byte) (*P2Affine, *Scalar) {
	ikm := make([]byte, 32)
	_, err := rand.Read(ikm)
	if err != nil {
		log.Fatal(err.Error())
	}
	r := blst.KeyGen(ikm)
	return new(P2Affine).Sign(r, msg, DST), r
}

// Unblind is used by the user to eventually unblind the blinded signature sent by the signer.
func Unblind(p *P2Affine, r *Scalar) *Signature {
	rInv := r.Inverse()
	return blst.P2AffinesMult([]*blst.P2Affine{p}, []*blst.Scalar{rInv}, skSize).ToAffine()
}
