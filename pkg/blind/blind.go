package blind

import (
	"crypto/rand"
	"log"

	blst "github.com/supranational/blst/bindings/go"
)

const skSize = 256

var DST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

type Scalar = blst.Scalar
type P1Affine = blst.P1Affine
type P2Affine = blst.P2Affine
type PrivateKey = Scalar
type PublicKey = P1Affine
type Signature = P2Affine
type AggregatePublicKey = blst.P1Aggregate
type AggregateSignature = blst.P2Aggregate

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

func Sign(p *P2Affine, sk *PrivateKey) *Signature {
	return blst.P2AffinesMult([]*blst.P2Affine{p}, []*blst.Scalar{sk}, skSize).ToAffine()
}

func Blind(msg []byte) (*P2Affine, *Scalar) {
	ikm := make([]byte, 32)
	_, err := rand.Read(ikm)
	if err != nil {
		log.Fatal(err.Error())
	}
	r := blst.KeyGen(ikm)
	return new(P2Affine).Sign(r, msg, DST), r
}

func Unblind(p *P2Affine, r *Scalar) *Signature {
	rInv := r.Inverse()
	return blst.P2AffinesMult([]*blst.P2Affine{p}, []*blst.Scalar{rInv}, skSize).ToAffine()
}
