package bls

import (
	"crypto/rand"
	"log"

	blst "github.com/supranational/blst/bindings/go"
)

// Scalar is an alias for blst.Scalar which represents a scalar value.
type Scalar = blst.Scalar

// P1 is an alias for the blst.P1 type from the blst package which represents a point on curve P1.
type P1 = blst.P1

// P2 is an alias for the blst.P2 type from the blst package which represents a point on curve P2.
type P2 = blst.P2

// P1Affine is an alias for blst.P1Affine which represents an affine point on curve P1.
type P1Affine = blst.P1Affine

// P2Affine is an alias for blst.P2Affine which represents an affine point on curve P2.
type P2Affine = blst.P2Affine

// P1Aggregate is an alias for blst.P1Aggregate which represents an aggregate of multiple P1 points.
type P1Aggregate = blst.P1Aggregate

// P2Aggregate is an alias for blst.P2Aggregate which represents an aggregate of multiple P2 points.
type P2Aggregate = blst.P2Aggregate

// SkSize is the size of the secret key in bits.
const SkSize = 256

// DST is a domain separation tag used in the BLS signature scheme.
var DST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

// P1AffinesMult is a reference to the function P1AffinesMult from the blst package.
// This function can be used to perform a multi-scalar multiplication on a list of P1 affine points.
var P1AffinesMult = blst.P1AffinesMult

// P2AffinesMult is a reference to the function P2AffinesMult from the blst package.
// It allows multi-scalar multiplication to be performed on a list of P2 affine points.
var P2AffinesMult = blst.P2AffinesMult

// randomScalar generates a new random scalar value which can be used as a private key.
func randomScalar() *Scalar {
	ikm := make([]byte, SkSize/8)
	_, err := rand.Read(ikm)
	if err != nil {
		log.Fatal(err.Error())
	}
	return blst.KeyGen(ikm)
}

// Keygen generates a new private key (scalar) and its corresponding public key (P1 affine point).
func Keygen() (*Scalar, *P1Affine) {
	sk := randomScalar()
	pk := new(P1Affine).From(sk)
	return sk, pk
}

// Sign creates a signature on a message using the given private key.
// The signature is a P2 affine point.
func Sign(msg []byte, sk *Scalar) *P2Affine {
	return new(P2Affine).Sign(sk, msg, DST)
}

// Verify checks whether a signature is valid for a given message and public key.
// It returns true if the verification is successful.
func Verify(sig *P2Affine, pk *P1Affine, msg []byte) bool {
	return sig.Verify(true, pk, true, msg, DST)
}

// AggregateP1 aggregates two P1 affine points into a P1 aggregate.
func AggregateP1(p1 *P1Affine, p2 *P1Affine) *P1Aggregate {
	agg := new(blst.P1Aggregate)
	agg.Aggregate([]*blst.P1Affine{p1, p2}, true)
	return agg
}

// AggregateP2 aggregates two P2 affine points into a P2 aggregate.
func AggregateP2(p1 *P2Affine, p2 *P2Affine) *P2Aggregate {
	agg := new(blst.P2Aggregate)
	agg.Aggregate([]*blst.P2Affine{p1, p2}, true)
	return agg
}
