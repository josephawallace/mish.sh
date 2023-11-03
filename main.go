package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

type PrivateKey = blst.Scalar
type PublicKey = blst.P1Affine
type Signature = blst.P2Affine
type AggregatePublicKey = blst.P1Aggregate
type AggregateSignature = blst.P2Aggregate

func main() {
	// Global parameter for proper hashing, signing, and verifying
	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

	// User wants to send blind message to Signer to sign
	// 1. Draft a plaintext message
	msg := []byte("hello foo")
	fmt.Printf("msg: %s\n", msg)

	// 2. Blind the hash by using a blinding factor r, or simply computer H(msg)^r
	ikm := make([]byte, 32)
	_, _ = rand.Read(ikm)
	r := blst.KeyGen(ikm)
	rPk := new(PublicKey).From(r)
	blindedHash := new(Signature).Sign(r, msg, dst) // sign operation used as exponentiation
	fmt.Printf("blindedHash: %s\n", hex.EncodeToString(blindedHash.Serialize()))
	verified := blindedHash.Verify(true, rPk, true, msg, dst)
	fmt.Printf("verified: %d\n", verified)

	// 3. Send the blinded hash to the Signer to sign
	// blindedHash ---> Signer

	// Signer will sign the underlying message of the blind hash
	// 1. Create keypair
	ikm = make([]byte, 32)
	_, _ = rand.Read(ikm)
	sk := blst.KeyGen(ikm)
	fmt.Printf("signer private key: %s\n", hex.EncodeToString(sk.Serialize()))

	pk := new(PublicKey).From(sk)
	fmt.Printf("signer public key: %s\n", hex.EncodeToString(pk.Compress()))

	// 2. Signs blind message (the hashing and signing steps are not conjoined here, as usual)
	tempBlindedSig := blst.P2AffinesMult([]*blst.P2Affine{blindedHash}, []*blst.Scalar{sk}, 256)
	blindSig := tempBlindedSig.ToAffine()
	fmt.Printf("blind sig: %s\n", hex.EncodeToString(blindSig.Compress()))

	//// 3. Sends the blind signed hash signature to the User for unblinding
	//// blindSig ---> User

	// User wants to unblind the signature to reveal a valid signature on the original msg
	// 1. Sign the blinded signature with 1/r
	rInv := r.Inverse()
	tempSig := blst.P2AffinesMult([]*blst.P2Affine{blindSig}, []*blst.Scalar{rInv}, 256)
	sig := tempSig.ToAffine()
	fmt.Printf("signature on msg: %s\n", hex.EncodeToString(sig.Compress()))

	// 2. Verify signature
	verified = sig.Verify(true, pk, true, msg, dst)
	fmt.Printf("verified: %d\n", verified)
}
