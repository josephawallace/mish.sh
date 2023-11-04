package main

import (
	"fmt"

	"github.com/josephawallace/mish.sh/pkg/blind"
)

func main() {
	// User wants to send blind message to Signer to sign
	// 1. Draft a plaintext message
	msg := []byte("hello foo")

	// 2. Blind the hash by using a blinding factor r, or simply computer H(msg)^r
	blinded, r := blind.Blind(msg)

	// 3. Send the blinded hash to the Signer to sign
	// blinded ---> Signer

	// Signer will sign the underlying message of the blind hash
	sk, pk := blind.Keygen()

	// 2. Signs blind message (the hashing and signing steps are not conjoined here, as usual)
	blindSig := blind.Sign(blinded, sk)

	//// 3. Sends the blind signed hash signature to the User for unblinding
	//// blindSig ---> User

	// User wants to unblind the signature to reveal a valid signature on the original msg
	// 1. Sign the blinded signature with 1/r
	unblinded := blind.Unblind(blindSig, r)

	// 2. Verify signature
	verified := unblinded.Verify(true, pk, true, msg, blind.DST)
	fmt.Printf("verified: %t\n", verified)
}
