package main

import (
	"log"
	"time"

	"github.com/josephawallace/mish.sh/internal/bls"

	blst "github.com/supranational/blst/bindings/go"
)

func main() {
	skIn, pkIn := bls.Keygen()

	ska, skb, aggKey := OpenShared(time.Hour, pkIn, []byte(""), 10, skIn)

	msg := []byte("attack at dawn")
	sigA := bls.Sign(msg, ska)
	sigB := bls.Sign(msg, skb)

	aggSig := bls.AggregateP2(sigA, sigB)

	verified := bls.Verify(aggSig.ToAffine(), aggKey.ToAffine(), msg)

	log.Printf("verified: %t", verified)
}

// OpenShared is a BLS implementation for functionality F.OpenSh
// F.OpenSh(T, pk_in, P_b, c, sk_in) called by P_a
// Here, we use BLS as it's used in Ethereum 2.0, placing public keys in G1 and messages/signatures in G2
func OpenShared(T time.Duration, pkIn *blst.P1Affine, Pb []byte, c int, skIn *blst.Scalar) (*blst.Scalar, *blst.Scalar, *blst.P1Aggregate) {
	// Generate keys (pk_a, sk_a), (pk_b, sk_b)
	// 1. Generate 'a' keys
	ska, pka := bls.Keygen()

	// 2. Generate 'b' keys
	skb, pkb := bls.Keygen()

	// 3. Call interface LSig.Freeze
	// This would be an on-chain transaction into the shared address, with T defining the time-length for a return
	// transaction to the funding account.

	// 4. Create shared address
	agg := bls.AggregateP1(pka, pkb)

	return ska, skb, agg // moving forward, the secret keys needs separately generated so neither party sees the others secret
}
