package blind

import "github.com/josephawallace/mish.sh/internal/bls"

// Keygen creates a keypair for blind signer.
func Keygen() (*bls.Scalar, *bls.P1Affine) {
	return bls.Keygen()
}

// Sign is used by the signer to sign a blinded message.
func Sign(p *bls.P2Affine, sk *bls.Scalar) *bls.P2Affine {
	return bls.P2AffinesMult([]*bls.P2Affine{p}, []*bls.Scalar{sk}, bls.SkSize).ToAffine()
}

// Blind is used by the user to blind a message.
func Blind(msg []byte) (*bls.P2Affine, *bls.Scalar) {
	r, _ := bls.Keygen()
	return new(bls.P2Affine).Sign(r, msg, bls.DST), r
}

// Unblind is used by the user to eventually unblind the blinded signature sent by the signer.
func Unblind(p *bls.P2Affine, r *bls.Scalar) *bls.P2Affine {
	rInv := r.Inverse()
	return bls.P2AffinesMult([]*bls.P2Affine{p}, []*bls.Scalar{rInv}, bls.SkSize).ToAffine()
}
