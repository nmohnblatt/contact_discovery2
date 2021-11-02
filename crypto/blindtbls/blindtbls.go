package blindtbls

import (
	"bytes"
	"encoding/binary"

	"github.com/nmohnblatt/contact_discovery2/crypto/blindbls"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

// Blind returns a blinded byte representation of an input point
func Blind(group kyber.Group, blindingFactor kyber.Scalar, HM kyber.Point) ([]byte, error) {
	return blindbls.Blind(group, blindingFactor, HM)
}

// Sign creates a threshold BLS signature Si = xi * H(m) on the given message m
// using the provided secret key share xi.
func Sign(suite pairing.Suite, group kyber.Group, private *share.PriShare, blindedHash []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, uint16(private.I)); err != nil {
		return nil, err
	}
	s, err := blindbls.Sign(group, private.V, blindedHash)
	if err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnblindShare outputs the unblinded point underlying the blinded signature s
func UnblindShare(group kyber.Group, blindingFactor kyber.Scalar, s []byte) (*share.PubShare, error) {
	Si := tbls.SigShare(s)
	i, err := Si.Index()
	if err != nil {
		return &share.PubShare{I: -1, V: nil}, err
	}

	axHM := group.Point()
	err = axHM.UnmarshalBinary(Si.Value())
	if err != nil {
		return &share.PubShare{I: -1, V: nil}, err
	}

	inv := group.Scalar().Inv(blindingFactor)
	xHM := axHM.Mul(inv, axHM)

	return &share.PubShare{I: i, V: xHM}, nil
}

// Verify checks the given threshold BLS signature Si on the message m using
// the public key share Xi that is associated to the secret key share xi. This
// public key share Xi can be computed by evaluating the public sharing
// polynonmial at the share's index i.
func Verify(suite pairing.Suite, group kyber.Group, public *share.PubPoly, HM kyber.Point, s *share.PubShare) error {
	return blindbls.Verify(suite, group, public.Eval(s.I).V, HM, s.V)
}

// Recover reconstructs the full BLS signature S = x * H(m) from a threshold t
// of signature shares Si using Lagrange interpolation. The full signature S
// can be verified through the regular BLS verification routine using the
// shared public key X. The shared public key can be computed by evaluating the
// public sharing polynomial at index 0.
func Recover(suite pairing.Suite, group kyber.Group, public *share.PubPoly, HM kyber.Point, sigs []*share.PubShare, t, n int) ([]byte, error) {
	for _, sig := range sigs {
		if err := Verify(suite, group, public, HM, sig); err != nil {
			return nil, err
		}
	}

	commit, err := share.RecoverCommit(group, sigs, t, n)
	if err != nil {
		return nil, err
	}
	sig, err := commit.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return sig, nil
}
