// Package blindbls implements a blind BLS Signature protocol based on the kyber library
package blindbls

import (
	"errors"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
)

// CheckGroup checks whether point P is from the group G
func CheckGroup(P kyber.Point, G kyber.Group) bool {
	isInGroup := false

	if G.String() == P.String()[:8] {
		isInGroup = true
	}

	return isInGroup
}

// Blind returns a blinded byte representation of an input point
func Blind(group kyber.Group, blindingFactor kyber.Scalar, HM kyber.Point) ([]byte, error) {
	if check := CheckGroup(HM, group); !check {
		err := errors.New("blind: HM and group do not match")
		return nil, err
	}
	aHM := group.Point()
	aHM.Mul(blindingFactor, HM)

	out, err := aHM.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Sign creates a BLS signature S = x * H(m) on a blinded message (byte representation) using the private
// key x. The signature S is a point on the curve defined by the argument group.
// Warning: "group" must match the original group of "blindedHash"
func Sign(group kyber.Group, x kyber.Scalar, blindedHash []byte) ([]byte, error) {
	aHM := group.Point()
	err := aHM.UnmarshalBinary(blindedHash)
	if err != nil {
		return nil, err
	}
	xaHM := aHM.Mul(x, aHM)

	s, err := xaHM.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Unblind outputs the unblinded point underlying the blinded signature s
func Unblind(group kyber.Group, blindingFactor kyber.Scalar, s []byte) (kyber.Point, error) {
	axHM := group.Point()
	err := axHM.UnmarshalBinary(s)
	if err != nil {
		return nil, err
	}

	inv := group.Scalar().Inv(blindingFactor)
	xHM := axHM.Mul(inv, axHM)

	return xHM, nil
}

// Verify checks the given BLS signature S on the message m using the public
// key X. If group is G1, it verfies that the equality e(H(m), X) == e(H(m), x*B2) ==
// e(x*H(m), B2) == e(S, B2) holds where e is the pairing operation and B2 is
// the base point from curve G2. If group is G2, it verifies that the equality e(X, H(m)) == e(x*B1, H(m)) ==
// e(B1, x*H(m)) == e(B1, S) holds where e is the pairing operation and B1 is
// the base point from curve G1.
func Verify(suite pairing.Suite, group kyber.Group, X kyber.Point, HM, xHM kyber.Point) error {

	if group.String() == "bn256.G1" {
		left := suite.Pair(HM, X)

		right := suite.Pair(xHM, suite.G2().Point().Base())
		if !left.Equal(right) {
			return errors.New("bls: invalid signature")
		}
	} else if group.String() == "bn256.G2" {
		left := suite.Pair(X, HM)

		right := suite.Pair(suite.G1().Point().Base(), xHM)
		if !left.Equal(right) {
			return errors.New("bls: invalid signature")
		}
	} else {
		return errors.New("Group not recognised")
	}

	return nil
}
