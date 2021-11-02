// Package moretbls mirrors the tbls package from the kyber library.
// It implements a (t,n)-threshold BLS signature scheme.
// Here, signatures are points on G2 and public keys are points on G1
//
// WARNING: relies on morebls package, which makes use of an insecure hash-to-G2 function
package moretbls

import (
	"bytes"
	"encoding/binary"

	"github.com/nmohnblatt/contact_discovery2/crypto/morebls"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

// Sign2 creates a threshold BLS signature Si = xi * H(m) on the given message m
// using the provided secret key share xi.
func Sign2(suite pairing.Suite, private *share.PriShare, msg []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, uint16(private.I)); err != nil {
		return nil, err
	}
	s, err := morebls.Sign2(suite, private.V, msg)
	if err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Verify2 checks the given threshold BLS signature Si on the message m using
// the public key share Xi that is associated to the secret key share xi. This
// public key share Xi can be computed by evaluating the public sharing
// polynonmial at the share's index i.
func Verify2(suite pairing.Suite, public *share.PubPoly, msg, sig []byte) error {
	s := tbls.SigShare(sig)
	i, err := s.Index()
	if err != nil {
		return err
	}
	return morebls.Verify2(suite, public.Eval(i).V, msg, s.Value())
}

// Recover2 reconstructs the full BLS signature S = x * H(m) from a threshold t
// of signature shares Si using Lagrange interpolation. The full signature S
// can be verified through the regular BLS verification routine using the
// shared public key X. The shared public key can be computed by evaluating the
// public sharing polynomial at index 0.
func Recover2(suite pairing.Suite, public *share.PubPoly, msg []byte, sigs [][]byte, t, n int) ([]byte, error) {
	pubShares := make([]*share.PubShare, 0)
	for _, sig := range sigs {
		s := tbls.SigShare(sig)
		i, err := s.Index()
		if err != nil {
			return nil, err
		}
		if err = morebls.Verify2(suite, public.Eval(i).V, msg, s.Value()); err != nil {
			return nil, err
		}
		point := suite.G2().Point()
		if err := point.UnmarshalBinary(s.Value()); err != nil {
			return nil, err
		}
		pubShares = append(pubShares, &share.PubShare{I: i, V: point})
		if len(pubShares) >= t {
			break
		}
	}
	commit, err := share.RecoverCommit(suite.G2(), pubShares, t, n)
	if err != nil {
		return nil, err
	}
	sig, err := commit.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return sig, nil
}
