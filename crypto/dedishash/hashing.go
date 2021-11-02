package dedishash

import (
	"errors"
	"log"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

type hashablePoint interface {
	Hash([]byte) kyber.Point
}

// hashtoG1 securely hashes a message into a point on G1
func hashtoG1(suite pairing.Suite, msg []byte) kyber.Point {
	hashable, ok := suite.G1().Point().(hashablePoint)
	if !ok {
		log.Printf("Point cannot be hashed")
	}
	hashed := hashable.Hash(msg)
	return hashed
}

// insecureHashtoG2 hashes a message to a point in G2 by using the message as a seed for the Pick method
// !!! Unsure whether this is collision resistant !!!
// To be replaced by a secure version that follows https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07
func insecureHashtoG2(suite pairing.Suite, msg []byte) kyber.Point {
	seed := blake2xb.New(msg)
	hashed := suite.G2().Point().Pick(seed)

	return hashed
}

// Hash hashes a msg to a point on the requested curve
func Hash(suite pairing.Suite, group kyber.Group, msg []byte) (kyber.Point, error) {
	if group.String() == "bn256.G1" {
		return hashtoG1(suite, msg), nil
	} else if group.String() == "bn256.G2" {
		return insecureHashtoG2(suite, msg), nil
	} else {
		return nil, errors.New("hash: group not recognised")
	}
}
