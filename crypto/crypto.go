package crypto

import (
	"errors"

	"github.com/nmohnblatt/contact_discovery2/crypto/dedishash"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
)

// ConstrainingKeys holds the left and right constaining keys. Both are Kyber points
type ConstrainingKeys struct {
	Left  kyber.Point
	Right kyber.Point
}

// PublicKeys holds the left and right public keys as derived from the discovery identifier. Both are Kyber points
type PublicKeys struct {
	Left  kyber.Point
	Right kyber.Point
}

// MasterSecretShares contains shares of the master secret for each group
type MasterSecretShares [2]*share.PriShare

// SharedKeys represents shared keys between Alice and Bob
// Outgoing is Shared(Alice, Bob), Incoming is Shared(Bob, Alice)
type SharedKeys struct {
	Outgoing kyber.Point
	Incoming kyber.Point
}

// DerivePublicKeys takes an identifier as input and returns the corresponding public keys
func DerivePublicKeys(suite pairing.Suite, identifier string) PublicKeys {
	var keys PublicKeys

	keys.Left, _ = dedishash.Hash(suite, suite.G1(), []byte(identifier))
	keys.Right, _ = dedishash.Hash(suite, suite.G2(), []byte(identifier))

	return keys
}

// DeriveSharedKeys returns shared keys between users A and B:
// shared12 = e(H1(idA)^s, H2(idB)) = e(H1(idA), H2(idB))^s
// shared21 = e(H1(idB), H2(idA)^s) = e(H1(idB), H2(idA))^s
func DeriveSharedKeys(suite pairing.Suite, aliceKeys ConstrainingKeys, contactIdentifier string) (kyber.Point, kyber.Point) {
	bobPk := DerivePublicKeys(suite, contactIdentifier)
	sharedA1B2 := suite.Pair(aliceKeys.Left, bobPk.Right)
	sharedB1A2 := suite.Pair(bobPk.Left, aliceKeys.Right)

	return sharedA1B2, sharedB1A2
}

// xorBytes is a bytewise XOR operation for same-sized slices of bytes
func xorBytes(a, b []byte) ([]byte, error) {
	var c []byte
	if len(a) != len(b) {
		return nil, errors.New("xorBytes: arguments must be of the same length")
	}

	for i := 0; i < len(a); i++ {
		buf := (int(a[i]) + int(b[i])) % 256
		c = append(c, byte(buf))
	}

	return c, nil
}

// KeyDerivationFunction takes the shared points computed by a user and returns some key material.
// We would normally want a secure KDF however for this POC we just XOR the key material we obtained
func KeyDerivationFunction(sharedAB, sharedBA kyber.Point) ([]byte, error) {
	bytesSharedAB, _ := sharedAB.MarshalBinary()
	bytesSharedBA, _ := sharedBA.MarshalBinary()

	keymaterial, err := xorBytes(bytesSharedAB, bytesSharedBA)
	return keymaterial, err
}
