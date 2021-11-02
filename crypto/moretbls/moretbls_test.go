package moretbls

import (
	"testing"

	"github.com/nmohnblatt/contact_discovery2/crypto/morebls"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

func TestTBLS(test *testing.T) {
	var err error
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	n := 10
	t := n/2 + 1
	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G1(), t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G1().Point().Base())
	sigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := Sign2(suite, x, msg)
		if err != nil {
			test.Errorf("%s", err)
		}
		sigShares = append(sigShares, sig)
	}
	sig, err := Recover2(suite, pubPoly, msg, sigShares, t, n)
	if err != nil {
		test.Errorf("%s", err)
	}
	err = morebls.Verify2(suite, pubPoly.Commit(), msg, sig)
	if err != nil {
		test.Errorf("Signature did not match")
	}
}
