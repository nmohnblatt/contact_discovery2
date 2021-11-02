package blindbls

import (
	"testing"

	"github.com/nmohnblatt/contact_discovery2/crypto/dedishash"
	"github.com/nmohnblatt/contact_discovery2/crypto/morebls"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestCheckGroup(t *testing.T) {
	suite := bn256.NewSuite()
	p1 := suite.G1().Point()
	p2 := suite.G2().Point()

	if test := CheckGroup(p1, suite.G1()); !test {
		t.Errorf("p1 was not recognised as a G1 point")
	}

	if test := CheckGroup(p2, suite.G2()); !test {
		t.Errorf("p2 was not recognised as a G2 point")
	}

	if test := CheckGroup(p1, suite.G2()); test {
		t.Errorf("p1 was recognised as a G2 point")
	}

	if test := CheckGroup(p2, suite.G1()); test {
		t.Errorf("p2 was recognised as a G1 point")
	}

}

func TestBlindUnblind(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	H1M, _ := dedishash.Hash(suite, suite.G1(), msg)
	BF := suite.G1().Scalar().Pick(random.New())

	aH1M, err := Blind(suite.G1(), BF, H1M)
	if err != nil {
		t.Errorf("%s", err)
	}

	test, err := Unblind(suite.G1(), BF, aH1M)
	if err != nil {
		t.Errorf("Could not Unblind")
	}

	if !test.Equal(H1M) {
		t.Errorf("Point was not recovered")
	}
}

func TestBlindBLSG1(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	H1M, _ := dedishash.Hash(suite, suite.G1(), msg)
	BF := suite.G1().Scalar().Pick(random.New())
	aH1M, err := Blind(suite.G1(), BF, H1M)
	if err != nil {
		t.Errorf("Could not Blind point")
	}
	blindedPoint := suite.G1().Point()
	if err := blindedPoint.UnmarshalBinary(aH1M); err != nil {
		t.Errorf("%s", err)
	}
	if blindedPoint.Equal(H1M) {
		t.Errorf("No blinding occurred, point is still the same")
	}
	private, public := bls.NewKeyPair(suite, random.New())
	sig, err := Sign(suite.G1(), private, aH1M)
	if err != nil {
		t.Errorf("%s", err)
	}
	xH1M, err := Unblind(suite.G1(), BF, sig)
	if err != nil {
		t.Errorf("%s", err)
	}
	err = Verify(suite, suite.G1(), public, H1M, xH1M)
	if err != nil {
		t.Errorf("Signature did not match")
	}
}

func TestBlindBLSG2(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	H2M, _ := dedishash.Hash(suite, suite.G2(), msg)
	BF := suite.G2().Scalar().Pick(random.New())
	aH2M, err := Blind(suite.G2(), BF, H2M)
	if err != nil {
		t.Errorf("Could not Blind point")
	}
	blindedPoint := suite.G2().Point()
	if err := blindedPoint.UnmarshalBinary(aH2M); err != nil {
		t.Errorf("%s", err)
	}
	if blindedPoint.Equal(H2M) {
		t.Errorf("No blinding occurred, point is still the same")
	}
	private, public := morebls.NewKeyPair2(suite, random.New())
	sig, err := Sign(suite.G2(), private, aH2M)
	if err != nil {
		t.Errorf("%s", err)
	}
	xH1M, err := Unblind(suite.G2(), BF, sig)
	if err != nil {
		t.Errorf("%s", err)
	}
	err = Verify(suite, suite.G2(), public, H2M, xH1M)
	if err != nil {
		t.Errorf("Signature did not match")
	}
}

func TestBlindBLSFailSig(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	H1M, _ := dedishash.Hash(suite, suite.G1(), msg)
	BF := suite.G1().Scalar().Pick(random.New())
	aH1M, err := Blind(suite.G1(), BF, H1M)
	if err != nil {
		t.Errorf("Could not Blind point")
	}
	blindedPoint := suite.G1().Point()
	if err := blindedPoint.UnmarshalBinary(aH1M); err != nil {
		t.Errorf("%s", err)
	}
	if blindedPoint.Equal(H1M) {
		t.Errorf("No blinding occurred, point is still the same")
	}
	private, public := bls.NewKeyPair(suite, random.New())

	msg2 := []byte("Goodbye Boneh-Lynn-Shacham")
	sig2, err := bls.Sign(suite, private, msg2)

	xH1M, err := Unblind(suite.G1(), BF, sig2)
	if err != nil {
		t.Errorf("%s", err)
	}
	err = Verify(suite, suite.G1(), public, H1M, xH1M)
	if err == nil {
		t.Errorf("Verification succeeded on the wrong signature")
	}
}

func TestBlindBLSFailKey(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	H1M, _ := dedishash.Hash(suite, suite.G1(), msg)
	BF := suite.G1().Scalar().Pick(random.New())
	aH1M, err := Blind(suite.G1(), BF, H1M)
	if err != nil {
		t.Errorf("Could not Blind point")
	}
	blindedPoint := suite.G1().Point()
	if err := blindedPoint.UnmarshalBinary(aH1M); err != nil {
		t.Errorf("%s", err)
	}
	if blindedPoint.Equal(H1M) {
		t.Errorf("No blinding occurred, point is still the same")
	}
	private, public := bls.NewKeyPair(suite, random.New())
	sig, err := Sign(suite.G1(), private, aH1M)
	if err != nil {
		t.Errorf("%s", err)
	}
	xH1M, err := Unblind(suite.G1(), BF, sig)
	if err != nil {
		t.Errorf("%s", err)
	}

	_, public = bls.NewKeyPair(suite, random.New())
	err = Verify(suite, suite.G1(), public, H1M, xH1M)
	if err == nil {
		t.Errorf("Verification succeeded using the wrong key")
	}
}
