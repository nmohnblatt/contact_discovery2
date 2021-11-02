package blindtbls

import (
	"testing"

	"github.com/nmohnblatt/contact_discovery2/crypto/blindbls"
	"github.com/nmohnblatt/contact_discovery2/crypto/dedishash"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestUnblindShare(test *testing.T) {
	// SETUP PHASE
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	signGroup := suite.G1()
	keyGroup := suite.G2()
	HM, err := dedishash.Hash(suite, signGroup, msg)
	HMBytes, err := HM.MarshalBinary()
	if err != nil {
		test.Error(err)
	}
	BF := signGroup.Scalar().Pick(random.New())
	if err != nil {
		test.Error(err)
	}
	n := 6
	t := n/2 + 1
	secret := signGroup.Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(keyGroup, t, secret, suite.RandomStream())

	// BLIND
	aHM, err := Blind(signGroup, BF, HM)

	// SIGN CLEAR
	clearSigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := Sign(suite, signGroup, x, HMBytes)
		if err != nil {
			test.Error(err)
		}
		clearSigShares = append(clearSigShares, sig)
	}

	// SIGN BLIND
	blindSigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := Sign(suite, signGroup, x, aHM)
		if err != nil {
			test.Error(err)
		}
		blindSigShares = append(blindSigShares, sig)
	}

	// UNBLIND
	testSigShares := make([]*share.PubShare, len(blindSigShares))
	for i := 0; i < len(blindSigShares); i++ {
		buf, err := UnblindShare(signGroup, BF, blindSigShares[i])
		if err != nil {
			test.Error(err)
		}
		testSigShares[i] = buf
	}

	// CHECKS
	for i := 0; i < len(testSigShares); i++ {
		want, err := SigSharetoPubShare(signGroup, tbls.SigShare(clearSigShares[i]))
		if err != nil {
			test.Error(err)
		}
		if testSigShares[i].I != want.I {
			test.Errorf("unblindshares: indexes do not match")
		}
		if !testSigShares[i].V.Equal(want.V) {
			test.Errorf("unblindshares: index %d values do not match", want.I)
			// test.Logf("want %s \n actual %s", want.V.String(), testSigShares[i].V.String())
		} else if testSigShares[i].V.Equal(want.V) {
			test.Logf("unblindshares: index %d OK", want.I)
		}
	}
}

func TestBlindTBLSRecoverThenUnblind(test *testing.T) {
	// SETUP PHASE
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	signGroup := suite.G1()
	keyGroup := suite.G2()
	HM, err := dedishash.Hash(suite, signGroup, msg)
	if err != nil {
		test.Error(err)
	}
	BF := signGroup.Scalar().Pick(random.New())
	if err != nil {
		test.Error(err)
	}
	n := 10
	t := n/2 + 1
	secret := signGroup.Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(keyGroup, t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(keyGroup.Point().Base())

	// BLIND
	aHM, err := Blind(signGroup, BF, HM)

	// SIGN
	blindSigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := Sign(suite, signGroup, x, aHM)
		if err != nil {
			test.Error(err)
		}
		blindSigShares = append(blindSigShares, sig)
	}

	// RECOVER
	aHMPoint := signGroup.Point()
	if err := aHMPoint.UnmarshalBinary(aHM); err != nil {
		test.Error(err)
	}
	blindSigSharesFormat := make([]*share.PubShare, len(blindSigShares))
	for i, sig := range blindSigShares {
		blindSigSharesFormat[i], _ = SigSharetoPubShare(signGroup, tbls.SigShare(sig))
	}
	sig, err := Recover(suite, signGroup, pubPoly, aHMPoint, blindSigSharesFormat[:t], t, n)

	// UNBLIND
	final, _ := blindbls.Unblind(signGroup, BF, sig)

	// CHECKS
	want := signGroup.Point().Mul(secret, HM)
	if !final.Equal(want) {
		test.Errorf("Computed signature does not match expected signature")
	}
	err = blindbls.Verify(suite, signGroup, pubPoly.Commit(), HM, final)
	if err != nil {
		test.Errorf("Signature did not verify")
	}
}

func TestBlindTBLSUnblindThenRecover(test *testing.T) {
	// SETUP PHASE
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	signGroup := suite.G1()
	keyGroup := suite.G2()
	HM, err := dedishash.Hash(suite, signGroup, msg)
	BF := signGroup.Scalar().Pick(random.New())
	if err != nil {
		test.Error(err)
	}
	n := 10
	t := n/2 + 1
	secret := signGroup.Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(keyGroup, t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(keyGroup.Point().Base())

	// BLIND
	aHM, err := Blind(signGroup, BF, HM)

	// SIGN
	blindSigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := Sign(suite, signGroup, x, aHM)
		if err != nil {
			test.Error(err)
		}
		blindSigShares = append(blindSigShares, sig)
	}

	//UNBLIND
	sigShares := make([]*share.PubShare, 0)
	for _, Si := range blindSigShares {
		buf, err := UnblindShare(signGroup, BF, Si)
		if err != nil {
			test.Error(err)
		}
		sigShares = append(sigShares, buf)
	}

	// RECOVER
	sig, err := Recover(suite, signGroup, pubPoly, HM, sigShares[:t], t, n)
	if err != nil {
		test.Error(err)
	}

	// CHECKS
	testPoint := signGroup.Point()
	if err = testPoint.UnmarshalBinary(sig); err != nil {
		test.Error(err)
	}
	want := signGroup.Point().Mul(secret, HM)
	if !testPoint.Equal(want) {
		test.Errorf("Computed signature does not match expected signature")
	}

	err = blindbls.Verify(suite, signGroup, pubPoly.Commit(), HM, testPoint)
	if err != nil {
		test.Errorf("Signature did not match")
	}
}
