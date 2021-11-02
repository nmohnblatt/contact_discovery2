package morebls

import (
	"testing"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestBLS(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, public := NewKeyPair2(suite, random.New())
	sig, err := Sign2(suite, private, msg)
	if err != nil {
		t.Errorf("%s", err)
	}
	err = Verify2(suite, public, msg, sig)
	if err != nil {
		t.Errorf("Signature did not match")
	}
}

func TestBLSFailSig(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, public := NewKeyPair2(suite, random.New())
	sig, err := Sign2(suite, private, msg)
	if err != nil {
		t.Errorf("%s", err)
	}
	sig[0] ^= 0x01
	if Verify2(suite, public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func TestBLSFailKey(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, _ := NewKeyPair2(suite, random.New())
	sig, err := Sign2(suite, private, msg)
	if err != nil {
		t.Errorf("%s", err)
	}
	_, public := NewKeyPair2(suite, random.New())
	if Verify2(suite, public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}
