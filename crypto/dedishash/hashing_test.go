package dedishash

import (
	"testing"

	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func TestHashToG2(t *testing.T) {
	suite := bn256.NewSuite()
	testMsg := "this is a test message"
	hash1 := insecureHashtoG2(suite, []byte(testMsg))
	hash2 := insecureHashtoG2(suite, []byte(testMsg))

	if !hash1.Equal(hash2) {
		t.Errorf("Hashing the same message yield different points")
	}
}
