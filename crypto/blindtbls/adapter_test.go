package blindtbls

import (
	"testing"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestConvert(t *testing.T) {
	suite := bn256.NewSuite()
	integer := 1
	point := suite.G1().Point().Pick(random.New())

	A := &share.PubShare{I: integer, V: point}

	B, err := PubSharetoSigShare(A)
	if err != nil {
		t.Error(err)
	}

	BI, err := B.Index()
	if err != nil {
		t.Error(err)
	}

	if BI != integer {
		t.Errorf("Wrong index")
	}

	testPoint := suite.G1().Point()
	if err := testPoint.UnmarshalBinary(B.Value()); err != nil {
		t.Error(err)
	}

	if !testPoint.Equal(point) {
		t.Errorf("wrong value")
	}
}
