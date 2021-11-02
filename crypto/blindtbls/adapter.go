package blindtbls

import (
	"bytes"
	"encoding/binary"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

// SigSharetoPubShare converts a SigShare (byte representation) to a PubShare (complex representation)
func SigSharetoPubShare(group kyber.Group, sig tbls.SigShare) (*share.PubShare, error) {
	i, err := sig.Index()
	if err != nil {
		return &share.PubShare{I: -1, V: nil}, err
	}

	point := group.Point()
	if err := point.UnmarshalBinary(sig.Value()); err != nil {
		return &share.PubShare{I: -1, V: nil}, err
	}

	return &share.PubShare{I: i, V: point}, nil

}

// PubSharetoSigShare converts a PubShare (complex representation) to a SigShare (byte representation)
func PubSharetoSigShare(sig *share.PubShare) (tbls.SigShare, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, uint16(sig.I)); err != nil {
		return nil, err
	}
	point, _ := sig.V.MarshalBinary()
	if err := binary.Write(buf, binary.BigEndian, point); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
