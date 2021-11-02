package main

import (
	"github.com/nmohnblatt/contact_discovery2/crypto"
	"github.com/nmohnblatt/contact_discovery2/crypto/blindtbls"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
)

type server struct {
	ID    int
	keys  crypto.MasterSecretShares
	Comms chan keysInTransport
}

func (s server) sign(suite pairing.Suite, userPublic keysInTransport) ([]byte, []byte, error) {

	buf1, err := blindtbls.Sign(suite, suite.G1(), s.keys[0], userPublic.Left)
	if err != nil {
		return nil, nil, err
	}

	buf2, _ := blindtbls.Sign(suite, suite.G2(), s.keys[1], userPublic.Right)
	if err != nil {
		return nil, nil, err
	}

	return buf1, buf2, nil
}

func (s server) runServer(parameters publicParameters) {
	for {
		toSign := <-s.Comms

		left, right, _ := s.sign(parameters.Suite, toSign)
		outputMessage := keysInTransport{left, right, nil}

		s.Comms <- outputMessage
	}
}

// NewServer creates an instance of a server
func newServer(id int, key1, key2 *share.PriShare, comms chan keysInTransport) *server {
	return &server{
		ID:    id,
		keys:  [2]*share.PriShare{key1, key2},
		Comms: comms,
	}
}
