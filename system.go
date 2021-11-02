package main

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/util/random"
)

// PublicParameters contains all the required public parameters
type publicParameters struct {
	Threshold         int
	TotalServers      int
	Suite             pairing.Suite
	PublicPolynomials [2]*share.PubPoly
}

type keysInTransport struct {
	Left  []byte
	Right []byte
	Error error
}

func setupThresholdServers(parameters publicParameters, secret kyber.Scalar) ([]*server, *share.PubPoly, *share.PubPoly) {
	serverList := make([]*server, parameters.TotalServers)
	if secret == nil {
		secret = parameters.Suite.GT().Scalar().Pick(random.New())
	}

	priPoly1 := share.NewPriPoly(parameters.Suite.G2(), parameters.Threshold, secret, random.New())
	pubPoly1 := priPoly1.Commit(parameters.Suite.G2().Point().Base())
	serverPrivateKeys1 := priPoly1.Shares(parameters.TotalServers)

	priPoly2 := share.NewPriPoly(parameters.Suite.G1(), parameters.Threshold, secret, random.New())
	pubPoly2 := priPoly2.Commit(parameters.Suite.G1().Point().Base())
	serverPrivateKeys2 := priPoly2.Shares(parameters.TotalServers)

	for i := 0; i < parameters.TotalServers; i++ {
		comms := make(chan keysInTransport)
		serverList[i] = newServer(i, serverPrivateKeys1[i], serverPrivateKeys2[i], comms)
	}

	return serverList, pubPoly1, pubPoly2
}
