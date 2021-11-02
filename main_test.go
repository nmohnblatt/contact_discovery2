package main

import (
	"testing"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestSharedKeyDerivationLocal(t *testing.T) {
	// 1) SETUP

	// Set public parameters
	var parameters publicParameters
	parameters.TotalServers = 9 // this can be decided at setup
	parameters.Threshold = 3    // t-of-n, using 1/3 as an example
	parameters.Suite = bn256.NewSuite()

	// Ideally servers would run a DKG protocol
	// Instead here we generate a master secret key and will share it
	masterSecret := parameters.Suite.G1().Scalar().Pick(random.New())
	serverList := make([]*server, parameters.TotalServers)
	serverList, parameters.PublicPolynomials[0], parameters.PublicPolynomials[1] = setupThresholdServers(parameters, masterSecret)

	// run servers, each server is its own go-routine
	for _, s := range serverList {
		go s.runServer(parameters)
	}

	// 2) USERS

	arke := newUser(parameters, "arke", []string{"thaumas", "electra"})
	electra := newUser(parameters, "electra", []string{"arke", "thaumas"})
	thaumas := newUser(parameters, "thaumas", []string{"arke", "iris"})
	rando := newUser(parameters, "rando", []string{"arke", "thaumas", "electra"})

	users := []*user{arke, electra, thaumas, rando}
	family := []*user{arke, electra, thaumas}

	for _, u := range users {
		u.requestContrainingKeys(parameters, chooseTofNservers(parameters, serverList))
		u.computeSharedKeys(parameters)
	}

	for _, u := range family {
		for _, val := range u.sharedKeys {
			for _, randoVal := range rando.sharedKeys {
				if val.Incoming.Equal(randoVal.Incoming) || val.Outgoing.Equal(randoVal.Outgoing) || val.Incoming.Equal(randoVal.Outgoing) || val.Outgoing.Equal(randoVal.Incoming) {
					t.Errorf("Some keys are shared between %s and rando", u.DiscoveryIdentifier)
				}
			}
		}
	}

}

func TestConstrainingKeys(t *testing.T) {
	// 1) SETUP

	// Set public parameters
	var parameters publicParameters
	parameters.TotalServers = 9 // this can be decided at setup
	parameters.Threshold = 3    // t-of-n, using 1/3 as an example
	parameters.Suite = bn256.NewSuite()

	// Ideally servers would run a DKG protocol
	// Instead here we generate a master secret key and will share it
	masterSecret := parameters.Suite.G1().Scalar().Pick(random.New())
	serverList := make([]*server, parameters.TotalServers)
	serverList, parameters.PublicPolynomials[0], parameters.PublicPolynomials[1] = setupThresholdServers(parameters, masterSecret)

	// run servers, each server is its own go-routine
	for _, s := range serverList {
		go s.runServer(parameters)
	}

	// 2) USERS

	u1 := newUser(parameters, "nmohnblatt", []string{"mom", "dad"})

	// Obtain constraining keys from t servers
	u1.requestContrainingKeys(parameters, chooseTofNservers(parameters, serverList))

	// Compute the expected values for Alice's private keys
	want1 := parameters.Suite.G1().Point().Mul(masterSecret, u1.publicKeys.Left)
	want2 := parameters.Suite.G2().Point().Mul(masterSecret, u1.publicKeys.Right)

	// Check the value recovered from servers matches the expected value
	if !u1.constrainingKeys.Left.Equal(want1) {
		t.Errorf("Did not compute correct private key 1")
	} else {
		t.Log("private key 1 OK")
	}
	if !u1.constrainingKeys.Right.Equal(want2) {
		t.Errorf("Did not compute correct private key 2")
	}

}
