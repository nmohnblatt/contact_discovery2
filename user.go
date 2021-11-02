package main

import (
	"encoding/hex"
	"errors"

	"github.com/nmohnblatt/contact_discovery2/crypto"
	"github.com/nmohnblatt/contact_discovery2/crypto/blindbls"
	"github.com/nmohnblatt/contact_discovery2/crypto/blindtbls"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"go.dedis.ch/kyber/v3/util/random"
)

type user struct {
	DiscoveryIdentifier string
	contacts            []string
	publicKeys          crypto.PublicKeys
	constrainingKeys    crypto.ConstrainingKeys
	sharedKeys          map[string]crypto.SharedKeys
	contactPresence     map[string]bool
}

func newUser(parameters publicParameters, identifier string, contacts []string) *user {
	addressBook := make(map[string]bool)
	for _, contact := range contacts {
		addressBook[contact] = false
	}

	return &user{
		DiscoveryIdentifier: identifier,
		contacts:            contacts,
		publicKeys:          crypto.DerivePublicKeys(parameters.Suite, identifier),
		constrainingKeys:    crypto.ConstrainingKeys{Left: parameters.Suite.G1().Point(), Right: parameters.Suite.G2().Point()},
		sharedKeys:          make(map[string]crypto.SharedKeys),
		contactPresence:     addressBook,
	}
}

func (u *user) requestContrainingKeys(parameters publicParameters, serverlist []*server) error {
	t := parameters.Threshold
	n := parameters.TotalServers

	if len(serverlist) < parameters.Threshold {
		return errors.New("Not enough servers to meet the threshold")
	}

	// Choose a blinding factor (one per group)
	BF := [2]kyber.Scalar{parameters.Suite.G1().Scalar().Pick(random.New()), parameters.Suite.G2().Scalar().Pick(random.New())}

	// Blind
	aH1M, err := blindtbls.Blind(parameters.Suite.G1(), BF[0], u.publicKeys.Left)
	if err != nil {
		return err
	}
	aH2M, err := blindtbls.Blind(parameters.Suite.G2(), BF[1], u.publicKeys.Right)
	if err != nil {
		return err
	}

	// Keep an unmarshalled representation for later
	blindedPublic := crypto.PublicKeys{Left: parameters.Suite.G1().Point(), Right: parameters.Suite.G2().Point()}

	if err := blindedPublic.Left.UnmarshalBinary(aH1M); err != nil {
		return err
	}
	if err := blindedPublic.Right.UnmarshalBinary(aH2M); err != nil {
		return err
	}

	// Sign
	buf1 := make([][]byte, len(serverlist))
	buf2 := make([][]byte, len(serverlist))

	for i, s := range serverlist {
		s.Comms <- keysInTransport{aH1M, aH2M, nil}
		received := <-s.Comms
		if received.Error != nil {
			return received.Error
		}

		buf1[i] = received.Left
		buf2[i] = received.Right

	}

	// Recover
	buf1Formatted := make([]*share.PubShare, len(buf1))
	buf2Formatted := make([]*share.PubShare, len(buf2))
	for i := 0; i < len(buf1); i++ {
		buf1Formatted[i], err = blindtbls.SigSharetoPubShare(parameters.Suite.G1(), tbls.SigShare(buf1[i]))
		if err != nil {
			return err
		}
		buf2Formatted[i], err = blindtbls.SigSharetoPubShare(parameters.Suite.G2(), tbls.SigShare(buf2[i]))
		if err != nil {
			return err
		}
	}

	blindKey1, err := blindtbls.Recover(parameters.Suite, parameters.Suite.G1(), parameters.PublicPolynomials[0], blindedPublic.Left, buf1Formatted[:t], t, n)
	if err != nil {
		return err
	}
	blindKey2, err := blindtbls.Recover(parameters.Suite, parameters.Suite.G2(), parameters.PublicPolynomials[1], blindedPublic.Right, buf2Formatted[:t], t, n)
	if err != nil {
		return err
	}

	// Unblind
	u.constrainingKeys.Left, err = blindbls.Unblind(parameters.Suite.G1(), BF[0], blindKey1)
	if err != nil {
		return err
	}
	u.constrainingKeys.Right, err = blindbls.Unblind(parameters.Suite.G2(), BF[1], blindKey2)
	if err != nil {
		return err
	}

	return nil
}

func (u *user) computeSharedKeys(parameters publicParameters) {
	for _, contact := range u.contacts {
		sharedAB, sharedBA := crypto.DeriveSharedKeys(parameters.Suite, u.constrainingKeys, contact)
		u.sharedKeys[contact] = crypto.SharedKeys{Outgoing: sharedAB, Incoming: sharedBA}
	}
}

func (u *user) insecureMeet(contact string, onlineCache meetingPlatform) {
	if keys, found := u.sharedKeys[contact]; found {
		keymaterial, _ := crypto.KeyDerivationFunction(keys.Outgoing, keys.Incoming)
		meetingPoint := createMeetingPoint(keymaterial)

		if x, found := onlineCache[meetingPoint]; found {
			if hex.EncodeToString(x) == hex.EncodeToString(keymaterial) {
				u.contactPresence[contact] = true
			}
		} else {
			onlineCache[meetingPoint] = keymaterial
		}
	}
}
