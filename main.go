package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
)

func main() {
	// 1) SETUP SERVERS
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

	// 2) SETUP ONLINE CACHE FOR MEETING POINTS
	onlineCache := make(meetingPlatform)

	// 3) SETUP USERS
	electra := newUser(parameters, "electra", []string{"arke", "thaumas"})
	thaumas := newUser(parameters, "thaumas", []string{"arke", "electra"})

	users := []*user{electra, thaumas}

	for _, u := range users {
		u.requestContrainingKeys(parameters, serverList)
		u.computeSharedKeys(parameters)
		for _, contact := range u.contacts {
			u.insecureMeet(contact, onlineCache)
		}
	}

	// 4) DISCOVERY!
	fmt.Println("PoC for the privacy preserving contact discovery service. In this demo you will be prompted to sign up to the service by using a username and entering some contacts. You may enter any identifiers you desire. To test the functionality, some users have already been built in to the platform and are expecting the arrival of one special guest, can you find who it is?")
	fmt.Println("\nPlease enter your discovery identifier (username, mobile number, etc...):")
	var identifier string
	fmt.Scanf("%s", &identifier)
	fmt.Println("\nEnter your contacts' discovery identifiers separated by spaces:")
	reader := bufio.NewReader(os.Stdin)
	contactString, _ := reader.ReadString('\n')
	contactString = strings.TrimSuffix(contactString, "\n")
	contacts := strings.Fields(contactString)

	externalUser := newUser(parameters, identifier, contacts)
	fmt.Printf("\nWelcome %s!\n\n", externalUser.DiscoveryIdentifier)

	externalUser.requestContrainingKeys(parameters, serverList)
	fmt.Printf("Successfully fetched your constraining keys from %d out of %d servers\n", parameters.Threshold, parameters.TotalServers)

	externalUser.computeSharedKeys(parameters)
	fmt.Printf("Your constraining keys were used locally to derive shared secrets with your contacts. Checking meeting points...\n")

	totalSignedUp := 0
	for _, contact := range externalUser.contacts {
		externalUser.insecureMeet(contact, onlineCache)
		if present, found := externalUser.contactPresence[contact]; found {
			if present {
				fmt.Printf("Your friend %s has already signed up and searched for you\n", contact)
				totalSignedUp++
			}
		}
	}

	fmt.Printf("\nFound %d contacts\n", totalSignedUp)

}
