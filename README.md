# Privacy-Preserving Contact Discovery / ARKE - PoC
This is an improved version of the work I submitted as part of my masters degree [dissertation](https://github.com/nmohnblatt/ucl_dissertation) at UCL. The (not so great) original can be found [here](https://github.com/nmohnblatt/cd_client).


As is written in the code, I present:
> "PoC for the privacy preserving contact discovery service. In this demo you will be prompted to sign up to the service by using a username and entering some contacts. You may enter any identifiers you desire. To test the functionality, some users have already been built in to the platform and are expecting the arrival of one special guest, can you find who it is?"

## System Requirements
Application has only been tested on Linux. Requires [Go](https://golang.org) v1.14 or later.

This PoC is built on top of the [dedis/kyber](https://github.com/dedis/kyber) library. Note however that this library only allows BLS signatures where messages are points on G1 and public keys are points on G2. In the case of our contact discovery scheme, we need to perform BLS signatures in both groups of our asymmetric pairing. The package `crypto` written as part of the original project implements the missing functionality.

## Current Functionnality
1. `n` servers are initialised, of which at least `t` are assumed to be honest 
2. users sign up with an identifier and enter their contacts
3. the user's identifier is blinded and sent to `t` servers to obtain **constraining keys** (blind threshold BLS signature)
4. the constraining keys are used to derive unique key material for each contact (left-right constrained PRFs)
5. steps 2-4 are repeated for each user
6. users make sue of the derived key material to establish a meeting point on an "online" cache

## TODO
- prevent impersonation: currently users can claim any identifier they want, even if it does not belong to them. In the ARKE construction, a mechanism is designed to avoid this (see [write-up](https://github.com/nmohnblatt/ucl_dissertation))
- use key material to establish a **secure** meeting point, ideally truly online (IPFS)


## Running the application

There are two ways to run this applications:
- run tests to verify that it works
- run the binary to play aorund. As mentioned above, some users are initialised and are expecting a specific user.

To download and run the source code:
```
$ go get github.com/nmohnblatt/contact_discovery2
$ cd /go/src/github.com/nmohnblatt/
$ go build
$ ./contact_discovery2
```
