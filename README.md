# Privacy-Preserving Contact Discovery / ARKE - PoC
This is an improved version of the work I submitted as part of my masters degree [dissertation](https://github.com/nmohnblatt/ucl_dissertation) at UCL. The (not so great) original can be found [here](https://github.com/nmohnblatt/cd_client)

    "PoC for the privacy preserving contact discovery service. In this demo you will be prompted to sign up to the service by using a username and entering some contacts. You may enter any identifiers you desire. To test the functionality, some users have already been built in to the platform and are expecting the arrival of one special guest, can you find who it is?"

## System Requirements
Application has only been tested on Linux. Requires [Go](https://golang.org) v1.14 or later.

## Current Functionnality
1. `n` servers are initialised, of which at least `t` are assumed to be honest
2. users sign up with an identifier and enter their contacts
3. the user's identifier is blinded and sent to `t` servers to obtain **constraining keys**
4. the ocnstraining keys are used to derive unique key material for each contact
5. steps 2-4 are repeated for each user
6. users make sue of the derived key material to establish a meeting point on an "online" cache

## TODO
- prevent impersonation: currently users can claim any identifier they want, even if it does not belong to them. In the ARKE construction, a mechanism is designed to avoid this (see [write-up](https://github.com/nmohnblatt/ucl_dissertation))
- use key material to establish a **secure** meeitng point, ideally truly online (IPFS)


## Running the application

There are two ways to run this applications:
- run tests to verify that it works
- run the binary to play aorund. As mentioned above, some users are initialised and are expecting a specific user.

In a new terminal window, clone the repository into your `GOPATH/src` directory and install the application. In this example, `GOPATH` is set to the default value `$HOME/go`:

    $ cd $HOME/go/src
    $ git clone https://github.com/nmohnblatt/contact_discovery2.git
    $ go install github.com/nmohnblatt/contact_discovery2

NOTE: you can check the value of GOPATH by running the command `go env GOPATH`

Run the application by simply typing:

    $ contact_discovery2

Alternatively, you can navigate to your `GOPATH/bin` directory and run the application. Again in this example `GOPATH` os set to the default value `$HOME/go`:

    $ cd $HOME/go/bin
    $ ./cd_client