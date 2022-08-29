# OpenSPA

![GitHub Workflow Status](https://img.shields.io/github/workflow/status/greenstatic/openspa/Test)
[![Go Reference](https://pkg.go.dev/badge/github.com/greenstatic/openspa.svg)](https://pkg.go.dev/github.com/greenstatic/openspa)
[![Go Report Card](https://goreportcard.com/badge/github.com/greenstatic/openspa)](https://goreportcard.com/report/github.com/greenstatic/openspa)
![License](https://img.shields.io/github/license/greenstatic/openspa)

OpenSPA: An open and extensible Single Packet Authorization (SPA) implementation of the [OpenSPA Protocol](docs/protocol.md).

[v1](https://github.com/greenstatic/openspa/tree/v1) of the protocol was created in 2018 and while functioning, it has a 
few shortcomings which are being resolved in v2 (currently the dev branch) of the protocol.

**v2 is currently as of 2022 under heavy development.** No guarantees are made that it will remain backwards compatible 
in it's current form.
We WILL break it during development.

v1 was never production ready and so any PR regarding v1 will be rejected.

## What is OpenSPA?
OpenSPA is an open and extensible SPA implementation built upon the OpenSPA Protocol.
OpenSPA allows the deployment of a service on an internal network or the internet, that is hidden to all unauthorized 
users.
Authorized users authenticate by sending a single packet to the OpenSPA server, which will reveal itself only if the 
user is authorized to access the service.

OpenSPA builds what essentially is a dynamic firewall.

![OpenSPA-Demo](docs/assets/openspa_brief.png)

Unauthorized users will not be able to detect via the network the presence of the hidden service (no ping, traceroute, 
port scans, fingerprinting, etc.).
Once the user sends an OpenSPA request packet (via UDP) and they are authorized only then will the server respond with 
a response.
Unauthorized users thus will also be unable to confirm the existence of the OpenSPA service.

## Version 1 vs. 2?
The major difference between v1 and v2 of the OpenSPA protocol is how binary messages (request & response) are encoded.
Version 1 had a well-defined binary format (e.g. offset X with a length of 32 bits contains the client's IP address).
While this of course worked, it also proved very difficult to extend and modify.
Which is why version 2 uses TLVs to encode the binary messages.
This allows v2 to be customized and extended very easily for difference use-cases.

Version 2 also brings native support for IPtables, making extension scripts optional (or rather an alternative to the 
native IPtables integration to support different firewalls).

## Version 2 Status
Completed:
* openspalib (`pkg/openspalib`) - library for the OpenSPA protocol. With this you can implement your own OpenSPA client 
and server
* client (`cli/openspa-client`) - OpenSPA client CLI

In progress:
* server (`cli/openspa-server`) - OpenSPA server CLI
  * Native IPtables integration is completed
  * Config file support is completed
  * TODO
    * External authentication & authorization integration 
    * External firewall integration

Planned:
* ECC support
* x509 certificate support
* Helper utility to generate keys
* eBPF integration for ADK (Anti DoS knocking protection)
