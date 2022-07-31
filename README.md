# OpenSPA
OpenSPA: An open and extensible Single Packet Authorization (SPA) implementation of the [OpenSPA Protocol](docs/protocol.md).

[v1](https://github.com/greenstatic/openspa/tree/v1) of the protocol was created in 2018 and while functioning, it has a few shortcomings which are being resolved in v2 (currently the dev branch) of the protocol.

**v2 is currently as of 2022 under heavy development.** No guarantees are made that it will remain backwards compatible in it's current form.
We WILL break it during development.

v1 was never production ready and so any PR regarding v1 will be rejected.

## What is OpenSPA?
OpenSPA is an open and extensible SPA implementation built upon the OpenSPA Protocol.
OpenSPA allows the deployment of a service on an internal network or the internet, that is hidden to all unauthorized users.
Authorized users authenticate by sending a single packet to the OpenSPA server, which will reveal itself only if the user is authorized to access the service.

OpenSPA builds what essentially is a dynamic firewall.

![OpenSPA-Demo](docs/assets/openspa_brief.png)

Unauthorized users will not be able to detect via the network the presence of the hidden service (no ping, traceroute, port scans, fingerprinting, etc.).
Once the user sends an OpenSPA request packet (via UDP) and they are authorized only then will the server respond with a response.
Unauthorized users thus will also be unable to confirm the existence of the OpenSPA service.
