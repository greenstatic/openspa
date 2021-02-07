# Echo IP
A small Go web service to return the client's public IP.

Features:
- HTTP/HTTPS support
- IPv4/IPv6 support
- Apache Common Log Format (CLF)
- No need for web server or reverse proxy
- GET & POST support
- Docker support

## Example Response
### Request
```http request
GET /
```
### Response
```json
{
    "success": true,
    "ip": "212.235.188.20",
    "datetime": "2018-07-22T21:24:11+02:00",
    "ipDetails": {
        "remoteIP": "212.235.188.20",
        "forwardedForIP": ""
    },
    "service": "echo-ip",
    "version": "1.2.0",
    "srcUrl": "https://github.com/greenstatic/echo-ip"
}
```

In case the HTTP request contains an `X-Forwarded-For` header, we will replace
the `ip` address response field with the specified value. This is useful in cases
where there is a proxy between the client and the server. However both IPs are
still explicitly defined in the `ipDetails` field.

## Server
```
A small go web service to return the client's public IP.

Usage:
  echo-ip [flags]

Flags:
  -b, --bind ip          Bind to IP (IPv4/IPv6) (default 0.0.0.0)
  -c, --cert string      Server's HTTPS certificate
  -h, --help             help for echo-ip
  -p, --port uint16      Port to listen to
  -k, --privKey string   Server's certificate private key

```

By default the server will try to listen to port `80` (HTTP) however 
if both `--cert` and `--privKey` flags are supplied a HTTPS server 
on default port `443` will be started. The port can always be overridden
using the `--port` flag.

To run the server in IPv6 mode bind the address to `::`.

To view the help output run: `echo-ip --help`.

### Endpoints
- GET/POST /: IP details response (see example response)
- GET/POST /health: health information about the web service

Note: HTTP POST methods are supported in case the client wishes to bypass 
proxies that cache HTTP GET requests/responses but ignore HTTP POST.

## Download
You can download a standalone complied version of the server on the 
[releases page](https://github.com/greenstatic/echo-ip/releases) 
of this repository.

Note, this software is only for GNU/Linux.

## Docker Container
A Docker container is available: [here](https://hub.docker.com/r/greenstatic/echo-ip/).

```bash
docker pull greenstatic/echo-ip
```

### Examples
To run the container here are some examples:

To run a HTTP server:
```bash
docker run --name echoip -p 80:8080 -d greenstatic/echo-ip
```
The container will by default listen to port `8080`.

To run a HTTPS server (with certificate/key on the local filesystem):
```bash
docker run --name echoip -p 443:443 -d -v /home/greenstatic/certs:/cert:ro  greenstatic/echo-ip -c /cert/server.crt -k /cert/server.key
```

## Build
The `scripts/` directory contains three scripts used for building.
- build_standalone.sh <version>: Run this to build the Go project as a standalone
executable, with a version number (eg. "1_0_0")
- build_container.sh <version>: Run this to build a docker container, with
a version number (eg. 1.0.0 - note the dots instead of the underscores).
This will build a docker container `echo-ip:<version>`, to change this edit the script.
- build_clean.sh: Run this after to remove the build(s) that were run 
(does not touch docker or any docker images).

Note: you **MUST** have your working directory (PWD) inside the `scripts` 
directory. The script checks this in case you accidentally launch outside
of the directory.

If the build is successful you will find a new directory `bin` inside the 
root of the project. Inside you will find the build executable and a 
compressed tar.gz file. On `build_clean.sh` this directory will be 
removed along with all the builds and compressed files.

## Devlopment
Install dependencies using (working directory must be the root of the repository):
```bash
go get ./...
```

## Future Features
- Let's Encrypt support to automatically refresh certificates and restart
the server
- Reverse IP lookup details in response
- IP address details in response (using something like GeoIP DB)
- Would be nice (necessary) to write some tests
- User agent support in logs