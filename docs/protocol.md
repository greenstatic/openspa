# OpenSPA Protocol
Version: **0.1.0 ALPHA**

## Status
This protocol is currently a draft for the final specification.

## Introduction
OpenSPA is an open-source software application that implements Single Packet Authorization (SPA).
The application is designed to be extensible with support for implementing any firewall support and client authorization mechanisms.

OpenSPA uses the OpenSPA protocol to define the messages exchanged between the client and server.

## Versioning Scheme
Currently the protocol is in alpha, meaning anything can change without warning or support for backwards compatibility.
Current implementations may use the version number `0x1`, although careful attention should be taken to reflect changes that will be present in the official release of version 1.0 of the protocol.

## Typical Sequence of Events
1. The client creates an OpenSPA request packet where it includes the device ID, protocol and port(s), public IP to allow access to, digital signature and a couple of network related fields. 
This packet is encrypted and sent to the OpenSPA server using a UDP datagram.
2. The server receives the packet and attempts to parse it, verify the signature and check if the user is authenticated and authorized. 
In case any of the previous fail, the server silently drops the packet - no error response message is sent.
4. After successfully authenticating and authorizing the user, the server opens the requested firewall port for the requested public IP.
5. The server sends an encrypted OpenSPA response packet that contains the whitelisted protocol and port(s) along with the duration the client is allowed to access.
6. After the duration expires the server removes the whitelist rule.

## Packet Format
OpenSPA protocol defines two types of packets: request and response.
Both packets contain the same formatted header.

All packets have an upper bound of 1232 octets.
The upper bound of OpenSPA packets is inherently affected by the data link layer MTU size.
A common MTU is Ethernet's 1500 octet MTU.
The decision to limit the size of OpenSPA packets to only 1232 was decided empirically.
This would allow OpenSPA to be used in environments where IP header packet manipulation is performed since the reduced size would allow such techniques to be used without splitting the packet into multiple pieces.

### Header
The packet header contains the following fields:
- **Version (4 bits)**: Specifies the version of the protocol (0001 = v1).
- **Type (1 bit)**: Denotes the packet payload type (0=request, 1=response).
- **Reserved (5 bits)**: Field reserved for future use.
- **Encryption Method (6 bits)**: The method the payload was encrypted, see 
[Encryption & Signature](#encryption-&-signature).

<pre>
0                   1            
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|T|Reserved |Enc. Method|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
</pre>

Thus the header size (incl. reserved fields) is 2 octets.

### Request
Request packet (encrypted) payload.
- **Timestamp (8 octets)**: A UNIX 64-bit timestamp when the packet was created.
- **Client Device ID (16 octets)**: The unique UUID of the device.
- **Nonce (3 octets)**: A random nonce value to prevent replay attacks.
- **Protocol (1 octet)**: The protocol for which the client is requesting access 
(e.g. TCP, UDP, ICMP, etc.) determined by the 
[IANA Assigned Internet Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).
- **Start Port (2 octets)**: The port the client is requesting access to.
- **End Port (2 octets)**: The last port the client is requesting access to in 
case the client wishes to request access to a port interval (e.g. 6881-6887). 
In case the client wishes access to a single port, then this field should 
mirror the start port field.
- **Signature Method (1 octet)**: Method that the packet was signed.
- NAT flag (1 bit): A flag that the client sets to true if they detect that 
they are behind a NAT. This is used by the OpenSPA server to determine if 
the current policy allows such access.
- **Reserved (23 bit)**: Field reserved for future use.
- **Client Public IP (16 octets)**: The client’s IPv4 or IPv6 public IP address 
that requires access.
- **Server Public IP (16 octets)**: The server’s IPv4 or IPv6 public IP address 
that we are requiring access to.
- **Signature (1162 octets max.)**: The user signature for the packet.


<pre>
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                           Timestamp                           +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                        Client Device ID                       +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Nonce                  |    Protocol   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Start Port          |           End Port            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Sig. Method  |N|                 Reserved                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                        Client Public IP                       +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                        Server Public IP                       +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                            Signature                          +
|                                                               |
...                                                           ...
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
</pre>

The maximum total size of the OpenSPA request payload (incl. reserved fields) is therefore 1230 octets.


### Response
Response packet (encrypted) payload.
- **Timestamp (8 octets)**: A UNIX 64-bit timestamp when the packet was created.
- **Nonce (3 octets)**: A random nonce value to prevent replay attacks.
- **Protocol (1 octet)**: The protocol for which the client has received access 
to (e.g. TCP, UDP, ICMP, etc.) determined by the IANA Assigned Internet Protocol Numbers [8].
- **Start Port (2 octets)**: The start port the client has received access to.
- **End Port (2 octets)**: The end port the client has received access to. In 
case of a single port then this field should mirror the start port field.
- **Duration (2 octets)**: The duration in seconds the client has access to the 
aforementioned protocol/port.
- **Signature Method (1 octet)**: Method that the packet was signed.
- **Reserved (5 octets)**: Field reserved for future use.
- **Signature (1206 octets 9 max.)**: The packet signature.

<pre>
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                           Timestamp                           +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Nonce                  |    Protocol   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Start Port          |           End Port            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Duration           |  Sig. Method  |    Reserved   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Reserved                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                            Signature                          +
|                                                               |
...                                                           ...
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
</pre>

The maximum total size of the OpenSPA response payload (incl. reserved fields) is therefore 1230 octets.


## Signature & Encryption
Currently there is only support for a single signature and encryption method.
We encourage suggestions regarding which methods to add.

Even though currently there is only support for a single method using public-key cryptography, the use of symmetric-key cryptography is not discouraged.

### Signature
| Method ID | Signature Method                        |
| ---------:| --------------------------------------- |
| 0x01      | RSA PKCS#1 v1.5 2048 bit + SHA-256      |

#### Methods
##### Method: 0x01: RSA PKCS#1 v1.5 2048 bit + SHA-256
The private key used is of the device (server, client) that is signing the packet.
```
Signature = PKCS1v15( SHA-256( header || unsigned payload ), private key )
```

### Encryption
| Method ID | Encryption Method                       |
| ---------:|:----------------------------------------|
| 0x01      | RSA PKCS#1 v1.5 2048 bit + AES-256-CBC  |

#### Methods
##### Method: 0x01: RSA PKCS#1 v1.5 2048 bit + AES-256-CBC
We first encrypt using a random AES key and IV the payload.
Then the AES key is encrypted using RSA and appended as the prefix of the ciphertext.
The public key used is of the device (server, client) we are sending the packet to.

```
Encrypted payload = PKCS1v15( AES key, public key ) || IV || AES-256-CBC( IV, signed payload || padding, AES key )
```

The signed payload is padded using [PKCS #7: Cryptographic Message Syntax](https://tools.ietf.org/html/rfc2315), section *10.3 Content-encryption process*, note *2*.