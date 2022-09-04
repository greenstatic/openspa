# OpenSPA Protocol

## OpenSPA PDU
The OpenSPA PDU contains a fixed 8 octet header and a variable length body.

**OpenSPA PDU**
<pre>
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+ Control Field | Transaction ID| Cipher Suite  |   Reserved    +
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+                           Reserved                            +
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+                                                               +
...                         TLV Body                          ...
+                                                               +
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
</pre>

**Control Field**
<pre>
0                
0 1 2 3 4 5 6 7 8
+-+-+-+-+-+-+-+-+
+T|  V  |   R   +
+-+-+-+-+-+-+-+-+
</pre>

The control field contains:
* T: PDU Type - Request (0) or Response (1)
* V: PDU Version - currently 2
* R: Reserved field for future use

The OpenSPA PDU contains:
* Control Field - see above for control field details
* Transaction ID - a random number identifying the corresponding request and response
* Cipher Suite - the method of securing the body TLV
* TLV Body - the body encoded using TLV8

### Cipher Suite
| ID  | Cipher Suite Method            |
|-----|--------------------------------|
| 1   | RSA + SHA256 + AES256-CBC      |

ID 0 and 255 are invalid.

### TLV Definitions

#### Encrypted TLV8 Definition
| Type | Name              | Format | Size     | Description                                                                                           |
|------|-------------------|--------|----------|-------------------------------------------------------------------------------------------------------|
| 1    | Encrypted Payload | bytes  | variable | Encrypted payload TLV8 (see [Encrypted Payload TLV8 Description](#encrypted-payload-tlv8-definition)) |
| 2    | Encrypted Session | bytes  | variable | Encrypted session key, which can be used to decrypt the encrypted payload                             |

#### Encrypted Payload TLV8 Definition
| Type | Name      | Format | Size     | Description                                            |
|------|-----------|--------|----------|--------------------------------------------------------|
| 1    | Packet    | tlv8   | variable | [OpenSPA Packet TLV8](#openspa-packet-tlv8-definition) |
| 2    | Signature | bytes  | variable |                                                        |
| 3    | Nonce     | bytes  | 3 Bytes  | Random nonce                                           |


#### OpenSPA Packet TLV8 Definition
| Type | Name       | Format | Size     | Description                                           |
|------|------------|--------|----------|-------------------------------------------------------|
| 1    | Timestamp  | uint64 | 8 Bytes  | UNIX timestamp of the packet in seconds               |
| 2    | ClientUUID | bytes  | 16 Bytes | Client's UUID used for authentication & authorization |
| 3    | Firewall   | tlv8   | variable | [Firewall TLV8](#firewall-tlv8-definition)            |

#### Firewall TLV8 Definition
| Type | Name            | Format           | Size     | Description                                                            |
|------|-----------------|------------------|----------|------------------------------------------------------------------------|
| 1    | TargetProtocol  | uint8            | 1 Byte   | Target Protocol (TCP, UDP, ICMP, ICMPv6)                               |
| 2    | TargetPortStart | uint16           | 2 Bytes  | Target Port Start range if the protocol supports ports (e.g. TCP, UDP) |
| 3    | TargetPortEnd   | uint16           | 2 Bytes  | Target Port End range if the protocol supports ports (e.g. TCP, UDP)   |
| 4    | ClientIPv4      | uint32           | 4 Bytes  | Client's IPv4 address to grant access to target protocol/port          |
| 5    | ClientIPv6      | bytes            | 16 Bytes | Client's IPv6 address to grant access to target protocol/port          |
| 6    | TargetIPv4      | uint32           | 4 Bytes  | Target IPv4 address, client wishes to access                           |
| 7    | TargetIPv6      | bytes            | 16 Bytes | Target IPv6 address, client wishes to access                           |
| 8    | Duration        | unsigned integer | 3 Bytes  | Duration the firewall rule is enabled before expiring                  |

---

<!--

| Type | Name            | Format           | Size     | Description                                                            |
|------|-----------------|------------------|----------|------------------------------------------------------------------------|
| 1    | Timestamp       | uint64           | 8 Bytes  | UNIX timestamp of the packet in seconds                                |
| 2    | ClientUUID      | bytes            | 16 Bytes | Client's UUID used for authentication & authorization                  |
| 3    | TargetProtocol  | uint8            | 1 Byte   | Target Protocol (TCP, UDP, ICMP, ICMPv6)                               |
| 4    | TargetPortStart | uint16           | 2 Bytes  | Target Port Start range if the protocol supports ports (e.g. TCP, UDP) |
| 5    | TargetPortEnd   | uint16           | 2 Bytes  | Target Port End range if the protocol supports ports (e.g. TCP, UDP)   |
| 6    | ClientIPv4      | uint32           | 4 Bytes  | Client's IPv4 address to grant access to target protocol/port          |
| 7    | ClientIPv6      | bytes            | 16 Bytes | Client's IPv6 address to grant access to target protocol/port          |
| 8    | TargetIPv4      | uint32           | 4 Bytes  | Target IPv4 address, client wishes to access                           |
| 9    | TargetIPv6      | bytes            | 16 Bytes | Target IPv6 address, client wishes to access                           |
| 10   | Nonce           | bytes            | 3 Bytes  | Random nonce                                                           |
| 11   | Duration        | unsigned integer | 3 Bytes  | Duration the firewall rule is enabled before expiring                  |


-->