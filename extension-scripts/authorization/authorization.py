#!/usr/bin/env python3

# Copyright 2018 Gregor R. Krmelj
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# ----------------------------------------------------------------------------------------------------------------------

# OpenSPA authorization extension script. This script will return to stdout
# the number of seconds the user is allowed to access a service in seconds.
#
# Usage:
#   python3 authorization.py <client_device_id> <client_public_ip> <server_public_ip> <protocol>
#                            <start_port> <end_port> <timestamp> <signature_method> <behind_nat>
#
#   client_device_id: client device uuid (uuidv4)
#   client_public_ip: client public ip (IPv4/IPv6) as a string
#   server_public_ip: server public ip (IPv4/IPv6) as a string
#   protocol: the requested protocol as a string (eg. ICMP, TCP, UDP, IPv4)
#   start_port: integer (eg. 80, 443)
#   end_port: integer
#   timestamp: unix timestamp as a DEC string
#   signature_method: string (RSA_SHA256)
#   behind_nat: boolean (1=True, 0=False)
#
#
# The client's user ID should be in the UUIDv4 format WITH DASHES.
#
# This script will return 3 minutes for ALL clients.
#
# VERSION: 1.0.0

import sys
import logging

EXIT_BAD_INPUT = 1
EXIT_INVALID_USER_UUID = 2

ARG_COUNT = 9

logging.basicConfig()
logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)


class Packet:
    def __init__(self, client_device_id, client_public_ip, server_public_ip, protocol, start_port, end_port,
                 timestamp, signature_method, behind_nat):
        self.client_device_id = client_device_id
        self.client_public_ip = client_public_ip
        self.server_public_ip = server_public_ip
        self.protocol = protocol
        self.start_port = start_port
        self.end_port = end_port
        self.timestamp = timestamp
        self.signature_method = signature_method
        self.behind_nat = behind_nat


def main():
    if len(sys.argv) != ARG_COUNT + 1:
        logger.error("Did not specify all required arguments")
        sys.exit(EXIT_BAD_INPUT)

    arguments = []
    for i in range(1, ARG_COUNT + 1):
        arguments.append(sys.argv[i])

    packet = Packet(*arguments)

    duration = user_authorization(packet)

    sys.stdout.write(str(duration)+"\n")
    sys.stdout.flush()
    sys.exit(0)


def user_authorization(packet):
    """
    Returns the user's authorized duration in seconds, if unauthorized the return value
    will be 0.
    """

    minute = 60
    return 3 * minute


if __name__ == "__main__":
    main()
