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

# OpenSPA rule remove extension script. This script will remove a connection host iptables firewall rule.
#
# Usage:
#   python3 rule_remove.py <CLIENT_DEVICE_ID> <Client IP is "ipv4"/"ipv6"> <CLIENT_IP_ADDRESS>
#                          <Server IP is "ipv4"/"ipv6"> <SERVER_IP_ADDRESS> <Protocol: tcp, udp, icmp, icmpv6>
#                          <START_PORT> <END_PORT> <Client behind NAT: "1"/"0"> <DURATION (s)>
#
#   client_device_id: client device uuid (uuidv4)
#   client_ip_is "ipv4"/"ipv6": if the client's IP that follows is an IPv4/IPv6 address (valid args are: ipv4 or ipv6"
#   client_ip_address: client's ip address as a string
#   server_ip_is "ipv4"/"ipv6": if the servers's IP that follows is an IPv4/IPv6 address (valid args are: ipv4 or ipv6"
#   servers_ip_address: servers's ip address as a string
#   protocol: the protocol as a string (eg. icmp, tcp, udp)
#   start_port: integer (eg. 80, 443)
#   end_port: integer (in case there is only one port make this field a copy of the start_port field, eg. 80 80)
#   client_behind_nat: boolean (1=True, 0=False) if client is behind NAT
#   duration: the duration is seconds how much time the firewall rule will be opened
#
# This script uses iptables/ip6tables as the firewall. All arguments provided are not used, however they are
# provided so you can customize the script to your liking. Please note however if this script has been run
# you should not do any authentication/authorization steps here, since they have been already performed.
# OpenSPA expects this script to run successfully, otherwise a perfectly valid OpenSPA request will be
# dropped and no response to the client will be sent. In case you need to customize the authentication/authorization
# step please checkout the authorization extension script.
#
# This script will wait for the iptables command to release any other active usage and then perform the removal
# of the rule. By default it will wait 10 seconds using the --wait flag. In case the command takes longer or in
# case the entire command takes longer than 15 seconds to respond (by default), we will return a non-zero exit
# status with which the OpenSPA server will understand the removal of the firewall rule was unsuccessful and
# mark the connection host entry from its firewall state management as "stuck".
#
# VERSION: 1.1.0

import logging
import sys
import subprocess
from threading import Timer

# This is the chain that will be used to remove iptable rules.
# Please create it using: "iptables --new-chain OPENSPA"
# then add it to the INPUT chain: "iptables --append INPUT --jump OPENSPA"
# and set the default policy of the INPUT chain to drop: "iptables --policy INPUT drop"
# remember to add any whilelist rules to the INPUT chain in case you wish to
# bypass OpenSPA for a couple of clients (eg. administrators computer).
IPTABLES_OPENSPA_CHAIN = "OPENSPA"

# This is the chain that will be used to block active connections
# once they expire. This rule will forcefully block established
# connections. The way it works is when we remove the allowed rule,
# we will create a block rule inside the OPENSPA-BLOCK chain. This
# allows us to have the ESTABLISHED,RELATED iptables rule to allow responses
# that the host initiates but blocks established connections for OpenSPA
# clients. You can disable this feature by setting
# STATELESS_BLOCK_ENABLE=False. If you disable this feature it means that
# if you have the ESTABLISHED,RELATED iptables rule enabled, if a client
# keeps their connection alive, they will not be blocked by OpenSPA until
# the connection drops.
#
# This is the established,related rule we were talking about:
# iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#
# The rule_add.py script will before allowing a connection try to delete
# the same rule inside the OPENSPA-BLOCK chain in order to clean it up
# a bit. The OPENSPA-BLOCK iptables chain will most of the time be filled
# with unnecessary old rules and it is recommended to clean it up from
# time to time, in order to prevent it from growing. A daily/weekly cron job
# would be ideal - depending on how versatile is your OpenSPA usage.
#
# Note: if the STATELESS_BLOCK feature is enabled here it should be enabled
# in the rule_add.py script as well and vice versa.
# Check README.md for more information.
IPTABLES_OPENSPA_BLOCK_CHAIN = "OPENSPA-BLOCK"
STATELESS_BLOCK_ENABLE = True

# The command timeout is specifically a timeout for the subprocess that will
# run the iptables command. While the wait variable is completely handled
# by iptables using the iptables command argument --wait. The wait variable
# should be less than the command timeout. It is not recommended that you
# edit these values.
IPTABLES_COMMAND_TIMEOUT = 15 # seconds
IPTABLES_WAIT = 10 # seconds

# Process exit statuses
EXIT_BAD_INPUT = 1
EXIT_IPTABLES_COMMAND_TIMEOUT = 2
EXIT_IPTABLES_FAILED_TO_REMOVE_RULE = 2

logging.basicConfig()
logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)


def main(ignore_iptables_failed_to_remove=False):
    required_arguments = ["<CLIENT_DEVICE_ID>", "<Client IP is \"ipv4\"/\"ipv6\">", "<CLIENT_IP_ADDRESS>",
                          "<Server IP is \"ipv4\"/\"ipv6\">", "<SERVER_IP_ADDRESS>", "<Protocol: tcp, udp, icmp>",
                          "<START_PORT>", "<END_PORT>", "<Client behind NAT: \"1\"/\"0\">", "<DURATION (s)>"]

    if len(sys.argv) != len(required_arguments) + 1:  # + 1 because the command is the first arg
        arguments_str = " ".join(required_arguments)
        logger.error("Did not run script correctly, expected %d required arguments: %s",
                     len(required_arguments), arguments_str)
        sys.exit(EXIT_BAD_INPUT)

    # Parse arguments
    client_device_id = sys.argv[1]
    client_ip_is_v4 = True if sys.argv[2].lower() == "ipv4" else False
    client_ip = sys.argv[3]
    server_ip_is_v4 = True if sys.argv[4].lower() == "ipv4" else False
    server_ip = sys.argv[5]
    protocol = sys.argv[6].lower()
    start_port = int(sys.argv[7])
    end_port = int(sys.argv[8])
    client_behind_nat = True if sys.argv[9] == "1" else False
    duration = int(sys.argv[10])

    success = iptables_remove(client_ip, protocol, start_port, end_port, ipv4=client_ip_is_v4)
    if not success and not ignore_iptables_failed_to_remove:
        sys.exit(EXIT_IPTABLES_FAILED_TO_REMOVE_RULE)

    if STATELESS_BLOCK_ENABLE:
        success = iptables_add_block(client_ip, protocol, start_port, end_port, ipv4=client_ip_is_v4)
        if not success and not ignore_iptables_failed_to_remove:
            sys.exit(EXIT_IPTABLES_FAILED_TO_REMOVE_RULE)


def iptables_add_block(client_ip, protocol, start_port, end_port, ipv4=True):
    return iptables(True, IPTABLES_OPENSPA_BLOCK_CHAIN, False, client_ip, protocol, start_port, end_port, ipv4)


def iptables_remove(client_ip, protocol, start_port, end_port, ipv4=True):
    return iptables(False, IPTABLES_OPENSPA_CHAIN, True, client_ip, protocol, start_port, end_port, ipv4)


def iptables(append, chain, accept, client_ip, protocol, start_port, end_port, ipv4):
    """
    Creates an iptables rule.
    If append is True we will add a rule otherwise we will delete the rule.
    The chain is which iptables chain we are operating on (table FILTER).
    The accept is if we wish to mark the rule with --jump ACCEPT otherwise
    we will mark is --jump DROP.

    If ipv4=False then we will use ip6tables.

    append=True, accept=True -> add a rule to the chain which is going to be allowed (ACCEPT)
    append=False, accept=True -> remove a rule from the chain that was added with the previous combo

    append=True, accept=False -> add a rule to the chain which is going to be dropped (DROP)
    append=False, accept=False -> removes a rule from the chain that was added with the previous combo
    """

    command = "iptables"
    if not ipv4:
        command = "ip6tables"

    command_args = ["--append", chain, "--source", client_ip, "-p", protocol]
    if not append:
        command_args = ["--delete", chain, "--source", client_ip, "-p", protocol]

    # If protocol is TCP or UDP add port information, otherwise ignore it (ICMP for example has
    # not ports)
    if protocol == "tcp" or protocol == "udp":
        # In case we only have one port to allow use this simple argument
        if start_port == end_port:
            command_args.extend(["--dport", str(start_port)])
        else:
            # In case we have a port range, use the multiport match feature in iptables
            ports = "{}:{}".format(start_port, end_port)
            command_args.extend(["--match", "multiport", "--dport", ports])

    if accept:
        command_args.extend(["--jump", "ACCEPT"])
    else:
        command_args.extend(["--jump", "DROP"])

    cmd = None

    def timeout():
        # Kills the command process and exists the process with a non-zero exit status.
        # Triggered after the timeout duration after running the iptables command.
        global cmd
        logger.warning("iptables command timed out (in %d seconds), command: %s, args: %s. Killing process",
                       command, command_args)
        cmd.kill()
        sys.exit(EXIT_IPTABLES_COMMAND_TIMEOUT)

    cmd_full = [command] + command_args

    logger.info("Running command: %s", cmd_full)

    cmd = subprocess.Popen(cmd_full)

    # Start timer, in case the iptables command timesout, run the timeout function
    t = Timer(IPTABLES_COMMAND_TIMEOUT, timeout)
    t.start()

    cmd.wait()
    t.cancel()

    if cmd.returncode != 0:
        logger.warning("Failed to execute iptables rule using command: %s", cmd_full)

        logger.error(cmd.stdout)
        logger.error(cmd.stderr)

        return False

    logger.info("Successfully executed iptables rule using command: %s", cmd_full)
    return True


def iptables_add_block(client_ip, protocol, start_port, end_port, ipv4=True):
    """
    Adds a rule to the iptables FILTER table to allow a host to connect.
    If ipv4=False then we will use ip6tables.
    """

    command = "iptables"
    if not ipv4:
        command = "ip6tables"

    command_args = ["--append", IPTABLES_OPENSPA_BLOCK_CHAIN, "--source", client_ip, "-p", protocol]

    # If protocol is TCP or UDP add port information, otherwise ignore it (ICMP for example has
    # not ports)
    if protocol == "tcp" or protocol == "udp":
        # In case we only have one port to allow use this simple argument
        if start_port == end_port:
            command_args.extend(["--dport", str(start_port)])
        else:
            # In case we have a port range, use the multiport match feature in iptables
            ports = "{}:{}".format(start_port, end_port)
            command_args.extend(["--match", "multiport", "--dport", ports])

    command_args.extend(["--jump", "DROP"])
    cmd = None

    def timeout():
        # Kills the command process and exists the process with a non-zero exit status.
        # Triggered after the timeout duration after running the iptables command.
        global cmd
        logger.warning("iptables command timed out (in %d seconds), command: %s, args: %s. Killing process",
                       command, command_args)
        cmd.kill()
        sys.exit(EXIT_IPTABLES_COMMAND_TIMEOUT)

    cmd_full = [command] + command_args

    logger.info("Running command: %s", cmd_full)

    cmd = subprocess.Popen(cmd_full)

    # Start timer, in case the iptables command timesout, run the timeout function
    t = Timer(IPTABLES_COMMAND_TIMEOUT, timeout)
    t.start()

    cmd.wait()
    t.cancel()

    if cmd.returncode == 0:
        logger.info("Successfully added iptables block rule using command: %s", cmd_full)
        return True

    logger.warning("Failed to add iptables block rule using command: %s", cmd_full)

    logger.error(cmd.stdout)
    logger.error(cmd.stderr)

    return False




if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # We catch Keyboard Interrupt exceptions because when
        # the server receives a SIGINT it will spread to the
        # children processes which will then stop the process
        # therefore killing the removal of a firewall rule.
        # This would result in a bad firewall state, therefore
        # a simple semi-solution is to run the main() function
        # again.
        main(ignore_iptables_failed_to_remove=True)
        # We are using the ignore_iptables_failed_to_remove feature
        # to suppress any failed iptable rule removal warnings, since
        # it is highly probable that they we removed in the first
        # running of the command which was prematurely cut off.
