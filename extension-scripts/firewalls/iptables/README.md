# OpenSPA firewall extension script - iptables
Rule add and rule remove extension scripts that use iptables as a firewall.
Supports both IPv4 and IPv6.

## Script Running Requirements
* iptables, version 1.4.21 or greater
* Python
* root permission to run `iptable` commands

## How it Works
Since iptables will be setup with a default drop policy on the INPUT chain along
with a jump to the custom `OPENSPA` chain, only connections that will be explicitly
whitelisted will be allowed and the rules in the `OPENSPA` chain.
The rule add script will add to the `OPENSPA` chain only the requested host connections 
which should be triggered by the OpenSPA server. Once the OpenSPA servers built-in
firewall duration tracking mechanism triggers the revocation of the rule it will trigger
the rule remove script which will remove the connection from the `OPENSPA` iptables 
chain and deny network access to the host.

## Features
### Strict Stateless Block
The strict stateless block feature enables you to block the OpenSPA client
after the expiration immediately even in the event of an established connection -
in cases where the server has the rule to allow established connections on the
INPUT chain, like this one:
`iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`.

What this means is that if this feature is disabled and the server has the
rule above, a client who still has an established connection with the server
**will not be blocked** immediately by iptables. However once the connection
is closed or a timeout occurs the client will be fully disconnected from the
server. Note that if a client has an established connection with the server
(with strict stateless block disabled) and tries to start a new connection,
that connection will be dropped - it only preserves existing connections that
were created during the clients authorization period, for the duration of the
connection.

#### How It Works
This feature works by having another iptables chain, `OPENSPA-BLOCK`. This chain
should be placed directly **after** the `OPENSPA` chain and **before** the
aforementioned *ESTABLISHED,RELATED* rule. The `rule_remove.py` script will
after deleting a rule add the same rule (but with a DROP action) inside the
`OPENSPA-BLOCK` chain. This causes iptables to immedietly block the client's
already established connection (this is why the chain should be before the
*ESTABLISHED,RELATED* rule). The `rule_add.py` script will after adding a
rule try to delete the same rule (except with a DROP action) inside the
`OPENSPA-BLOCK` chain. This prevents the `rule_remove.py` script from polluting
the `OPENSPA-BLOCK` chain with duplicate rules.

#### Maintenance
As you might have though, we primary write to the `OPENSPA-BLOCK` chain, with
the occasional removal of an exact match of a request. This however means that
the chain will though time get larger and larger without providing any real value
besides the first couple of minutes when the rule is created to prevent the
client from abusing an established connection. For this reason we recommend
a daily cron job that cleans the `OPENSPA-BLOCK` chain. Or some other mechanism
to clean periodically the chain. Contributions are welcomed.

#### How To Disable
If you wish to disable this feature all you have to do is set the variable:
`STATELESS_BLOCK_ENABLE` to `False` in **BOTH** `rule_add.py` and `rule_remove.py`
scripts.

## Setup
Before adding the default drop policy on the input chain, it is recommended to add one 
or more hosts that have a whitelist rule to allow to connect without OpenSPA
(eg. administrators computer). Attach these rules directly to the INPUT 
chain before any other chains that will be created for OpenSPA. These IPs will
not be under OpenSPA control and will permanently have  network access on
all protocols/ports (unless of course you modify the recommended
rule bellow): \
`iptables --insert INPUT --source <SOURCE_IP> --jump ACCEPT`

Since we will be setting the default policy on the INPUT chain to drop, it
is recommended to add the following rules to your INPUT chain:
* `iptables -I INPUT 1 -i lo -j ACCEPT` - enables loopback interface (as the first rule
to improve performance)
* `iptables -A INPUT -p udp --dport 22211 --jump ACCEPT` - Allow UDP connections
to port 22211 or whichever port you will use for the OpenSPA server.
* `iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT` - allows
established sessions (from the server) to receive traffic (eg. ping started from server)

Once you are confident you will not lose network access during the installation, follow
these steps:
1. Create a new chain: `iptables --new-chain OPENSPA`
2. Add the *OPENSPA* chain to the INPUT chain: `iptables --insert INPUT 3 --jump OPENSPA`
(note: here we insert the rule as rule number 3, this will most definitely depend
on your setup. What is important is that this rule is BEFORE the *ESTABLISHED,RELATED*
rule).
3. Set the default drop policy on the INPUT chain: `iptables --policy INPUT DROP`. If you
haven't properly setup a whitelist rule for your connection, you will be cutoff here.

If you do not wish to enable the [strict stateless block](#strict-stateless-block)
feature you are finished. Just be sure to **disable the feature** in **BOTH** `rule_add.py`
and `rule_remove.py` scripts. Check the [strict stateless block](#strict-stateless-block)
section to see how to disable properly.

4. Create a new chain: `iptables --new-chain OPENSPA-BLOCK`
5. Add the *OPENSPA-BLOCK* chain **AFTER** the **OPENSPA** chain but **BEFORE**
the *ESTABLISHED,RELATED* rule to the INPUT chain:
`iptables --insert INPUT 4 --jump OPENSPA-BLOCK` - again the rule number depends
on your setup, use: `iptables -vnL --line-numbers` to place the rule before
the *ESTABLISHED,RELATED* rule.

### Note
iptables is not persistent between reboots.
To save your rules between reboots we recommend *iptables-persistent*:

 ```bash
sudo apt-get install iptables-persistent
```

### IPv6 Setup
If you wish to enable IPv6 support simply run the above mentioned commands, 
but replace *iptables* with *ip6tables*.

It must be noted that IPv6 relies on ICMPv6 to work properly. Therefore blocking 
all ICMPv6 traffic is not a best practise.
Rule to allow all ICMPv6 traffic: `ip6tables -I INPUT -icmpv6 --jump ACCEPT`. 
A better approach would be to allow ICMPv6 traffic but deny the echo request/reply
type and/or time exceeded used respectively by ping and traceroute.

However if you still wish to block all ICMPv6 traffic, you must at least allow 
the following rules. Which will enable the minimum your server needs to 
communicate over IPv6:
* `ip6tables -I INPUT -p icmpv6 --icmpv6-type router-solicitation --jump ACCEPT`
* `ip6tables -I INPUT -p icmpv6 --icmpv6-type router-advertisement --jump ACCEPT`
* `ip6tables -I INPUT -p icmpv6 --icmpv6-type neighbour-solicitation --jump ACCEPT`
* `ip6tables -I INPUT -p icmpv6 --icmpv6-type neighbour-advertisement --jump ACCEPT`
