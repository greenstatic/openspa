# OpenSPA Server and Client Installation with iptables
This tutorial will walk you through the installation and setup of OpenSPA on a Debian system using iptables as the firewall mechanism.

## Requirements
* 1 x Debian/Ubuntu based system to install the OpenSPA Server with a public IP address
* 1 x client (Linux or MacOS) to install the OpenSPA Client
* Root privileges on the server (required to set `iptable` rules)
* Python3 installed on the server

## Tutorial
This tutorial is a bit more involved since currently we do not package binaries.
Once the project will be released officially, we will simply this greatly.
### Part 1: Setting up the server
1. Install Golang - Go tools
    ```bash
    sudo snap install --classic go
    ```
2. Logout and log back in your terminal session (to refresh your PATH ENV variable)

3. Download the OpenSPA source code
    ```bash
    cd ~
    git clone github.com/greenstatic/openspa
    mkdir openspa-server
    ```
    
4. Build OpenSPA client and tools
    ```bash
    cd openspa/openspa/cmd/openspa-server
    go build .
    cp openspa-server ~/openspa-server/
    
    cd ../openspa-tools
    go build .
    cp openspa-tools ~/openspa-server/
    ```

5. Generate the server's private/public keypair
    ```bash
    cd ~/openspa-server
    ./openspa-tools gen-server-key
    mkdir keys
    mv server.key server.pub keys/
    ```

5. Create the server config
    ```bash
    cp ~/openspa/openspa/configs/server_config_example.yaml ~/openspa-server/config.yaml
    nano ~/openspa-server/config.yaml
    ```
    Under the field `serverIP` enter the server's public IP

### Part 2: Setting up the Extension Scripts
Here we will setup some example Extension Scripts (ES) which are meant as a jump off point to get you started.

1. Copy the example extension scripts
    ```bash
    mkdir ~/openspa-server/es
    cp ~/openspa/openspa-extension-scripts/user_directory_service/user_directory_service.py ~/openspa-server/es/
    cp ~/openspa/openspa-extension-scripts/authorization/authorization.py ~/openspa-server/es/
    cp ~/openspa/openspa-extension-scripts/firewalls/iptables/rule_*.py ~/openspa-server/es/
    ```
2. Setup the User Directory Service ES script
    ```bash
    mkdir ~/openspa-server/es/public_keys
    ```
    This will be where all of the client's public keys will be stored.
    
3. Setup iptables. To understand what all of this does, we recommend you checkout the details of the instructions of the [Extension Script's README](../openspa-extension-scripts/firewalls/iptables/README.md).
    ```bash
    sudo iptables -I INPUT 1 -i lo -j ACCEPT
    sudo iptables -A INPUT -p udp --dport 22211 --jump ACCEPT
    sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    sudo iptables --new-chain OPENSPA
    sudo iptables --insert INPUT 3 --jump OPENSPA
    
    sudo iptables --new-chain OPENSPA-BLOCK
    sudo iptables --insert INPUT 4 --jump OPENSPA-BLOCK
    
    # Here add whitelisted IP's that will have full network access to your server (eg. administrator's IP). 
    # Add also (temporarly) the IP you are connecting from, to setup OpenSPA.
    sudo iptables -A INPUT --source <WHITELIST_IP>
    
    # If you did not properly setup the firewall this rule will block you out.
    # Note, the OpenSPA server is not running yet. 
    # If you won't be able to login the machine you won't be able to start the OpenSPA server.
    sudo iptables --policy INPUT DROP
    ```
    
    If you have lost control of the server due to the firewall rule all you need to do is restart the server.
    The rules have not been saved permanently yet.
    
4. If you still have access to the server (try creating another SSH session) then you can save the rules.
    ```bash
    sudo apt-get install iptables-persistent
    ```
    
5. Finally run the server
    ```bash
    # To run in background we recommend screen
    sudo screen -d -m ~/openspa-server/openspa-server start
    # To view the server run: sudo screen -r
    
    # You can of course run the server in the foreground as well
    sudo ~/openspa-server/openspa-server start
    ```
    
    A note on *sudo*. 
    Sudo is needed to launch the *rule_add.py* and *rule_remove.py* script.
    We recommend creating a new account and giving sudo access only to the iptables and ip6tables commands.
    This way the program will not run under root access.

### Part 3: Setting up the client
1. Build the client
    ```bash
    mkdir ~/openspa-client
    cd ~/openspa/openspa/cmd/openspa-client
    go build -o ~/openspa-client/openspa-client # This will build a binary that will only work on operating system and architecture you are building on (eg. on ubuntu it will only work for linux systems)
    
    # To build for Linux (amd64) explicitly 
    GOOS=linux GOARCH=amd64 go build -o ~/openspa-client/openspa-client_linux
    
    # To build for MacOS explicitly 
    GOOS=darwin GOARCH=amd64 go build -o ~/openspa-client/openspa-client_macos
    ```
    
2. Create the client's config file (OSPA file)
    ```bash
    cd ~/openspa-client
    mkdir clients
    ~/openspa-server/openspa-tools gen-client -o ~/openspa-client/clients/ ~/openspa-server/keys/server.pub
    
    # Follow the on-screen intructions and DO NOT forget to fill out the server IP!
    ```
    Inside the *clients* directory there should be a directory with the client's UUID.
    Inside the directory you will find the clients public key with the filename: *<CLIENT_DEVICE_ID>.pub" and a *client.ospa* file.
    
    Give the *client.ospa* file to the client along with the binary of the *openspa-client* for their platform (Linux/MacOS).
    
3. Copy the client's public key into our directory of allowed clients
    ```bash
    cd ~/openspa-server
    cp clients/<CLIENT_UUID>/<CLIENT_UUID>.pub es/public_keys
    ```

### Part 4: Testing it on the Client
The client should have the *openspa-client* binary and the server generated *client.ospa* file.

1. Try to ping the OpenSPA server from the client.
You should not be getting any responses (remember you need to send an OpenSPA request first).

2. Go to the directory where the *openspa-client* and *client.ospa* files are located and create an ICMP protocol request.
    ```bash
    # ICMP does not require any ports, the CLI is just configured to require a port.
    ./openspa-client_linux request client.ospa --protocol icmp -p 1
    ```
    
2. You should be able to ping the server now.
The time allowed to access the system depends on how the server is configured (by default 180 seconds).


### Notes
#### Authorization
Any client that has their public key inside of `~/openspa-server/es/public_keys` is authorized for any kind of request for a hard coded limit of 180 seconds.
Once the duration is up their access will be revoked.
The client can of course request access again (the client even has an automatic request mode that re-requests access when the client reaches the half-point before revocation).

To customize the authorization rules checkout the `~/openspa-server/es/authorization.py` script.

#### IPv6
Although we did not show IPv6 support, the setup for IPv6 (only) is identical only replace IPv4 addresses with the IPv6 counterparts and use *ip6tables* instead of *iptables*.
