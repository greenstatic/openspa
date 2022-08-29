# OpenSPA Extension Scripts
This repository contains various extension scripts (ES) to use with the OpenSPA server
to extend the functionality of the server.

## Type of Scripts
As of version 0.1.0 of the OpenSPA server the following scripts are supported:
* User Directory Service - script to return various user information, used in the authentication step.
* Authorization - script to authorize a particular user's OpenSPA request
* Rule add - script to add a firewall accept rule to allow the host to connect
* Rule remove - script to remove rules accepted by the rule add extension script.

## Available Scripts
### Firewalls
Here are various scripts that implement the rule add and rule remove ES.
* iptables

### User Directory Service
The user directory service in this repository implements a single command 
`GET_USER_PUBLIC_KEY`which will get the requested users public key using 
the provided client device ID. The script gets the user's public key by
simply checking a directory for the users public key.

### Authorization
The authorization script in this repository simply allows all verified
connections for a hardcoded limit of 3 minutes.

## Note
These scripts are meant to be a jump-off point to allow you to simply modify
them to match your required needs. Apart from the firewall scripts, they are
often not suited to be used out of the box and require modification to match
your required goal.

## License
All scripts are released under the Apache License 2.0.