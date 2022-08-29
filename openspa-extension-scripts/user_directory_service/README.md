# User Directory Service
The OpenSPA server currently only supports a single mode of encryption and signature.
Both of which require the requesting client's device public key. The user directory
service provides a simple mechanism to return to the OpenSPA server the client's
device public key using their client device ID as a lookup key.

The user directory service extension script is however planned to support also
other user specific lookup functions. For this reason there are various "commands".

The only one supported now is `GET_USER_PUBLIC_KEY` command which will simply return 
the client's public key found in a directory where the client's public key is located 
inside a file in the format of: *<client_device_id>.pub*.

To change the directory where the public keys are stored, change the variable 
`PUBLIC_KEY_DIR` inside the script.

## Requirements:
* Python3
* Directory with the client's public keys stored in the format *<client_device_id>.pub* - 
this directory should be specified in the `GET_USER_PUBLIC_KEY` variable inside the script.