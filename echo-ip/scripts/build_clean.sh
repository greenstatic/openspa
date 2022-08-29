#!/usr/bin/env bash

# Verify that we are inside echo-ip/scripts dir.
# This is because we use relative paths, and we
# assume we are in the echo-ip/scripts directory.
REVPWD=$(echo "$PWD" | rev)

REVPWD1=$(echo "$REVPWD" | cut -d/ -f1)
REVPWD2=$(echo "$REVPWD" | cut -d/ -f2)

REVSCRIPTS=$(echo "scripts" | rev)
REVECHOIP=$(echo "echo-ip" | rev)

echo "Verifying we are in the correct directory ..."

if [ "$REVPWD1" != "$REVSCRIPTS" ]; then
    echo "Not in correct dir, cd into: echo-ip/scripts"
    exit 1
fi

if [ "$REVPWD2" != "$REVECHOIP" ]; then
    echo "Not in correct dir, cd into: echo-ip/scripts"
    exit 1
fi

cd ../

echo "Clearing the bin directory"
rm ./bin/*

echo "Removing the bin directory"
rm -d ./bin

echo "Done"