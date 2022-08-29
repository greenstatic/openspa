#!/usr/bin/env bash

if [ "$1" == "" ]; then
    echo "Requires version as the first argument (eg. \"1_0_0\")"
    exit 1
fi

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
    exit 2
fi

if [ "$REVPWD2" != "$REVECHOIP" ]; then
    echo "Not in correct dir, cd into: echo-ip/scripts"
    exit 2
fi


NAME="echo-ip"

cd ../

echo "Creating bin dir (if it does not exist)"
mkdir -p bin

cd cmd/echo-ip

echo "Removing old builds"
rm ../../bin/*

GOOS="linux"
GOARCH="amd64"

echo "Building for: $GOOS/$GOARCH"
#CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -a -installsuffix cgo -o ../../bin/$NAME
GOOS=$GOOS GOARCH=$GOARCH go build -o ../../bin/$NAME

echo "Build successful"

echo "Compressing ..."
COMPRESSEDNAME="$NAME"
COMPRESSEDNAME+="_"
COMPRESSEDNAME+="$GOOS"
COMPRESSEDNAME+="_"
COMPRESSEDNAME+="$GOARCH"
COMPRESSEDNAME+="_v"
COMPRESSEDNAME+="$1"
COMPRESSEDNAME+=".tar.gz"

cd ../../bin

tar -czvf $COMPRESSEDNAME $NAME

echo "Done"