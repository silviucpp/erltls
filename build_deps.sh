#!/usr/bin/env bash

DEPS_LOCATION=deps
DESTINATION=boringssl

if [ -d "$DEPS_LOCATION/$DESTINATION" ]; then
    echo "BoringSSL fork already exist. delete $DEPS_LOCATION/$DESTINATION for a fresh checkout."
    exit 0
fi

REPO=https://boringssl.googlesource.com/boringssl
BRANCH=chromium-stable
REV=78684e5b222645828ca302e56b40b9daff2b2d27

function DownloadBoringSsl()
{
	echo "repo=$REPO rev=$REV branch=$BRANCH"

	mkdir -p $DEPS_LOCATION
	pushd $DEPS_LOCATION
	git clone -b $BRANCH $REPO $DESTINATION
	pushd $DESTINATION
	git checkout $REV
	popd
	popd
}

function BuildBoringSsl()
{
	pushd $DEPS_LOCATION
	pushd $DESTINATION

	mkdir build
	pushd build

	cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-fPIC"
	make
	mkdir ../lib
	cp crypto/libcrypto.a ../lib/libcrypto.a
	cp ssl/libssl.a ../lib/libssl.a

    popd
	popd
	popd
}

DownloadBoringSsl
BuildBoringSsl
