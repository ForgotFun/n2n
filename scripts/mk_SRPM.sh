#!/bin/sh

# This script makes a SRPM - a source RPM file which can be built into the
# appropriate distro specific RPM for any platform.
#
# To build the binary package:
# rpm -i n2n-<ver>.src.rpm
# rpmbuild -bb n2n.spec
#
# Look for the "Wrote:" line to see where the final RPM is.
#
# To run this script cd to the n2n directory and run it as follows
# scripts/mk_SRPMS.sh
#

function exit_fail()
{
    echo "$1"
    exit 1
}

PACKAGE="n2n"
PKG_VERSION="1.2"
PKG_AND_VERSION="${PACKAGE}-${PKG_VERSION}"

BUILD_MANIFEST="
edge.c
lzoconf.h
lzodefs.h
Makefile
minilzo.c
minilzo.h
n2n.c
n2n.h
n2n.spec
supernode.c
tuntap_linux.c
tuntap_osx.c
twofish.c
twofish.h
edge.8
supernode.1
"

BASE=`pwd`

for F in ${BUILD_MANIFEST}; do
    test -f $F || exit_fail "Wrong directory. Please execute from n2n directory.";
done

echo "Found critical files. Proceeding."

pushd ..

test -d ${PKG_AND_VERSION} && exit_fail "Directory ${PKG_AND_VERSION} already exists above. I need to create this, but I won't remove it in case it has data."

echo "Creating staging directory at ${PWD}/${PKG_AND_VERSION}"
mkdir ${PKG_AND_VERSION} || exit_fail "failed to mkdir ${PKG_AND_VERSION}"

echo "Copying in files"
for F in ${BUILD_MANIFEST}; do
    cp ${BASE}/$F ${PKG_AND_VERSION}/ || exit_fail "copy failed"
done



echo "Creating tarfile"
tar czf ${PKG_AND_VERSION}.tar.gz ${PKG_AND_VERSION}

echo "Building SRPM"
# -ts means build source RPM from tarfile
rpmbuild -ts ${PKG_AND_VERSION}.tar.gz

echo "Removing staging directory"
rm -rf ${PKG_AND_VERSION}

popd

echo "Done"
