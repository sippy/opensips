#!/bin/sh

set -e
set -x

git clone https://github.com/zorgnax/libtap.git dist/libtap
make -C dist/libtap CPPFLAGS="${CC_EXTRA_OPTS}" LDFLAGS="${CC_EXTRA_OPTS}" clean all
sudo make -C dist/libtap install
sudo rm /usr/local/lib/libtap.so
