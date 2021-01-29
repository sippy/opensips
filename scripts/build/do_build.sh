#!/bin/sh

set -e

PKGS=`grep -A 35 packages: .travis.yml  | grep -e '^ *[-]' | awk '{print $2}'`

. $(dirname $0)/build.conf.sub

MAKE_TGT="${MAKE_TGT:-"all"} opensips_unittests"
CC_EXTRA_OPTS="${CC_EXTRA_OPTS:-"-Werror"} -Idist/libtap"

CC_EXTRA_OPTS="${CC_EXTRA_OPTS}" FASTER=1 NICER=0 make \
  LD_EXTRA_OPTS=-Ldist/libtap exclude_modules="db_oracle osp sngtc cachedb_cassandra cachedb_couchbase \
  cachedb_mongodb auth_jwt" ${MAKE_TGT}
