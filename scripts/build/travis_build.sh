#!/bin/sh

set -e
set -x

CC_EXTRA_OPTS=${CC_EXTRA_OPTS:-"-Werror -Idist/libtap"}
LD_EXTRA_OPTS=${LD_EXTRA_OPTS:-"-Ldist/libtap -L/usr/local/lib -lssl -lcrypto"}
MAKE_TGT=${MAKE_TGT:-"all opensips_test"}

make CC_EXTRA_OPTS="${CC_EXTRA_OPTS}" LD_EXTRA_OPTS="${LD_EXTRA_OPTS}" \
 FASTER=1 NICER=0 exclude_modules="db_oracle osp sngtc cachedb_cassandra \
 cachedb_couchbase cachedb_mongodb auth_jwt" ${MAKE_TGT}
