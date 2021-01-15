#!/bin/sh

set -e

if [ -e opensips_test ]
then
  ./opensips_test 2>opensips_test.elog
fi
