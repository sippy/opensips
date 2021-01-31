#!/bin/sh

set -e

./opensips_unittests 2>opensips_test.elog
for tcfile in modules/*/test/*.cfg
do
  mod_name=`echo ${tcfile} | awk -F / '{print $2}'`
  ./opensips_deeptests -T ${mod_name} 2>>opensips_test.elog
done
