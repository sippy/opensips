#!/bin/sh

set -e

./opensips_unittests 2>opensips_test.elog
for tcfile in modules/*/test/*.cfg
do
  mod_name=`echo ${tcfile} | awk -F / '{print $2}'`
  if [ ! -e modules/${mod_name}/${mod_name}_unittests.so ]
  then
    continue
  fi
  ./opensips_deeptests -T ${mod_name} 2>>opensips_test.elog
done
