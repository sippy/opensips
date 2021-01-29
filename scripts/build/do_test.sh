#!/bin/sh

set -e

exec ./opensips_unittests 2>opensips_test.elog
