#!/bin/sh

set -e

. $(dirname $0)/dockerize.sub

PKGS=$(cat "$(dirname $0)/apt_requirements.txt")

. $(dirname $0)/build.conf.sub

_PKGS=""
for pkg in ${PKGS}
do
  if [ "${BUILD_OS}" != ubuntu-20.04 -a "${BUILD_OS}" != ubuntu-18.04 -a "${pkg}" = python-dev ]
  then
    pkg="python-dev-is-python3"
  fi
  if [ "${BUILD_OS%-*}" = "debian" -a "${pkg}" = libmysqlclient-dev ]
  then
    pkg="libmariadb-dev"
  fi
  _PKGS="${_PKGS} ${pkg}"
done
PKGS="${_PKGS}"

if [ ! -z "${PRE_INSTALL_CMD}" ]
then
	${PRE_INSTALL_CMD}
fi

${SUDO} apt-get update -y
${SUDO} apt-get -y remove libmemcached11 libpq5
${SUDO} apt-get -y autoremove

PKGS="$PKGS $(. "$(dirname $0)/apt_requirements_postupdate.sh")"
${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get -y --allow-downgrades install ${PKGS}

if [ ! -z "${POST_INSTALL_CMD}" ]
then
	${POST_INSTALL_CMD}
fi
