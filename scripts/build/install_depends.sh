#!/bin/sh

set -e

PKGS=`grep -A 35 packages: .travis.yml  | grep -e '^ *[-]' | awk '{print $2}'`

. $(dirname $0)/build.conf.sub

if [ ! -z "${PRE_INSTALL_CMD}" ]
then
  ${PRE_INSTALL_CMD}
fi

sudo apt-get update -y
sudo apt-get -y install ${PKGS}

case "${COMPILER}" in
gcc-mips64-cross)
        sudo mkdir "/usr/mips64-linux-gnuabi64/etc"
        sudo touch "/usr/mips64-linux-gnuabi64/etc/ld.so.cache"
        sudo mkdir "/etc/qemu-binfmt"
        sudo ln -sf "/usr/mips64-linux-gnuabi64" "/etc/qemu-binfmt/mips64"
        ;;
gcc-arm32-cross)
        sudo mkdir "/usr/arm-linux-gnueabihf/etc"
        sudo touch "/usr/arm-linux-gnueabihf/etc/ld.so.cache"
        sudo mkdir "/etc/qemu-binfmt"
        sudo ln -sf "/usr/arm-linux-gnueabihf" "/etc/qemu-binfmt/arm"
	;;
gcc-arm64-cross)
        sudo mkdir "/usr/aarch64-linux-gnu/etc"
        sudo touch "/usr/aarch64-linux-gnu/etc/ld.so.cache"
        sudo mkdir "/etc/qemu-binfmt"
        sudo ln -sf "/usr/aarch64-linux-gnu" "/etc/qemu-binfmt/aarch64"
        ;;
esac
