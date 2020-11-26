#!/bin/sh

set -e

PKGS=`grep -A 35 packages: .travis.yml  | grep -e '^ *[-]' | awk '{print $2}'`

case "${COMPILER}" in
gcc)
	export CC="${COMPILER}"
	PKGS="${PKGS} gcc g++"
	;;
gcc-i386-cross)
	export CC="gcc"
	export CC_EXTRA_OPTS="-Werror -m32"
	sudo dpkg --add-architecture i386
	PKGS="${PKGS} gcc g++ libc6-dev:i386 libstdc++6:i386 lib32gcc-7-dev"
	;;
gcc-mips64-cross)
	export CC="mips64-linux-gnuabi64-gcc"
	export AR="mips64-linux-gnuabi64-ar"
	export RANLIB="mips64-linux-gnuabi64-ranlib"
	PKGS="${PKGS} gcc-mips64-linux-gnuabi64 libc-dev-mips64-cross qemu-user-static"
	;;
clang)
	export CC="${COMPILER}"
	export AR="llvm-ar"
	export RANLIB="llvm-ranlib"
	export GCOV_CMD="llvm-cov gcov"
	PKGS="${PKGS} clang llvm-dev"
	;;
clang-i386-cross)
	export CC="clang"
	export CC_EXTRA_OPTS="-Werror -m32"
	sudo dpkg --add-architecture i386
	PKGS="${PKGS} clang llvm-dev libc6-dev:i386 libstdc++6:i386 lib32gcc-7-dev"
	;;
gcc-9)
	export CC="${COMPILER}"
	export AR="gcc-ar-9"
	export RANLIB="gcc-ranlib-9"
	export GCOV_CMD="gcov-9"
	sudo apt install software-properties-common
	sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
	PKGS="${PKGS} gcc-9 g++-9"
	;;
gcc-10)
	export CC="${COMPILER}"
	export AR="gcc-ar-10"
	export RANLIB="gcc-ranlib-10"
	export GCOV_CMD="gcov-10"
	sudo apt install software-properties-common
	sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
	PKGS="${PKGS} gcc-9 g++-9"
	;;
clang-9)
	export CC="${COMPILER}"
	export AR="llvm-ar-9"
	export RANLIB="llvm-ranlib-9"
	export GCOV_CMD="llvm-cov-9 gcov"
	PKGS="${PKGS} clang-9 llvm-9-dev libc++-9-dev libc++abi-9-dev"
	;;
clang-10)
	export CC="${COMPILER}"
	export AR="llvm-ar-10"
	export RANLIB="llvm-ranlib-10"
	export GCOV_CMD="llvm-cov-10 gcov"
	PKGS="${PKGS} clang-10 llvm-10-dev libc++-10-dev libc++abi-10-dev"
	;;
*)
	printf 'COMPILER="%s" is unknown / unsupported\n' "${COMPILER}" 1>&2
	exit 1
        ;;
esac

sudo apt-get update -y
sudo apt-get -y install ${PKGS}

case "${COMPILER}" in
gcc-mips64-cross)
        sudo mkdir "/usr/mips64-linux-gnuabi64/etc"
        sudo touch "/usr/mips64-linux-gnuabi64/etc/ld.so.cache"
        sudo mkdir "/etc/qemu-binfmt"
        sudo ln -sf "/usr/mips64-linux-gnuabi64" "/etc/qemu-binfmt/mips64"
        ;;
esac
