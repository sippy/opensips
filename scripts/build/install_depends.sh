#!/bin/sh

set -e

PKGS=`grep -A 35 packages: .travis.yml  | grep -e '^ *[-]' | awk '{print $2}'`

case ${CC} in
gcc)
	PKGS="${PKGS} gcc g++"
	;;
clang)
	export AR="llvm-ar"
	export RANLIB="llvm-ranlib"
	export GCOV_CMD="llvm-cov gcov"
	PKGS="${PKGS} clang llvm-dev"
	;;
gcc-9)
	export AR="gcc-ar-9"
	export RANLIB="gcc-ranlib-9"
	export GCOV_CMD="gcov-9"
	sudo apt install software-properties-common
	sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
	PKGS="${PKGS} gcc-9 g++-9"
	;;
gcc-10)
	export AR="gcc-ar-10"
	export RANLIB="gcc-ranlib-10"
	export GCOV_CMD="gcov-10"
	sudo apt install software-properties-common
	sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
	PKGS="${PKGS} gcc-9 g++-9"
	;;
clang-9)
	export AR="llvm-ar-9"
	export RANLIB="llvm-ranlib-9"
	export GCOV_CMD="llvm-cov-9 gcov"
	PKGS="${PKGS} clang-9 llvm-9-dev libc++-9-dev libc++abi-9-dev"
	;;
clang-10)
	export AR="llvm-ar-10"
	export RANLIB="llvm-ranlib-10"
	export GCOV_CMD="llvm-cov-10 gcov"
	PKGS="${PKGS} clang-10 llvm-10-dev libc++-10-dev libc++abi-10-dev"
	;;
*)
	printf 'CC="%s" is unknown / unsupported\n' "${CC}" 1>&2
	exit 1
        ;;
esac

for pkg in ${PKGS}
do
  sudo apt-get -y install ${pkg}
done
