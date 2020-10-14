LIBNAME=	digest_auth

include ../../Makefile.openssl

LIBS=

SHA_512_256_SUPPORT:= $(shell printf '\#define EVP_sha512_256(x) \
	_TEST_P_A_S_S_E_D_()\n\#include "openssl/evp.h"\n' \
	| cpp $(DEFS) | grep -q _TEST_P_A_S_S_E_D_ && echo yes)

ifeq ($(SHA_512_256_SUPPORT),yes)
	DEFS+=-DSHA_512_256_ENABLE
else
	exclude_files=$(wildcard *sha512t256.c)
endif

include ../../Makefile.misclibs
