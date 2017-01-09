
PROJECT_NIF_NAME=erltls_nif

include nif.mk

ifeq ($(USE_BORINGSSL), 1)
	CXXFLAGS += -I$(BASEDIR)/deps/boringssl/include
	LDFLAGS  += -L$(BASEDIR)/deps/boringssl/lib
else
	ifeq ($(UNAME_SYS), Darwin)
		CXXFLAGS += -I/usr/local/opt/openssl/include
		LDFLAGS  += -L/usr/local/opt/openssl/lib
	endif
endif

CXXFLAGS += -DNDEBUG -g -Wextra -Werror -Wno-missing-field-initializers -fno-exceptions -fno-rtti -std=c++11
LDFLAGS +=  -lssl -lcrypto -lstdc++
