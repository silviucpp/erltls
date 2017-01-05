
PROJECT_NIF_NAME=erltls_nif

include nif.mk

ifeq ($(UNAME_SYS), Darwin)
    CXXFLAGS += -I/usr/local/opt/openssl/include
	LDFLAGS  += -L/usr/local/opt/openssl/lib
endif

CXXFLAGS += -DNDEBUG -g -Wextra -Werror -Wno-missing-field-initializers -fno-exceptions -fno-rtti -std=c++11
LDFLAGS +=  -lssl -lcrypto -lstdc++
