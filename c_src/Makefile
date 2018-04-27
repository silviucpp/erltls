
PROJECT_NIF_NAME=erltls_nif

include nif.mk

ifeq ($(USE_BORINGSSL), 1)
	CXXFLAGS += -I$(BASEDIR)/deps/boringssl/include
	LDFLAGS  += -L$(BASEDIR)/deps/boringssl/lib
else
	ifeq ($(UNAME_SYS), darwin)
		CXXFLAGS += -I/usr/local/opt/openssl/include
		LDFLAGS  += -L/usr/local/opt/openssl/lib
	endif
endif

CXXFLAGS += -DNDEBUG \
			-g -Wextra -Werror -Wno-missing-field-initializers -fno-exceptions -fno-rtti -std=c++11

ifeq ($(UNAME_SYS), darwin)
	LDFLAGS +=  -Wl,-U,_enif_alloc \
				-Wl,-U,_enif_free \
				-Wl,-U,_enif_realloc \
				-Wl,-U,_enif_alloc_resource \
				-Wl,-U,_enif_open_resource_type \
				-Wl,-U,_enif_release_resource \
				-Wl,-U,_enif_priv_data \
				-Wl,-U,_enif_consume_timeslice \
				-Wl,-U,_enif_inspect_binary \
				-Wl,-U,_enif_inspect_iolist_as_binary \
				-Wl,-U,_enif_is_binary \
				-Wl,-U,_enif_is_identical \
				-Wl,-U,_enif_is_tuple \
				-Wl,-U,_enif_get_int \
				-Wl,-U,_enif_get_list_cell \
				-Wl,-U,_enif_get_resource \
				-Wl,-U,_enif_get_tuple \
				-Wl,-U,_enif_get_long \
				-Wl,-U,_enif_get_uint \
				-Wl,-U,_enif_get_local_pid \
				-Wl,-U,_enif_make_atom \
				-Wl,-U,_enif_make_existing_atom \
				-Wl,-U,_enif_make_new_binary \
				-Wl,-U,_enif_make_resource \
				-Wl,-U,_enif_make_tuple \
				-Wl,-U,_enif_make_list \
				-Wl,-U,_enif_make_int \
				-Wl,-U,_enif_make_list_from_array
endif

LDFLAGS += -lssl -lcrypto -lstdc++
