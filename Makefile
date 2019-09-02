REBAR=rebar3
ROOT_TEST=_build/test/lib

C_SRC_DIR = $(shell pwd)/c_src
C_SRC_ENV ?= $(C_SRC_DIR)/env.mk

#regenerate all the time the env.mk
ifneq ($(wildcard $(C_SRC_DIR)),)
	GEN_ENV ?= $(shell erl -noshell -s init stop -eval "file:write_file(\"$(C_SRC_ENV)\", \
		io_lib:format( \
			\"ERTS_INCLUDE_DIR ?= ~s/erts-~s/include/~n\" \
			\"ERL_INTERFACE_INCLUDE_DIR ?= ~s~n\" \
			\"ERL_INTERFACE_LIB_DIR ?= ~s~n\", \
			[code:root_dir(), erlang:system_info(version), \
			code:lib_dir(erl_interface, include), \
			code:lib_dir(erl_interface, lib)])), \
		halt().")
    $(GEN_ENV)
endif

include $(C_SRC_ENV)

ifndef USE_BORINGSSL
    USE_BORINGSSL = 1
endif

get_deps:
	@./build_deps.sh

ifeq ($(USE_BORINGSSL), 1)
compile_nif: get_deps
endif

compile_nif:
	@make V=0 -C c_src -j 8 USE_BORINGSSL=$(USE_BORINGSSL)

clean_nif:
	@make -C c_src clean

compile:
	${REBAR} compile

clean:
	${REBAR} clean

ct:
	mkdir -p log
	${REBAR} ct --compile_only
	ct_run  -no_auto_compile \
			-cover test/cover.spec \
			-dir $(ROOT_TEST)/erltls/test \
			-pa $(ROOT_TEST)/*/ebin \
			-logdir log

cpplint:
	cpplint --counting=detailed --filter=-legal/copyright,-build/include_subdir,-build/include_order,-whitespace/braces,-whitespace/parens,-whitespace/newline,-whitespace/indent,-whitespace/blank_line \
			--linelength=300 \
			--exclude=c_src/*.o --exclude=c_src/*.mk  \
			c_src/*.*

cppcheck:
	cppcheck -j 8 --enable=all \
	 		 -I /usr/local/include \
	 		 -I deps/boringssl/include \
	 		 -I $(ERTS_INCLUDE_DIR) \
	 		 -I $(ERL_INTERFACE_INCLUDE_DIR) \
	 		 --suppress=*:*deps/boringssl* \
	 		 --xml-version=2 \
	 		 --output-file=cppcheck_results.xml \
	 		 c_src/
