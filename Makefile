REBAR=rebar

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
	ct_run -suite integrity_test_SUITE -pa ebin -pa deps/*/ebin -include include -logdir log


