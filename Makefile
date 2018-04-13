REBAR=rebar3
USE_BORINGSSL = 1

get_deps: ## Download and build boringssl
	@./build_deps.sh

ifeq ($(USE_BORINGSSL), 1)
compile_nif: get_deps
endif

compile_nif: ## Build nif
	@make V=0 -C c_src -j 8 USE_BORINGSSL=$(USE_BORINGSSL)

clean_nif:
	@make -C c_src clean

compile: ## Compile
	${REBAR} compile

clean: clean-deps clean_nif
	${REBAR} clean

clean-deps:
	rm -rf deps

ct:
	mkdir -p log
	ct_run -suite integrity_test_SUITE -pa ebin -pa deps/*/ebin -include include -logdir log

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
