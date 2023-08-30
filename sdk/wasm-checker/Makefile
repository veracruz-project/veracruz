# Makefile for the WASM Checker binary ABI validator.
#
# Authors
#
# The Veracruz Development Team.
#
# Copyright and Licensing
#
# See the `LICENSE.md` file in the Veracruz root directory for
# copyright and licensing information.

bin/wasm-checker: src/main.cc wabt json
	mkdir -p bin/
	g++ src/main.cc -o bin/wasm-checker -I./wabt/ -I./wabt/build -L ./wabt/build -I./json/include -lwabt

wabt:
	git clone --recursive --depth 1 --branch 1.0.19 https://github.com/WebAssembly/wabt.git; \
	mkdir -p wabt/build/ && cd wabt/build && cmake .. && cmake --build .

json:
	git clone --depth 1  --branch v3.9.1 https://github.com/nlohmann/json.git; \

.PHONY: clean
clean:
	rm -f bin/wasm-checker
	rm -rf wabt/
	rm -rf json/
