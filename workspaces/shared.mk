# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root director for licensing
# and copyright information.

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"
PLATFORM := $(shell uname)

###################################################
# Wasm programs

WASM_PROG_LIST = random-source.wasm \
				linear-regression.wasm \
				string-edit-distance.wasm \
				intersection-set-sum.wasm \
				private-set-intersection.wasm \
				idash2017-logistic-regression.wasm \
				moving-average-convergence-divergence.wasm \
				private-set-intersection-sum.wasm \
				number-stream-accumulation.wasm \
				read-file.wasm

WASM_PROG_FILES = $(patsubst %.wasm, $(OUT_DIR)/%.wasm, $(WASM_PROG_LIST))

wasm-files: $(WASM_PROG_FILES)

$(OUT_DIR)/%.wasm: $(WORKSPACE_DIR)/applications/target/wasm32-wasi/release/%.wasm
	cp $< $@

$(WORKSPACE_DIR)/applications/target/wasm32-wasi/release/%.wasm:
	$(MAKE) -C $(WORKSPACE_DIR)/applications

###################################################
# Generate Policy Files

# Numbers for wasi rights
FD_DATASYNC             := $(shell echo "2^0"  | bc)
FD_READ                 := $(shell echo "2^1"  | bc)
FD_SEEK                 := $(shell echo "2^2"  | bc)
FD_FDSTAT_SET_FLAGS     := $(shell echo "2^3"  | bc)
FD_SYNC                 := $(shell echo "2^4"  | bc)
FD_TELL                 := $(shell echo "2^5"  | bc)
FD_WRITE                := $(shell echo "2^6"  | bc)
FD_ADVISE               := $(shell echo "2^7"  | bc)
FD_ALLOCATE             := $(shell echo "2^8"  | bc)
PATH_CREATE_DIRECTORY   := $(shell echo "2^9"  | bc)
PATH_CREATE_FILE        := $(shell echo "2^10" | bc)
PATH_LINK_SOURCE        := $(shell echo "2^11" | bc)
PATH_LINK_TARGET        := $(shell echo "2^12" | bc)
PATH_OPEN               := $(shell echo "2^13" | bc)
FD_READDIR              := $(shell echo "2^14" | bc)
PATH_READLINK           := $(shell echo "2^15" | bc)
PATH_RENAME_SOURCE      := $(shell echo "2^16" | bc)
PATH_RENAME_TARGET      := $(shell echo "2^17" | bc)
PATH_FILESTAT_GET       := $(shell echo "2^18" | bc)
PATH_FILESTAT_SET_SIZE  := $(shell echo "2^19" | bc)
PATH_FILESTAT_SET_TIMES := $(shell echo "2^20" | bc)
FD_FILESTAT_GET         := $(shell echo "2^21" | bc)
FD_FILESTAT_SET_SIZE    := $(shell echo "2^22" | bc)
FD_FILESTAT_SET_TIMES   := $(shell echo "2^23" | bc)
PATH_SYMLINK            := $(shell echo "2^24" | bc)
PATH_REMOVE_DIRECTORY   := $(shell echo "2^25" | bc)
PATH_UNLINK_FILE        := $(shell echo "2^26" | bc)
POLL_FD_READWRITE       := $(shell echo "2^27" | bc)
SOCK_SHUTDOWN           := $(shell echo "2^28" | bc)
# Common rights
READ_RIGHT       := $(shell echo $(FD_READ) + $(FD_SEEK) + $(PATH_OPEN) | bc)
WRITE_RIGHT      := $(shell echo $(FD_WRITE) + $(PATH_CREATE_FILE) + $(PATH_FILESTAT_SET_SIZE) + $(FD_SEEK) + $(PATH_OPEN) | bc)
READ_WRITE_RIGHT := $(shell echo $(FD_READ) + $(FD_WRITE) + $(PATH_CREATE_FILE) + $(PATH_FILESTAT_SET_SIZE) + $(FD_SEEK) + $(PATH_OPEN) | bc)

ifeq ($(PLATFORM), Darwin)
	CERTIFICATE_EXPIRY := "$(shell date -Rf +100d)"
endif

ifeq ($(PLATFORM), Linux)
	CERTIFICATE_EXPIRY := "$(shell date --rfc-2822 -d 'now + 100 days')"
endif

POLICY_FILES ?= get_random_policy.json \
				one_data_source_policy.json \
				two_data_source_string_edit_distance_policy.json \
				two_data_source_intersection_set_policy.json \
				two_data_source_private_set_intersection_policy.json \
				dual_policy.json \
				triple_policy.json \
				triple_parties_two_data_sources_sum_policy.json \
				permuted_triple_parties_two_data_sources_sum_policy.json \
				triple_parties_two_data_sources_string_edit_distance_policy.json \
				dual_parallel_policy.json \
				quadruple_policy.json \
				test_multiple_key_policy.json \
				idash2017_logistic_regression_policy.json \
				moving_average_convergence_divergence.json \
				private_set_intersection_sum.json \
				number-stream-accumulation.json \
				basic_file_read_write.json


PGEN = $(WORKSPACE_DIR)/host/target/release/generate-policy

$(PGEN): $(WORKSPACE_DIR)/host/crates/test-collateral/generate-policy/src/main.rs $(WORKSPACE_DIR)/host/crates/test-collateral/generate-policy/Cargo.toml
	$(MAKE) -C $(WORKSPACE_DIR)/host

policy-files: $(patsubst %.json, $(OUT_DIR)/%.json, $(POLICY_FILES))
	@echo $(INFO_COLOR)"GEN   =>  $(POLICY_FILES)"$(RESET_COLOR)

CA_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/CACert.pem
CLIENT_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/client_rsa_cert.pem
PROGRAM_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/program_client_cert.pem
DATA_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/data_client_cert.pem
RESULT_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/result_client_cert.pem
EXPIRED_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/expired_cert.pem

CREDENTIALS = $(CA_CRT) $(CLIENT_CRT) $(PROGRAM_CRT) $(DATA_CRT) $(RESULT_CRT) $(EXPIRED_CRT) \
	$(MEASUREMENT_FILE)

PGEN_COMMON_PARAMS = --proxy-attestation-server-cert $(CA_CRT) $(MEASUREMENT_PARAMETER) \
	--certificate-expiry $(CERTIFICATE_EXPIRY) --execution-strategy Interpretation

$(OUT_DIR)/get_random_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/random-source.wasm
	cd $(OUT_DIR) ; $(PGEN) --enclave-debug-mode true \
		--certificate $(CLIENT_CRT) --capability "output : $(READ_RIGHT), random-source.wasm : $(WRITE_RIGHT)" \
		--binary random-source.wasm --capability "output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3011 --proxy-attestation-server-ip 127.0.0.1:3010  \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/one_data_source_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/linear-regression.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(CLIENT_CRT) --capability "input-0 : $(WRITE_RIGHT), output : $(READ_RIGHT), linear-regression.wasm : $(WRITE_RIGHT)" \
		--binary linear-regression.wasm --capability "input-0 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3012 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/test_multiple_key_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/moving-average-convergence-divergence.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(CLIENT_CRT) --capability "input-0 : $(WRITE_RIGHT), output : $(READ_RIGHT), moving-average-convergence-divergence.wasm : $(WRITE_RIGHT)" \
		--binary moving-average-convergence-divergence.wasm --capability "input-0 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3012 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/two_data_source_string_edit_distance_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/string-edit-distance.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(CLIENT_CRT) --capability "input-0 : $(WRITE_RIGHT), input-1 : $(WRITE_RIGHT), output : $(READ_RIGHT), string-edit-distance.wasm : $(WRITE_RIGHT)" \
		--binary string-edit-distance.wasm --capability "input-0 : $(READ_RIGHT), input-1 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3013 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/two_data_source_intersection_set_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/intersection-set-sum.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(CLIENT_CRT) --capability "input-0 : $(WRITE_RIGHT), input-1 : $(WRITE_RIGHT), output : $(READ_RIGHT), intersection-set-sum.wasm : $(WRITE_RIGHT)" \
		--binary intersection-set-sum.wasm --capability "input-0 : $(READ_RIGHT), input-1 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3022 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/two_data_source_private_set_intersection_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/private-set-intersection.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(CLIENT_CRT) --capability "input-0 : $(WRITE_RIGHT), input-1 : $(WRITE_RIGHT), output : $(READ_RIGHT), private-set-intersection.wasm : $(WRITE_RIGHT)" \
		--binary private-set-intersection.wasm --capability "input-0 : $(READ_RIGHT), input-1 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3026 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/dual_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/linear-regression.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(PROGRAM_CRT) --capability "linear-regression.wasm : $(WRITE_RIGHT)" \
		--certificate $(DATA_CRT) --capability "input-0 : $(WRITE_RIGHT), output : $(READ_RIGHT)" \
		--binary linear-regression.wasm --capability "input-0 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3014 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/dual_parallel_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/linear-regression.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(PROGRAM_CRT) --capability "linear-regression.wasm : $(WRITE_RIGHT)" \
		--certificate $(DATA_CRT) --capability "input-0 : $(WRITE_RIGHT), output : $(READ_RIGHT), linear-regression.wasm : $(WRITE_RIGHT)" \
		--binary linear-regression.wasm --capability "input-0 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3015 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/triple_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/linear-regression.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(PROGRAM_CRT) --capability "linear-regression.wasm : $(WRITE_RIGHT)" \
		--certificate $(DATA_CRT) --capability "input-0 : $(WRITE_RIGHT), output : $(READ_RIGHT), linear-regression.wasm : $(WRITE_RIGHT)" \
		--certificate $(RESULT_CRT) --capability "output : $(READ_RIGHT), linear-regression.wasm : $(WRITE_RIGHT)" \
		--binary linear-regression.wasm --capability "input-0 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3016 --proxy-attestation-server-ip 127.0.0.1:3010 \
		 --stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/triple_parties_two_data_sources_sum_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/intersection-set-sum.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(PROGRAM_CRT) --capability "intersection-set-sum.wasm : $(WRITE_RIGHT)" \
		--certificate $(DATA_CRT) --capability "input-0 : $(WRITE_RIGHT)" \
		--certificate $(RESULT_CRT) --capability "input-1 : $(WRITE_RIGHT), output : $(READ_RIGHT)" \
		--binary intersection-set-sum.wasm --capability "input-0 : $(READ_RIGHT), input-1 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3017 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/permuted_triple_parties_two_data_sources_sum_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/intersection-set-sum.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(PROGRAM_CRT) --capability "intersection-set-sum.wasm : $(WRITE_RIGHT)" \
		--certificate $(DATA_CRT) --capability "input-0 : $(WRITE_RIGHT)" \
		--certificate $(RESULT_CRT) --capability "input-1 : $(WRITE_RIGHT), output : $(READ_RIGHT)" \
		--binary intersection-set-sum.wasm --capability "input-0 : $(READ_RIGHT), input-1 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3018 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/triple_parties_two_data_sources_string_edit_distance_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/string-edit-distance.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(PROGRAM_CRT) --capability "string-edit-distance.wasm : $(WRITE_RIGHT)" \
		--certificate $(DATA_CRT) --capability "input-0 : $(WRITE_RIGHT)" \
		--certificate $(RESULT_CRT) --capability "input-1 : $(WRITE_RIGHT), output : $(READ_RIGHT)" \
		--binary string-edit-distance.wasm  --capability "input-0 : $(READ_RIGHT), input-1 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3019 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/quadruple_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/string-edit-distance.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(PROGRAM_CRT) --capability "string-edit-distance.wasm : $(WRITE_RIGHT)" \
		--certificate $(DATA_CRT) --capability "input-0 : $(WRITE_RIGHT)" \
		--certificate $(WORKSPACE_DIR)/host/crates/test-collateral/never_used_cert.pem --capability "input-1 : $(WRITE_RIGHT)" \
		--certificate $(RESULT_CRT) --capability "output : $(READ_RIGHT)" \
		--binary string-edit-distance.wasm --capability "input-0 : $(READ_RIGHT), input-1 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3020 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/invalid_policy_one_expired_data_source_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/linear-regression.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(EXPIRED_CRT) --capability "input-0 : $(WRITE_RIGHT), output : $(READ_RIGHT), linear-regression.wasm : $(WRITE_RIGHT)" \
		--binary linear-regression.wasm --capability "input-0 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3021 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/idash2017_logistic_regression_policy.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/idash2017-logistic-regression.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(CLIENT_CRT) --capability "input-0 : $(WRITE_RIGHT), output : $(READ_RIGHT), idash2017-logistic-regression.wasm : $(WRITE_RIGHT)" \
		--binary idash2017-logistic-regression.wasm  --capability "input-0 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3023 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/moving_average_convergence_divergence.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/moving-average-convergence-divergence.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(CLIENT_CRT) --capability "input-0 : $(WRITE_RIGHT), output : $(READ_RIGHT), moving-average-convergence-divergence.wasm : $(WRITE_RIGHT)" \
		--binary moving-average-convergence-divergence.wasm --capability "input-0 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3024 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/private_set_intersection_sum.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/private-set-intersection-sum.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(CLIENT_CRT) --capability "input-0 : $(WRITE_RIGHT), output : $(READ_RIGHT), private-set-intersection-sum.wasm : $(WRITE_RIGHT)" \
		--binary private-set-intersection-sum.wasm --capability "input-0 : $(READ_RIGHT), output : $(WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3025 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/number-stream-accumulation.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/number-stream-accumulation.wasm
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(CLIENT_CRT) --capability "stream-0 : $(WRITE_RIGHT), stream-1 : $(WRITE_RIGHT), input-0 : $(WRITE_RIGHT), output : $(READ_RIGHT), number-stream-accumulation.wasm : $(WRITE_RIGHT)" \
		--binary number-stream-accumulation.wasm --capability "stream-0 : $(READ_RIGHT), stream-1 : $(READ_RIGHT), input-0 : $(READ_RIGHT), output : $(READ_WRITE_RIGHT)" \
		--veracruz-server-ip 127.0.0.1:3026 --proxy-attestation-server-ip 127.0.0.1:3010 \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/basic_file_read_write.json: $(PGEN) $(CREDENTIALS) $(OUT_DIR)/read-file.wasm 
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(CLIENT_CRT) --capability "input.txt: $(WRITE_RIGHT), output : $(READ_RIGHT), read-file.wasm : $(WRITE_RIGHT)" \
		--binary read-file.wasm --capability "input.txt: $(READ_RIGHT), output : $(WRITE_RIGHT)" \
        --veracruz-server-ip 127.0.0.1:3011 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--stdin "stdin : $(READ_RIGHT)" --stdout "stdout : $(WRITE_RIGHT)" --stderr "stderr : $(WRITE_RIGHT)" \
		$(PGEN_COMMON_PARAMS) --output-policy-file $@
