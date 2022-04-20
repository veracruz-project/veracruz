# shared.mk: Shared make rules for test programs / policies
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

.PHONY: wasm-files datasets proxy-attestation-server-db policy-files test-collateral

test-collateral: wasm-files datasets proxy-attestation-server-db $(MEASUREMENT_FILE) policy-files

###################################################
# Wasm programs

WASM_PROG_LIST = random-source.wasm \
				linear-regression.wasm \
				string-edit-distance.wasm \
				intersection-set-sum.wasm \
				postcard-native.wasm \
				postcard-wasm.wasm \
				private-set-intersection.wasm \
				idash2017-logistic-regression.wasm \
				moving-average-convergence-divergence.wasm \
				private-set-intersection-sum.wasm \
				number-stream-accumulation.wasm \
				read-file.wasm \
				shamir-secret-sharing.wasm \
				fd-create.wasm

WASM_PROG_FILES = $(patsubst %.wasm, $(OUT_DIR)/%.wasm, $(WASM_PROG_LIST))

.PRECIOUS: $(WASM_PROG_FILES)

wasm-files: $(OUT_DIR) $(WASM_PROG_FILES)

$(OUT_DIR):
	@mkdir -p $@

$(OUT_DIR)/%.wasm: $(WORKSPACE_DIR)/applications/target/wasm32-wasi/$(PROFILE_PATH)/%.wasm
	cp $< $@

.PRECIOUS: $(WORKSPACE_DIR)/applications/target/wasm32-wasi/$(PROFILE_PATH)/%.wasm

$(WORKSPACE_DIR)/applications/target/wasm32-wasi/$(PROFILE_PATH)/%.wasm:
	$(MAKE) -C $(WORKSPACE_DIR)/applications

###################################################
# Datasets

datasets: $(OUT_DIR)
	$(MAKE) -C ../host datasets
	cp -r ../../sdk/datasets/* $(OUT_DIR)
	cp ../../test-collateral/*.pem $(OUT_DIR)

###################################################
# Proxy Attestation Server database

PROXY_ATTESTATION_SERVER_DB = $(abspath $(OUT_DIR)/..)/proxy-attestation-server.db

proxy-attestation-server-db: $(PROXY_ATTESTATION_SERVER_DB)

$(PROXY_ATTESTATION_SERVER_DB):
	diesel setup --config-file crates/proxy-attestation-server/diesel.toml --database-url $@ \
		--migration-dir crates/proxy-attestation-server/migrations
	echo "INSERT INTO firmware_versions VALUES(2, 'psa', '0.3.0', 'deadbeefdeadbeefdeadbeefdeadbeeff00dcafef00dcafef00dcafef00dcafe');" > tmp.sql
	sqlite3 $@ < tmp.sql
	rm tmp.sql

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
READ_RIGHT       := $(shell echo $(FD_READ) + $(FD_SEEK) + $(PATH_OPEN) + $(FD_READDIR) | bc)
WRITE_RIGHT      := $(shell echo $(FD_WRITE) + $(PATH_CREATE_FILE) + $(PATH_FILESTAT_SET_SIZE) + $(FD_SEEK) + $(PATH_OPEN) + $(PATH_CREATE_DIRECTORY) | bc)
READ_WRITE_RIGHT := $(shell echo $(FD_READ) + $(FD_SEEK) + $(PATH_OPEN) + $(FD_READDIR) + $(FD_WRITE) + $(PATH_CREATE_FILE) + $(PATH_FILESTAT_SET_SIZE) + $(PATH_CREATE_DIRECTORY) | bc)

ifeq ($(PLATFORM), Darwin)
	CERTIFICATE_EXPIRY := "$(shell date -Rf +100d)"
endif

ifeq ($(PLATFORM), Linux)
	CERTIFICATE_EXPIRY := "$(shell date --rfc-2822 -d 'now + 100 days')"
endif

POLICY_FILES ?= \
	single_client.json \
	single_client_no_debug.json \
	dual_policy.json \
	dual_parallel_policy.json \
	triple_policy_1.json \
	triple_policy_2.json \
	triple_policy_3.json \
	triple_policy_4.json \
	quadruple_policy.json

PGEN = $(WORKSPACE_DIR)/host/target/$(PROFILE_PATH)/generate-policy

$(PGEN): $(WORKSPACE_DIR)/host/crates/test-collateral/generate-policy/src/main.rs \
	$(WORKSPACE_DIR)/host/crates/test-collateral/generate-policy/Cargo.toml
	$(MAKE) -C $(WORKSPACE_DIR)/host

policy-files: $(OUT_DIR) $(MEASUREMENT_FILE) $(patsubst %.json, $(OUT_DIR)/%.json, $(POLICY_FILES)) $(OUT_DIR)/invalid_policy
	@echo $(INFO_COLOR)"GEN   =>  $(POLICY_FILES)"$(RESET_COLOR)

PROGRAM_DIR = /program/

CA_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/CACert.pem
CLIENT_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/client_rsa_cert.pem
PROGRAM_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/program_client_cert.pem
DATA_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/data_client_cert.pem
RESULT_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/result_client_cert.pem
NEVER_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/never_used_cert.pem
EXPIRED_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/expired_cert.pem

CREDENTIALS = $(CA_CRT) $(CLIENT_CRT) $(PROGRAM_CRT) $(DATA_CRT) $(RESULT_CRT) $(EXPIRED_CRT) $(MEASUREMENT_FILE)

PGEN_COMMON_PARAMS = --proxy-attestation-server-cert $(CA_CRT) $(MEASUREMENT_PARAMETER) \
	--certificate-expiry $(CERTIFICATE_EXPIRY) --execution-strategy Interpretation

$(OUT_DIR)/invalid_policy: $(WORKSPACE_DIR)/../test-collateral/invalid_policy/*.json
	mkdir -p $@
	cp $(WORKSPACE_DIR)/../test-collateral/invalid_policy/*.json $@

$(OUT_DIR)/single_client.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES)
	cd $(OUT_DIR) ; $(PGEN) --certificate $(CLIENT_CRT) \
	    --capability "/input/: $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_WRITE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT), /services/ : $(READ_WRITE_RIGHT)") \
            --veracruz-server-ip 127.0.0.1:3011 --proxy-attestation-server-ip 127.0.0.1:3010 \
	    --enclave-debug-mode $(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/single_client_no_debug.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES)
	cd $(OUT_DIR) ; $(PGEN) --certificate $(CLIENT_CRT) \
	    --capability "/input/: $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_WRITE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT), /services/ : $(READ_WRITE_RIGHT)") \
            --veracruz-server-ip 127.0.0.1:3011 --proxy-attestation-server-ip 127.0.0.1:3010 \
	    $(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/dual_policy.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES)
	cd $(OUT_DIR) ; $(PGEN) \
	    --certificate $(PROGRAM_CRT) --capability "$(PROGRAM_DIR) : $(READ_WRITE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    --certificate $(DATA_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), stdin : $(WRITE_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT)") \
		--veracruz-server-ip 127.0.0.1:3012 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--enable-clock $(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/dual_parallel_policy.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES)
	cd $(OUT_DIR) ; $(PGEN) \
	    --certificate $(PROGRAM_CRT) --capability "$(PROGRAM_DIR) : $(READ_WRITE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    --certificate $(DATA_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_RIGHT), stdin : $(WRITE_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT)") \
	    --veracruz-server-ip 127.0.0.1:3013 --proxy-attestation-server-ip 127.0.0.1:3010 \
	    --enable-clock $(PGEN_COMMON_PARAMS) --output-policy-file $@

# Generate all the triple policy but on different port.
$(OUT_DIR)/triple_policy_%.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES)
	cd $(OUT_DIR) ; $(PGEN) \
	    --certificate $(PROGRAM_CRT) --capability "$(PROGRAM_DIR) : $(READ_WRITE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    --certificate $(DATA_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_RIGHT), stdin : $(WRITE_RIGHT)" \
	    --certificate $(RESULT_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT)") \
	    --veracruz-server-ip 127.0.0.1:$(shell echo "3020 + $*" | bc) \
	    --proxy-attestation-server-ip 127.0.0.1:3010 \
	    --enable-clock $(PGEN_COMMON_PARAMS) --output-policy-file $@

$(OUT_DIR)/quadruple_policy.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES)
	cd $(OUT_DIR) ; $(PGEN) \
	    --certificate $(PROGRAM_CRT) --capability "$(PROGRAM_DIR) : $(READ_WRITE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    --certificate $(DATA_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_RIGHT), stdin : $(WRITE_RIGHT)" \
	    --certificate $(NEVER_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_RIGHT), stdin : $(WRITE_RIGHT)" \
	    --certificate $(RESULT_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT)") \
	    --veracruz-server-ip 127.0.0.1:3030 --proxy-attestation-server-ip 127.0.0.1:3010 \
	    --enable-clock $(PGEN_COMMON_PARAMS) --output-policy-file $@
