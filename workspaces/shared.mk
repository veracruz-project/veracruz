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

PLATFORM := $(shell uname)

.PHONY: datasets measurement-file policy-files test-collateral wasm-files

test-collateral: datasets measurement-file policy-files wasm-files

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
				random-u32-list.wasm \
				shamir-secret-sharing.wasm \
				sort-numbers.wasm \
				fd-create.wasm \
				aesctr-native.wasm

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
# Keys and certs

CA_KEY = $(WORKSPACE_DIR)/host/crates/test-collateral/CAKey.pem
CA_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/CACert.pem

$(CA_KEY): $(WORKSPACE_DIR)/host/crates/test-collateral
	# The -noout argument suppresses the inclusion of the EC PARAMETERS in the generated file
	openssl ecparam -name prime256v1 -genkey -noout -out $@

$(CA_CRT): $(CA_KEY) $(WORKSPACE_DIR)/host/crates/test-collateral
	openssl req -x509 -key $< -out $@ -config $(WORKSPACE_DIR)/ca-cert.conf

CLIENT_KEY = $(WORKSPACE_DIR)/host/crates/test-collateral/client_key.pem
CLIENT_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/client_cert.pem
PROGRAM_KEY = $(WORKSPACE_DIR)/host/crates/test-collateral/program_client_key.pem
PROGRAM_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/program_client_cert.pem
DATA_KEY = $(WORKSPACE_DIR)/host/crates/test-collateral/data_client_key.pem
DATA_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/data_client_cert.pem
RESULT_KEY = $(WORKSPACE_DIR)/host/crates/test-collateral/result_client_key.pem
RESULT_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/result_client_cert.pem
NEVER_KEY = $(WORKSPACE_DIR)/host/crates/test-collateral/never_used_key.pem
NEVER_CRT = $(WORKSPACE_DIR)/host/crates/test-collateral/never_used_cert.pem

CERTS = $(CLIENT_CRT) $(PROGRAM_CRT) $(DATA_CRT) $(RESULT_CRT) $(NEVER_CRT)
KEYS = $(CLIENT_KEY) $(PROGRAM_KEY) $(DATA_KEY) $(RESULT_KEY) $(NEVER_KEY)

$(WORKSPACE_DIR)/host/crates/test-collateral:
	mkdir -p $@

$(KEYS): %.pem : $(WORKSPACE_DIR)/host/crates/test-collateral
	openssl ecparam -name prime256v1 -genkey -out $@

$(CERTS): $(WORKSPACE_DIR)/host/crates/test-collateral/%_cert.pem : $(WORKSPACE_DIR)/host/crates/test-collateral/%_key.pem $(WORKSPACE_DIR)/host/crates/test-collateral
	openssl req -x509 -key $< -out $@ -config $(WORKSPACE_DIR)/cert.conf

###################################################
# Datasets

datasets: $(OUT_DIR) $(CERTS) $(KEYS) $(CA_KEY) $(CA_CRT)
	$(MAKE) -C $(WORKSPACE_DIR)/data-generators
	$(MAKE) -C ../host datasets
	cp -r ../../examples/datasets/* $(OUT_DIR)
	cp ../../test-collateral/*.pem $(OUT_DIR)

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
FD_EXECUTE              := $(shell echo "2^29"  | bc)
# Common rights
READ_RIGHT          := $(shell echo $(FD_READ) + $(FD_SEEK) + $(PATH_OPEN) + $(FD_READDIR) | bc)
WRITE_RIGHT         := $(shell echo $(FD_WRITE) + $(PATH_CREATE_FILE) + $(PATH_FILESTAT_SET_SIZE) + $(FD_SEEK) + $(PATH_OPEN) + $(PATH_CREATE_DIRECTORY) | bc)
READ_WRITE_RIGHT    := $(shell echo $(FD_READ) + $(FD_SEEK) + $(PATH_OPEN) + $(FD_READDIR) + $(FD_WRITE) + $(PATH_CREATE_FILE) + $(PATH_FILESTAT_SET_SIZE) + $(PATH_CREATE_DIRECTORY) | bc)
OPEN_EXECUTE_RIGHT  := $(shell echo $(PATH_OPEN) + $(FD_EXECUTE) + $(FD_SEEK) | bc)
WRITE_EXECUTE_RIGHT := $(shell echo $(FD_WRITE) + $(PATH_CREATE_FILE) + $(PATH_FILESTAT_SET_SIZE) + $(FD_SEEK) + $(PATH_OPEN) + $(PATH_CREATE_DIRECTORY) + $(FD_EXECUTE) | bc)

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
	triple_policy_4.json \
	quadruple_policy.json \
	single_client_postcard_native.json \
	single_client_aesctr_native.json

PGEN = $(WORKSPACE_DIR)/host/target/$(PROFILE_PATH)/generate-policy

$(PGEN): $(WORKSPACE_DIR)/host/crates/sdk/generate-policy/src/main.rs \
	$(WORKSPACE_DIR)/host/crates/sdk/generate-policy/Cargo.toml
	$(MAKE) -C $(WORKSPACE_DIR)/host

policy-files: $(OUT_DIR) measurement-file $(patsubst %.json, $(OUT_DIR)/%.json, $(POLICY_FILES))
	@echo $(INFO_COLOR)"GEN   =>  $(POLICY_FILES)"$(RESET_COLOR)

PROGRAM_DIR = /program/

CREDENTIALS = $(CA_CRT) $(CLIENT_CRT) $(PROGRAM_CRT) $(DATA_CRT) $(RESULT_CRT) $(MEASUREMENT_FILE)

PGEN_COMMON_PARAMS = --proxy-attestation-server-cert $(CA_CRT) $(MEASUREMENT_PARAMETER) \
	--certificate-expiry $(CERTIFICATE_EXPIRY) --execution-strategy Interpretation

MAX_MEMORY_MIB = 256

$(OUT_DIR)/single_client.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) --certificate $(CLIENT_CRT) \
	    --capability "/input/: $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--program-binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT), /services/ : $(READ_WRITE_RIGHT)") \
	    --pipeline "$(PROGRAM_DIR)random-u32-list.wasm ; if /output/unsorted_numbers.txt { $(PROGRAM_DIR)sort-numbers.wasm ; }" --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT), /services/ : $(READ_WRITE_RIGHT)" \
            --veracruz-server-ip 127.0.0.1:3011 --proxy-attestation-server-ip 127.0.0.1:3010 \
	    --enclave-debug-mode $(PGEN_COMMON_PARAMS) --max-memory-mib $(MAX_MEMORY_MIB) --output-policy-file $@

$(OUT_DIR)/single_client_no_debug.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) --certificate $(CLIENT_CRT) \
	    --capability "/input/: $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--program-binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT), /services/ : $(READ_WRITE_RIGHT)") \
            --veracruz-server-ip 127.0.0.1:3011 --proxy-attestation-server-ip 127.0.0.1:3010 \
	    $(PGEN_COMMON_PARAMS) --max-memory-mib $(MAX_MEMORY_MIB) --output-policy-file $@

$(OUT_DIR)/dual_policy.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) \
	    --certificate $(PROGRAM_CRT) --capability "$(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    --certificate $(DATA_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), stdin : $(WRITE_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--program-binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT)") \
		--veracruz-server-ip 127.0.0.1:3012 --proxy-attestation-server-ip 127.0.0.1:3010 \
		--enable-clock $(PGEN_COMMON_PARAMS) --max-memory-mib $(MAX_MEMORY_MIB) --output-policy-file $@

$(OUT_DIR)/dual_parallel_policy.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) \
	    --certificate $(PROGRAM_CRT) --capability "$(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    --certificate $(DATA_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(OPEN_EXECUTE_RIGHT), stdin : $(WRITE_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--program-binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT)") \
	    --veracruz-server-ip 127.0.0.1:3013 --proxy-attestation-server-ip 127.0.0.1:3010 \
	    --enable-clock $(PGEN_COMMON_PARAMS) --max-memory-mib $(MAX_MEMORY_MIB) --output-policy-file $@

# Generate all the triple policy but on different port.
$(OUT_DIR)/triple_policy_%.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) \
	    --certificate $(PROGRAM_CRT) --capability "$(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    --certificate $(DATA_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(OPEN_EXECUTE_RIGHT), stdin : $(WRITE_RIGHT)" \
	    --certificate $(RESULT_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(OPEN_EXECUTE_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--program-binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT)") \
	    --veracruz-server-ip 127.0.0.1:$(shell echo "3020 + $*" | bc) \
	    --proxy-attestation-server-ip 127.0.0.1:3010 \
	    --enable-clock $(PGEN_COMMON_PARAMS) --max-memory-mib $(MAX_MEMORY_MIB) --output-policy-file $@

$(OUT_DIR)/quadruple_policy.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) \
	    --certificate $(PROGRAM_CRT) --capability "$(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    --certificate $(DATA_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(OPEN_EXECUTE_RIGHT), stdin : $(WRITE_RIGHT)" \
	    --certificate $(NEVER_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(OPEN_EXECUTE_RIGHT), stdin : $(WRITE_RIGHT)" \
	    --certificate $(RESULT_CRT) --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(OPEN_EXECUTE_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--program-binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT)") \
	    --veracruz-server-ip 127.0.0.1:3030 --proxy-attestation-server-ip 127.0.0.1:3010 \
	    --enable-clock $(PGEN_COMMON_PARAMS) --max-memory-mib $(MAX_MEMORY_MIB) --output-policy-file $@

$(OUT_DIR)/single_client_postcard_native.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) --certificate $(CLIENT_CRT) \
	    --capability "/input/: $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--program-binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT), /services/ : $(READ_WRITE_RIGHT)") \
            --veracruz-server-ip 127.0.0.1:3011 --proxy-attestation-server-ip 127.0.0.1:3010 \
	    --enclave-debug-mode $(PGEN_COMMON_PARAMS) --max-memory-mib $(MAX_MEMORY_MIB) \
		--native-module-name "Postcard Service" --native-module-special-file "/services/postcard_string.dat" --native-module-entry-point "" \
		--output-policy-file $@

$(OUT_DIR)/single_client_aesctr_native.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) --certificate $(CLIENT_CRT) \
	    --capability "/input/: $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT), stdin : $(WRITE_RIGHT), stderr : $(READ_RIGHT), stdout : $(READ_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--program-binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT), stdin : $(READ_RIGHT), stderr : $(WRITE_RIGHT), stdout : $(WRITE_RIGHT), /services/ : $(READ_WRITE_RIGHT)") \
            --veracruz-server-ip 127.0.0.1:3011 --proxy-attestation-server-ip 127.0.0.1:3010 \
	    --enclave-debug-mode $(PGEN_COMMON_PARAMS) --max-memory-mib $(MAX_MEMORY_MIB) \
		--native-module-name "Counter mode AES Service" --native-module-special-file "/services/aesctr.dat" --native-module-entry-point "" \
		--output-policy-file $@
