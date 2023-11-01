# shared.mk: Shared make rules for test programs / policies
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.md` file in the Veracruz root director for licensing
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
	cp -r crates/examples/datasets/* $(OUT_DIR)
	cp crates/test-collateral/*.pem $(OUT_DIR)

###################################################
# Generate Policy Files

# Common rights
READ_RIGHT          := r
WRITE_RIGHT         := w
READ_WRITE_RIGHT    := rw
OPEN_EXECUTE_RIGHT  := rx
WRITE_EXECUTE_RIGHT := wx

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
	quadruple_policy.json 

PGEN = $(WORKSPACE_DIR)/host/target/$(PROFILE_PATH)/generate-policy

$(PGEN): $(WORKSPACE_DIR)/host/crates/generate-policy/src/main.rs \
	$(WORKSPACE_DIR)/host/crates/generate-policy/Cargo.toml
	$(MAKE) -C $(WORKSPACE_DIR)/host

policy-files: $(OUT_DIR) measurement-file $(patsubst %.json, $(OUT_DIR)/%.json, $(POLICY_FILES))
	@echo $(INFO_COLOR)"GEN   =>  $(POLICY_FILES)"$(RESET_COLOR)

PROGRAM_DIR = ./program/

CREDENTIALS = $(CA_CRT) $(CLIENT_CRT) $(PROGRAM_CRT) $(DATA_CRT) $(RESULT_CRT) $(MEASUREMENT_FILE)

PGEN_COMMON_PARAMS = 

CLIENT_WRITE_PROG_CAPABILITY = "./input/ : $(WRITE_RIGHT), ./output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT), /tmp/ : $(READ_WRITE_RIGHT)"
CLIENT_READ_PROG_CAPABILITY = "./input/ : $(WRITE_RIGHT), ./output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(OPEN_EXECUTE_RIGHT), /tmp/ : $(READ_WRITE_RIGHT)"
DEFAULT_PROGRAM_LIST = $(foreach prog_name,$(WASM_PROG_FILES),--program-binary $(PROGRAM_DIR)$(notdir $(prog_name))=$(prog_name) --capability "./input/ : $(READ_RIGHT), ./output/ : $(READ_WRITE_RIGHT), /tmp/ : $(READ_WRITE_RIGHT)")

MAX_MEMORY_MIB = 256
DEFAULT_FLAGS = --proxy-attestation-server-ip 127.0.0.1:3010 \
			    --proxy-attestation-server-cert $(CA_CRT) $(MEASUREMENT_PARAMETER) \
				--certificate-expiry $(CERTIFICATE_EXPIRY) \
				--execution-strategy JIT \
 				--max-memory-mib $(MAX_MEMORY_MIB) 

$(OUT_DIR)/single_client.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) --certificate $(CLIENT_CRT) --capability  $(CLIENT_WRITE_PROG_CAPABILITY) \
	    $(DEFAULT_PROGRAM_LIST) \
	    --pipeline "$(PROGRAM_DIR)random-u32-list.wasm ; if ./output/unsorted_numbers.txt { $(PROGRAM_DIR)sort-numbers.wasm ; }" --capability "./input/ : $(READ_RIGHT), ./output/ : $(READ_WRITE_RIGHT), ./services/ : $(READ_WRITE_RIGHT)" \
        --veracruz-server-ip 127.0.0.1:3011 \
		$(DEFAULT_FLAGS) \
	    --output-policy-file $@

$(OUT_DIR)/single_client_no_debug.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) --certificate $(CLIENT_CRT) --capability $(CLIENT_WRITE_PROG_CAPABILITY) \
		${DEFAULT_PROGRAM_LIST} \
		--veracruz-server-ip 127.0.0.1:3011  \
		$(DEFAULT_FLAGS) \
		--output-policy-file $@

$(OUT_DIR)/dual_policy.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(PROGRAM_CRT) --capability "$(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT)" \
		--certificate $(DATA_CRT) --capability "./input/ : $(WRITE_RIGHT), ./output/ : $(READ_RIGHT)" \
		$(DEFAULT_PROGRAM_LIST) \
		--veracruz-server-ip 127.0.0.1:3012 \
		$(DEFAULT_FLAGS) \
		--output-policy-file $@

$(OUT_DIR)/dual_parallel_policy.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(PROGRAM_CRT) --capability "$(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT)" \
		--certificate $(DATA_CRT) --capability $(CLIENT_READ_PROG_CAPABILITY) \
		$(DEFAULT_PROGRAM_LIST) \
		--veracruz-server-ip 127.0.0.1:3013 \
		$(DEFAULT_FLAGS) \
		--output-policy-file $@

# Generate all the triple policy but on different port.
$(OUT_DIR)/triple_policy_%.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(PROGRAM_CRT) --capability "$(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT)" \
		--certificate $(DATA_CRT) --capability $(CLIENT_READ_PROG_CAPABILITY) \
		--certificate $(RESULT_CRT) --capability $(CLIENT_READ_PROG_CAPABILITY) \
		$(DEFAULT_PROGRAM_LIST) \
		--veracruz-server-ip 127.0.0.1:$(shell echo "3020 + $*" | bc) \
		$(DEFAULT_FLAGS) \
		--output-policy-file $@

$(OUT_DIR)/quadruple_policy.json: $(PGEN) $(CREDENTIALS) $(WASM_PROG_FILES) $(RUNTIME_ENCLAVE_BINARY_PATH)
	cd $(OUT_DIR) ; $(PGEN) \
		--certificate $(PROGRAM_CRT) --capability "$(PROGRAM_DIR) : $(WRITE_EXECUTE_RIGHT)" \
		--certificate $(DATA_CRT) --capability $(CLIENT_READ_PROG_CAPABILITY) \
		--certificate $(NEVER_CRT) --capability $(CLIENT_READ_PROG_CAPABILITY) \
		--certificate $(RESULT_CRT) --capability $(CLIENT_READ_PROG_CAPABILITY) \
		$(DEFAULT_PROGRAM_LIST) \
		--veracruz-server-ip 127.0.0.1:3030 \
		$(DEFAULT_FLAGS) \
		--output-policy-file $@
