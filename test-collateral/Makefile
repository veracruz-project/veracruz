# Makefile for test-collateral generation
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

.PHONY: all policy-files clean pgen

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"
PLATFORM := $(shell uname)
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
PROGRAM_DIR := /program/


RUNTIME_MANAGER_CSS_BIN := ../runtime-manager/css-$(TEE).bin
RUNTIME_MANAGER_PCR0 := ../runtime-manager/PCR0

ifeq ($(PLATFORM), Darwin)
	CERTIFICATE_EXPIRY := "$(shell date -Rf +100d)"
endif

ifeq ($(PLATFORM), Linux)
	CERTIFICATE_EXPIRY := "$(shell date --rfc-2822 -d 'now + 100 days')"
endif

# the equivalent policy of one program provider and two data providers, however, deploy to different ports.
TRIPLE_POLICY_FILE := triple_policy_1.json \
					  triple_policy_2.json \
					  triple_policy_3.json \
					  triple_policy_4.json 

POLICY_FILES ?= single_client.json \
				single_client_no_debug.json \
				dual_policy.json \
				dual_parallel_policy.json \
				$(TRIPLE_POLICY_FILE) \
				quadruple_policy.json 

WASM_PROG_FILES = random-source.wasm \
				  linear-regression.wasm \
				  string-edit-distance.wasm \
				  intersection-set-sum.wasm \
				  private-set-intersection.wasm \
				  idash2017-logistic-regression.wasm \
				  moving-average-convergence-divergence.wasm \
				  private-set-intersection-sum.wasm \
				  number-stream-accumulation.wasm \
		                  read-file.wasm \
				  shamir-secret-sharing.wasm

DATA_FILES = linear-regression.dat \
			 hello-world-1.dat \
			 hello-world-2.dat \
			 intersection-customer.dat \
             intersection-advertisement-viewer.dat \
			 private-set-1.dat \
			 private-set-2.dat \
			 number-stream-init.dat \
			 share-1.dat \
			 share-2.dat \
			 share-3.dat

DATA_DIRS = idash2017 \
            macd \
            private-set-inter-sum \
            number-stream

all: pgen policy-files proxy-attestation-server.db $(WASM_PROG_FILES) $(DATA_FILES) $(DATA_DIRS)

pgen: generate-policy/src/main.rs generate-policy/Cargo.toml generate-policy/Makefile 
	$(MAKE) -C generate-policy
	cp generate-policy/target/release/generate-policy ./pgen

policy-files: $(POLICY_FILES)
	@echo $(INFO_COLOR)"GEN   =>  $(POLICY_FILES)"$(RESET_COLOR)

proxy-attestation-server.db:
	bash ./populate-test-database.sh proxy-attestation-server.db

$(RUNTIME_MANAGER_CSS_BIN):
	$(MAKE) css-$(TEE).bin -C ../runtime-manager

css-$(TEE).bin: $(RUNTIME_MANAGER_CSS_BIN)
	$(MAKE) css-$(TEE).bin -C ../runtime-manager
	cp $< $@

single_client.json: pgen css-$(TEE).bin client_rsa_cert.pem $(WASM_PROG_FILES)
	./pgen --certificate client_rsa_cert.pem --capability "/input/: $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_WRITE_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--binary $(PROGRAM_DIR)$(prog_name)=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT)") \
        --veracruz-server-ip 127.0.0.1:3011 --proxy-attestation-server-ip 127.0.0.1:3010 --output-policy-file $@ --certificate-expiry $(CERTIFICATE_EXPIRY) \
		--enclave-debug-mode true --execution-strategy Interpretation \
		--css-file $(RUNTIME_MANAGER_CSS_BIN) --pcr-file $(RUNTIME_MANAGER_PCR0) \
		--proxy-attestation-server-cert ../test-collateral/CACert.pem

single_client_no_debug.json: pgen css-$(TEE).bin client_rsa_cert.pem $(WASM_PROG_FILES)
	./pgen --certificate client_rsa_cert.pem --capability "/input/: $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_WRITE_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--binary $(PROGRAM_DIR)$(prog_name)=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT)") \
        --veracruz-server-ip 127.0.0.1:3011 --proxy-attestation-server-ip 127.0.0.1:3010 --output-policy-file $@ --certificate-expiry $(CERTIFICATE_EXPIRY) \
		--execution-strategy Interpretation \
		--css-file $(RUNTIME_MANAGER_CSS_BIN) --pcr-file $(RUNTIME_MANAGER_PCR0) \
		--proxy-attestation-server-cert ../test-collateral/CACert.pem

dual_policy.json: pgen css-$(TEE).bin program_client_cert.pem data_client_cert.pem linear-regression.wasm
	./pgen --certificate program_client_cert.pem --capability "$(PROGRAM_DIR) : $(READ_WRITE_RIGHT)" \
		--certificate data_client_cert.pem --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--binary $(PROGRAM_DIR)$(prog_name)=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT)") \
		--veracruz-server-ip 127.0.0.1:3012 --proxy-attestation-server-ip 127.0.0.1:3010 --output-policy-file $@ --certificate-expiry $(CERTIFICATE_EXPIRY) \
		--execution-strategy Interpretation \
		--enable-clock true \
		--css-file $(RUNTIME_MANAGER_CSS_BIN) --pcr-file $(RUNTIME_MANAGER_PCR0) \
		--proxy-attestation-server-cert ../test-collateral/CACert.pem

dual_parallel_policy.json: pgen css-$(TEE).bin program_client_cert.pem data_client_cert.pem linear-regression.wasm
	./pgen --certificate program_client_cert.pem --capability "$(PROGRAM_DIR) : $(READ_WRITE_RIGHT)" \
		--certificate data_client_cert.pem --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--binary $(PROGRAM_DIR)$(prog_name)=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT)") \
		--veracruz-server-ip 127.0.0.1:3013 --proxy-attestation-server-ip 127.0.0.1:3010 --output-policy-file $@ --certificate-expiry $(CERTIFICATE_EXPIRY) \
		--execution-strategy Interpretation \
		--enable-clock true \
		--css-file $(RUNTIME_MANAGER_CSS_BIN) --pcr-file $(RUNTIME_MANAGER_PCR0) \
		--proxy-attestation-server-cert ../test-collateral/CACert.pem

# Generate all the triple policy but on different port.
$(TRIPLE_POLICY_FILE) : triple_policy_%.json : pgen css-$(TEE).bin program_client_cert.pem data_client_cert.pem result_client_cert.pem linear-regression.wasm
	./pgen --certificate program_client_cert.pem --capability "$(PROGRAM_DIR) : $(READ_WRITE_RIGHT)" \
		--certificate data_client_cert.pem --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_RIGHT)" \
		--certificate result_client_cert.pem --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--binary $(PROGRAM_DIR)$(prog_name)=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT)") \
		--veracruz-server-ip 127.0.0.1:$(shell echo "3020 + $(patsubst triple_policy_%.json,%,$@)" | bc) \
	    --proxy-attestation-server-ip 127.0.0.1:3010 --output-policy-file $@ --certificate-expiry $(CERTIFICATE_EXPIRY) \
		--execution-strategy Interpretation \
		--enable-clock true \
		--css-file $(RUNTIME_MANAGER_CSS_BIN) --pcr-file $(RUNTIME_MANAGER_PCR0) \
		--proxy-attestation-server-cert ../test-collateral/CACert.pem

quadruple_policy.json: pgen css-$(TEE).bin program_client_cert.pem data_client_cert.pem result_client_cert.pem string-edit-distance.wasm
	./pgen --certificate program_client_cert.pem --capability "$(PROGRAM_DIR) : $(READ_WRITE_RIGHT)" \
		--certificate data_client_cert.pem --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_RIGHT)" \
		--certificate never_used_cert.pem --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_RIGHT)" \
		--certificate result_client_cert.pem --capability "/input/ : $(WRITE_RIGHT), /output/ : $(READ_RIGHT), $(PROGRAM_DIR) : $(READ_RIGHT)" \
	    $(foreach prog_name,$(WASM_PROG_FILES),--binary $(PROGRAM_DIR)$(prog_name)=$(prog_name) --capability "/input/ : $(READ_RIGHT), /output/ : $(READ_WRITE_RIGHT)") \
		--veracruz-server-ip 127.0.0.1:3030 --proxy-attestation-server-ip 127.0.0.1:3010 --output-policy-file $@ --certificate-expiry $(CERTIFICATE_EXPIRY) \
		--execution-strategy Interpretation \
		--enable-clock true \
		--css-file $(RUNTIME_MANAGER_CSS_BIN) --pcr-file $(RUNTIME_MANAGER_PCR0) \
		--proxy-attestation-server-cert ../test-collateral/CACert.pem

.SECONDEXPANSION:
$(WASM_PROG_FILES) : %.wasm: ../sdk/target/wasm32-wasi/release/$$@
	cp $< $@

$(DATA_FILES) : %.dat: ../sdk/datasets/%.dat 
	cp $< $@

$(DATA_DIRS) : %: ../sdk/datasets/% 
	cp -r $< $@

doc:
	$(MAKE) -C generate-policy doc

clean:
	rm -f pgen
	rm -f *.json
	rm -f css-$(TEE).bin
	rm -f *.dat
	$(MAKE) -C generate-policy clean
	rm -f *.wasm
