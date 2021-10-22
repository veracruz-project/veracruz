# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.

.PHONY: all doc clean fmt

PROXY_ATTESTATION_SERVER_DB  = $(abspath proxy-attestation-server.db)
TEST_PARAMETERS = DATABASE_URL=$(PROXY_ATTESTATION_SERVER_DB) \
	VERACRUZ_POLICY_DIR=$(abspath ../linux-runtime/test-programs) \
	VERACRUZ_TRUST_DIR=$(abspath crates/test-collateral) \
	VERACRUZ_PROGRAM_DIR=$(abspath ../linux-runtime/test-programs) \
	VERACRUZ_DATA_DIR=$(abspath crates/sdk/datasets) \
	LINUX_ROOT_ENCLAVE_PATH=$(abspath ../linux-runtime/target/release/linux-root-enclave) \
	RUNTIME_MANAGER_ENCLAVE_PATH=$(abspath ../linux-runtime/target/release/runtime_manager_enclave)
CC = CC_x86_64_unknown_linux_gnu=gcc CC_aarch64_unknown_linux_gnu=gcc

all:
	$(CC) cargo build --release \
		--features proxy-attestation-server/linux \
		--features veracruz-client/linux \
		--features veracruz-server/linux \
		--features veracruz-server-test/linux \
		--features veracruz-test/linux \
		--features cli

datasets:
	$(MAKE) -C ../host datasets

policy-files:
	$(MAKE) -C ../linux-runtime policy-files

test-server: datasets policy-files $(PROXY_ATTESTATION_SERVER_DB)
	$(CC) cargo test -p veracruz-server-test --features linux --no-run -- --nocapture
	$(CC) $(TEST_PARAMETERS) cargo test -p veracruz-server-test --features linux -- --test-threads=1 --nocapture
	$(CC) $(TEST_PARAMETERS) cargo test -p veracruz-server-test test_debug --features linux  -- --ignored --test-threads=1

test-client:
	$(CC) $(TEST_PARAMETERS) cargo test -p veracruz-client --lib --features "mock linux" -- --test-threads=1

veracruz-test: datasets policy-files $(PROXY_ATTESTATION_SERVER_DB)
	$(CC) cargo test -p veracruz-test --features linux --no-run
	$(CC) $(TEST_PARAMETERS) cargo test -p veracruz-test --features linux -- --test-threads=1

$(PROXY_ATTESTATION_SERVER_DB):
	diesel setup --config-file crates/proxy-attestation-server/diesel.toml --database-url $@ \
		--migration-dir crates/proxy-attestation-server/migrations
	echo "INSERT INTO firmware_versions VALUES(1, 'sgx', '0.3.0', '${sgx_hash:-}');" > tmp.sql
	echo "INSERT INTO firmware_versions VALUES(2, 'psa', '0.3.0', 'deadbeefdeadbeefdeadbeefdeadbeeff00dcafef00dcafef00dcafef00dcafe');" >> tmp.sql
	sqlite3 $@ < tmp.sql
	rm tmp.sql

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean
