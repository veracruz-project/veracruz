OUT_DIR ?= $(abspath test-collateral)
FINAL_DIR ?= $(abspath .)
WORKSPACE_DIR = $(abspath ..)

include $(WORKSPACE_DIR)/common.mk
include $(WORKSPACE_DIR)/shared.mk

MEASUREMENT_FILE = $(abspath css-icecap.bin)
MEASUREMENT_PARAMETER = --css-file $(MEASUREMENT_FILE)

.PHONY: clean test-collateral datasets

test-collateral: proxy-attestation-server.db css-icecap.bin \
	wasm-files policy-files datasets

datasets: $(OUT_DIR)
	$(MAKE) -C ../host datasets
	cp -r ../../sdk/datasets/* $(OUT_DIR)
	cp ../../test-collateral/*.pem $(OUT_DIR)

css-icecap.bin:
	touch $@

proxy-attestation-server.db:
	diesel setup --config-file crates/proxy-attestation-server/diesel.toml --database-url $@ \
		--migration-dir crates/proxy-attestation-server/migrations
	echo "INSERT INTO firmware_versions VALUES(2, 'psa', '0.3.0', 'deadbeefdeadbeefdeadbeefdeadbeeff00dcafef00dcafef00dcafef00dcafe');" > tmp.sql
	sqlite3 $@ < tmp.sql
	rm tmp.sql

clean:
	rm -rf $(OUT_DIR)
	rm -f proxy-attestation-server.db
	rm -f css-icecap.bin
