manifest_path = $(abspath $(PROJECT)/Cargo.toml)

cdl_script_path = $(abspath $(PROJECT)/cdl/composition.py)

icedl_components := \
	runtime-manager-enclave \
	virtio-console-server

project_feature_flags := --features icecap --features icecap-$(icecap_plat)
