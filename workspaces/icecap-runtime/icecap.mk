manifest_path = $(abspath $(PROJECT)/Cargo.toml)

cdl_script_path = $(abspath $(PROJECT)/cdl/composition.py)

icedl_components := \
	runtime_manager_enclave virtio-console-server
