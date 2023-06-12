manifest_path = $(abspath $(PROJECT)/Cargo.toml)

cdl_script_path = $(abspath $(PROJECT)/cdl/composition.py)

icedl_components := \
	icecap-runtime-manager \
	virtio-console-server

project_feature_flags := --features icecap-$(icecap_plat)
