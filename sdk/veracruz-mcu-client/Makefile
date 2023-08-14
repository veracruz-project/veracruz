# Veracruz MCU Client Makefile
#
# These values can be overridden by applications that include this module
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.


# Project name/paths, used for docker image
TARGET ?= veracruz-mcu-client
DOCKER_IMAGE ?= $(TARGET)
DOCKER_CONTAINER ?= $(TARGET)
DOCKER_ROOT ?= $(abspath $(firstword $(MAKEFILE_LIST))/..)

ELF_PATH ?= /zephyr-workspace/$(TARGET)/build/zephyr/zephyr.elf
EXE_PATH ?= /zephyr-workspace/$(TARGET)/build/zephyr/zephyr.exe

# configuration for veracruz-mcu-client
VC_POLICY_PATH ?= policy.json
VC_IDENTITY_PATH ?= client_cert.pem
VC_KEY_PATH ?= client_key.pem

# configuration for samples
AUDIO_EVENT_TRIANGULATION_CLAP_NUMBER ?= 0
AUDIO_EVENT_TRIANGULATION_DELAY ?= 0

SHAMIR_SECRET_SHARING_BINARY_PATH ?= binary.wasm


# launch docker
.PHONY: docker
docker: Dockerfile
	# copy over transport_protocol.proto, since we need this in the workspace,
	# note that we can't use a Docker COPY since this file is technically
	# outside of the build context
	$(strip cp -f \
		../transport-protocol/protos/transport_protocol.proto \
		transport_protocol.proto)

	# build and run the docker image
	$(strip docker build \
		--build-arg TARGET=$(TARGET) \
		--build-arg USER=$(USER) \
		--build-arg UID=$(UID) \
		-t $(DOCKER_IMAGE) -f $< .)
	$(strip docker run -it --rm \
		-v $(DOCKER_ROOT):/zephyr-workspace/$(TARGET) \
		--cap-add=NET_ADMIN --device /dev/net/tun:/dev/net/tun \
		--name $(DOCKER_CONTAINER) \
		$(DOCKER_IMAGE) bash -c "./tap-setup.sh ; bash")

# clean
.PHONY: clean
clean:
	rm -rf samples/audio-event-triangulation/clap.h samples/audio-event-triangulation/clap.c
	rm -rf samples/shamir-secret-sharing/binary.h samples/shamir-secret-sharing/binary.c
	rm -rf transport_protocol.pb.h transport_protocol.pb.c
	rm -rf policy.h policy.c
	rm -rf build

.PHONY: quick-clean
quick-clean:
	rm -rf samples/audio-event-triangulation/clap.h samples/audio-event-triangulation/clap.c
	rm -rf samples/shamir-secret-sharing/binary.h samples/shamir-secret-sharing/binary.c
	rm -rf transport_protocol.pb.h transport_protocol.pb.c
	rm -rf policy.h policy.c
	rm -rf build

# rules for the audio-event-triangulation demo
.PHONY: build-demo
build-demo:
	$(strip west build -b native_posix \
			samples/audio-event-triangulation \
			-DZEPHYR_EXTRA_MODULES=/zephyr-workspace/$(TARGET) \
			-DCONFIG_VC_POLICY_PATH=\"$(abspath $(VC_POLICY_PATH))\" \
			-DCONFIG_VC_IDENTITY_PATH=\"$(abspath $(VC_IDENTITY_PATH))\" \
			-DCONFIG_VC_KEY_PATH=\"$(abspath $(VC_KEY_PATH))\" \
			-DCONFIG_VC_AUDIO_EVENT_TRIANGULATION_CLAPS_PATH=\"/zephyr-workspace/$(TARGET)/samples/audio-event-triangulation/claps.wav\" \
			-DCONFIG_VC_AUDIO_EVENT_TRIANGULATION_CLAP_NUMBER="$(AUDIO_EVENT_TRIANGULATION_CLAP_NUMBER)" \
			-DCONFIG_VC_AUDIO_EVENT_TRIANGULATION_DELAY="$(AUDIO_EVENT_TRIANGULATION_DELAY)" )

.PHONY: build-demo-no-log
build-demo-no-log:
	$(strip west build -b native_posix \
			samples/audio-event-triangulation \
			-DZEPHYR_EXTRA_MODULES=/zephyr-workspace/$(TARGET) \
			-DCONFIG_VC_POLICY_PATH=\"$(abspath $(VC_POLICY_PATH))\" \
			-DCONFIG_VC_IDENTITY_PATH=\"$(abspath $(VC_IDENTITY_PATH))\" \
			-DCONFIG_VC_KEY_PATH=\"$(abspath $(VC_KEY_PATH))\" \
			-DCONFIG_VC_AUDIO_EVENT_TRIANGULATION_CLAPS_PATH=\"/zephyr-workspace/$(TARGET)/samples/audio-event-triangulation/claps.wav\" \
			-DCONFIG_VC_AUDIO_EVENT_TRIANGULATION_CLAP_NUMBER="$(AUDIO_EVENT_TRIANGULATION_CLAP_NUMBER)" \
			-DCONFIG_VC_AUDIO_EVENT_TRIANGULATION_DELAY="$(AUDIO_EVENT_TRIANGULATION_DELAY)" \
			-DCONFIG_VC_LOG=n )

.PHONY: run
run:
	$(abspath $(EXE_PATH))

# rules for testing via Shamir's secret sharing sample 
.PHONY: build-test
build-test:
	$(strip west build -b native_posix \
			samples/shamir-secret-sharing \
			-DZEPHYR_EXTRA_MODULES=/zephyr-workspace/$(TARGET) \
			-DCONFIG_VC_POLICY_PATH=\"$(abspath $(VC_POLICY_PATH))\" \
			-DCONFIG_VC_IDENTITY_PATH=\"$(abspath $(VC_IDENTITY_PATH))\" \
			-DCONFIG_VC_KEY_PATH=\"$(abspath $(VC_KEY_PATH))\" \
			-DCONFIG_VC_SHAMIR_SECRET_SHARING_BINARY_PATH=\"$(abspath $(SHAMIR_SECRET_SHARING_BINARY_PATH))\" )

# additional rules for finding memory usage reports
build-qemu-cortex-m3:
	$(strip west build -b qemu_cortex_m3 \
		samples/audio-event-triangulation \
		-DZEPHYR_EXTRA_MODULES=/zephyr-workspace/$(TARGET) \
		-DCONFIG_VC_POLICY_PATH=\"$(abspath $(VC_POLICY_PATH))\" \
		-DCONFIG_VC_IDENTITY_PATH=\"$(abspath $(VC_IDENTITY_PATH))\" \
		-DCONFIG_VC_KEY_PATH=\"$(abspath $(VC_KEY_PATH))\" \
		-DCONFIG_VC_AUDIO_EVENT_TRIANGULATION_CLAPS_PATH=\"/zephyr-workspace/$(TARGET)/samples/audio-event-triangulation/claps.wav\" \
		-DCONFIG_VC_AUDIO_EVENT_TRIANGULATION_CLAP_NUMBER="$(AUDIO_EVENT_TRIANGULATION_CLAP_NUMBER)" \
		-DCONFIG_VC_AUDIO_EVENT_TRIANGULATION_DELAY="$(AUDIO_EVENT_TRIANGULATION_DELAY)" \
		-DCONFIG_TEST_RANDOM_GENERATOR=y \
		-DCONFIG_VC_LOG=n)


rom-report: build-qemu-cortex-m3
	west build -b qemu_cortex_m3 -t rom_report > rom_report.txt
	sed -i '/^Path/,$$!d' rom_report.txt

static-ram-report: build-qemu-cortex-m3
	west build -b qemu_cortex_m3 -t ram_report > static_ram_report.txt
	sed -i '/^Path/,$$!d' static_ram_report.txt

run-with-dyn-ram-report: build-demo-no-log
	valgrind --tool=massif --stacks=yes --massif-out-file=massif.out $(EXE_PATH)
	ms_print massif.out > dyn_ram_report.txt

run-with-memory-report: \
		run-with-dyn-ram-report \
		rom-report \
		static-ram-report
	@echo
	@./find_memory_breakdown.py rom_report.txt static_ram_report.txt dyn_ram_report.txt
	@echo
	@echo "full reports written to: rom_report.txt static_ram_report.txt dyn_ram_report.txt"
	@echo
	


	

