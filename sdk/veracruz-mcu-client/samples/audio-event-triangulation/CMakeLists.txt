# Veracruz MCU Client example CMakeList.txt
#
# These values can be overridden by applications that include this module
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSE.md` file in the Veracruz root directory for
# licensing and copyright information.

# Zephyr project
cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(vc_audio_event_triangulation)

# Generate transport_protocol.pb.h/c
add_custom_target(
    claps_to_header
    COMMAND ${PYTHON_EXECUTABLE}
        claps_to_header.py
            ${CONFIG_VC_AUDIO_EVENT_TRIANGULATION_CLAPS_PATH}
            --bitrate ${CONFIG_VC_AUDIO_EVENT_TRIANGULATION_CLAP_BITRATE}
            -B ${CONFIG_VC_AUDIO_EVENT_TRIANGULATION_CLAP_SAMPLES_BEFORE}
            -A ${CONFIG_VC_AUDIO_EVENT_TRIANGULATION_CLAP_SAMPLES_AFTER}
            --clap ${CONFIG_VC_AUDIO_EVENT_TRIANGULATION_CLAP_NUMBER}
            --delay ${CONFIG_VC_AUDIO_EVENT_TRIANGULATION_DELAY}
            --header clap.h
            --source clap.c
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    BYPRODUCTS
        ${CMAKE_CURRENT_SOURCE_DIR}/clap.h
        ${CMAKE_CURRENT_SOURCE_DIR}/clap.c
    COMMENT "Generating clap.h/c"
)
add_dependencies(app claps_to_header)

file(GLOB SRC "*.c")
target_sources(app PRIVATE ${SRC})
target_sources(app PRIVATE clap.c)
target_compile_options(app PRIVATE "-Wno-unused-variable")

