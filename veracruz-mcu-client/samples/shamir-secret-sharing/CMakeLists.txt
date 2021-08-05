# Veracruz MCU Client example CMakeList.txt
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.

# Zephyr project
cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(vc_shamir_secret_sharing)

# Generate binary header
add_custom_target(
    app_veracruz_binary
    COMMAND ${PYTHON_EXECUTABLE}
        binary_to_header.py
            ${CONFIG_VC_SHAMIR_SECRET_SHARING_BINARY_PATH}
            --name BINARY
            --header binary.h
            --source binary.c
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    BYPRODUCTS
        ${CMAKE_CURRENT_SOURCE_DIR}/binary.h
        ${CMAKE_CURRENT_SOURCE_DIR}/binary.c
    COMMENT "Generating binary.h/c"
)
add_dependencies(app app_veracruz_binary)

file(GLOB SRC "*.c")
target_sources(app PRIVATE ${SRC})
target_sources(app PRIVATE binary.c)

