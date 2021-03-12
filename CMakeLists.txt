
# Zephyr project
cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(mini_durango)

file(GLOB SRC "*.c" "nanopb/*.c")
target_sources(app PRIVATE ${SRC})
target_include_directories(app PRIVATE nanopb)

include(${ZEPHYR_BASE}/samples/net/common/common.cmake)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)
generate_inc_file_for_target(
    app
    globalsign_r2.der
    ${gen_dir}/globalsign_r2.der.inc
    )

