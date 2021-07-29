if(CONFIG_VC)

zephyr_interface_library_named(VC)

# Run policy_to_header.py before compilation
#
# Great writeup here on how this works:
# https://stackoverflow.com/a/49021383
add_custom_target(
    policy_to_header ALL
    COMMAND ${PYTHON_EXECUTABLE}
        policy_to_header.py
            ${CONFIG_VC_POLICY_PATH}
            --identity ${CONFIG_VC_IDENTITY_PATH}
            --key ${CONFIG_VC_KEY_PATH}
            --header policy.h
            --source policy.c
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    BYPRODUCTS
        ${CMAKE_CURRENT_SOURCE_DIR}/policy.h
        ${CMAKE_CURRENT_SOURCE_DIR}/policy.c
    COMMENT "Generating policy.h/c"
)
add_dependencies(VC policy_to_header)

# Generate transport_protocol.pb.h/c
add_custom_target(
    transport_protocol_pb
    COMMAND ${PYTHON_EXECUTABLE}
        nanopb/generator/nanopb_generator.py
            transport_protocol.proto
            --options-file=transport_protocol.options
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    BYPRODUCTS
        ${CMAKE_CURRENT_SOURCE_DIR}/transport_protocol.pb.h
        ${CMAKE_CURRENT_SOURCE_DIR}/transport_protocol.pb.c
    COMMENT "Generating transport_protocol.pb.h/c"
)
add_dependencies(VC transport_protocol_pb)
    
# Describe the Zephyr library
zephyr_include_directories(.)
zephyr_include_directories(nanopb)

zephyr_library()
file(GLOB SRC "*.c" "nanopb/*.c")
zephyr_library_sources(${SRC})
zephyr_library_sources(policy.c)
zephyr_library_sources(transport_protocol.pb.c)

zephyr_library_link_libraries(VC)
target_link_libraries(VC INTERFACE zephyr_interface)

endif()
