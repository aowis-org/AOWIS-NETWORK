cmake_minimum_required(VERSION 3.23)
project(AOWISNetwork VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
option(AOWIS_NETWORK_WITH_WIREGUARD "Build embedded wireguard-go + gVisor netstack" ON)

add_library(aowis-network STATIC src/wireguard_client.cpp)
add_library(AOWIS::Network ALIAS aowis-network)
target_compile_features(aowis-network PUBLIC cxx_std_17)
target_include_directories(aowis-network PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)

if(AOWIS_NETWORK_WITH_WIREGUARD)
    find_program(AOWIS_GO_EXECUTABLE NAMES go REQUIRED)
    find_package(Threads REQUIRED)
    set(AOWIS_GO_ARCHIVE "${CMAKE_CURRENT_BINARY_DIR}/go/libaowis_wireguard.a")
    set(AOWIS_GO_HEADER "${CMAKE_CURRENT_BINARY_DIR}/go/libaowis_wireguard.h")
    add_custom_command(
        OUTPUT "${AOWIS_GO_ARCHIVE}" "${AOWIS_GO_HEADER}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/go"
        COMMAND "${CMAKE_COMMAND}" -E env CGO_ENABLED=1 GOWORK=off
            "${AOWIS_GO_EXECUTABLE}" build -mod=readonly -buildmode=c-archive
            -o "${AOWIS_GO_ARCHIVE}" .
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bridge"
        DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/bridge/main.go"
            "${CMAKE_CURRENT_SOURCE_DIR}/bridge/socks5.go"
            "${CMAKE_CURRENT_SOURCE_DIR}/bridge/go.mod"
            "${CMAKE_CURRENT_SOURCE_DIR}/bridge/go.sum"
        COMMENT "Building embedded userspace WireGuard engine"
        VERBATIM)
    add_custom_target(aowis-wireguard-bridge DEPENDS "${AOWIS_GO_ARCHIVE}" "${AOWIS_GO_HEADER}")
    add_library(aowis-wireguard-go STATIC IMPORTED GLOBAL)
    set_target_properties(aowis-wireguard-go PROPERTIES IMPORTED_LOCATION "${AOWIS_GO_ARCHIVE}")
    add_dependencies(aowis-wireguard-go aowis-wireguard-bridge)
    target_compile_definitions(aowis-network PRIVATE AOWIS_NETWORK_WITH_WIREGUARD=1)
    target_link_libraries(aowis-network PRIVATE aowis-wireguard-go Threads::Threads ${CMAKE_DL_LIBS})
endif()

if(BUILD_TESTING)
    add_executable(aowis-network-tests tests/wireguard_client_test.cpp)
    target_link_libraries(aowis-network-tests PRIVATE AOWIS::Network)
    add_test(NAME aowis-network-client COMMAND aowis-network-tests)
    if(AOWIS_NETWORK_WITH_WIREGUARD)
        add_test(NAME aowis-network-go-tests
            COMMAND "${AOWIS_GO_EXECUTABLE}" test -mod=readonly -count=1 -run "^TestSOCKS5" ./...)
        set_tests_properties(aowis-network-go-tests PROPERTIES
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bridge")
        add_test(NAME aowis-network-wireguard-e2e
            COMMAND "${AOWIS_GO_EXECUTABLE}" test -mod=readonly -count=1
                -timeout=60s -run "^TestWireGuardE2E" ./...)
        set_tests_properties(aowis-network-wireguard-e2e PROPERTIES
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bridge"
            TIMEOUT 90)
    endif()
endif()
