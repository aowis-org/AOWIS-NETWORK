cmake_minimum_required(VERSION 3.23)
project(AOWISNetwork VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
option(AOWIS_NETWORK_WITH_WIREGUARD "Build embedded wireguard-go + gVisor netstack" ON)

add_library(aowis-network STATIC src/wireguard_client.cpp src/wireguard_conf.cpp)
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

# Qt remains an optional companion API. AUTO enables it when Qt6 Network
# development files are available, without changing the headless core build.
set(AOWIS_NETWORK_WITH_QT "AUTO" CACHE STRING "Qt HTTP adapter: AUTO, ON or OFF")
set_property(CACHE AOWIS_NETWORK_WITH_QT PROPERTY STRINGS AUTO ON OFF)
if(NOT AOWIS_NETWORK_WITH_QT MATCHES "^(AUTO|ON|OFF)$")
    message(FATAL_ERROR "AOWIS_NETWORK_WITH_QT must be AUTO, ON or OFF")
endif()
if(NOT AOWIS_NETWORK_WITH_QT STREQUAL "OFF")
    if(AOWIS_NETWORK_WITH_QT STREQUAL "ON")
        find_package(Qt6 REQUIRED COMPONENTS Core Network)
    else()
        find_package(Qt6 QUIET COMPONENTS Core Network)
    endif()
    if(Qt6_FOUND)
        add_library(aowis-network-qt STATIC src/qt_http_client.cpp)
        add_library(AOWIS::NetworkQt ALIAS aowis-network-qt)
        target_compile_features(aowis-network-qt PUBLIC cxx_std_17)
        target_include_directories(aowis-network-qt PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>)
        target_link_libraries(aowis-network-qt PUBLIC AOWIS::Network Qt6::Network)
        message(STATUS "AOWIS-Network Qt HTTP adapter enabled")
    else()
        message(STATUS "Qt6 Network unavailable: optional AOWIS-Network Qt adapter disabled")
    endif()
endif()

if(BUILD_TESTING)
    if(TARGET aowis-network-qt)
        add_executable(aowis-network-qt-tests tests/qt_http_client_test.cpp)
        target_link_libraries(aowis-network-qt-tests PRIVATE AOWIS::NetworkQt)
        add_test(NAME aowis-network-qt-http COMMAND aowis-network-qt-tests)
        set_tests_properties(aowis-network-qt-http PROPERTIES TIMEOUT 30)
    endif()
    # Full encrypted path: Qt HTTP -> C++ tunnel -> Go C ABI -> real UDP
    # WireGuard -> remote userspace netstack HTTP. The Go peer is a CTest-only
    # executable, never linked into or installed with the production library.
    if(AOWIS_NETWORK_WITH_WIREGUARD AND TARGET aowis-network-qt)
        set(AOWIS_TEST_PEER_BIN "${CMAKE_CURRENT_BINARY_DIR}/go/aowis-network-test-peer")
        add_custom_command(
            OUTPUT "${AOWIS_TEST_PEER_BIN}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/go"
            COMMAND "${CMAKE_COMMAND}" -E env CGO_ENABLED=1 GOWORK=off
                "${AOWIS_GO_EXECUTABLE}" build -mod=readonly
                -o "${AOWIS_TEST_PEER_BIN}" ./testpeer
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bridge"
            DEPENDS
                "${CMAKE_CURRENT_SOURCE_DIR}/bridge/testpeer/main.go"
                "${CMAKE_CURRENT_SOURCE_DIR}/bridge/internal/testdns/testdns.go"
                "${CMAKE_CURRENT_SOURCE_DIR}/bridge/go.mod"
                "${CMAKE_CURRENT_SOURCE_DIR}/bridge/go.sum"
            COMMENT "Building isolated userspace WireGuard Qt test peer"
            VERBATIM)
        add_custom_target(aowis-network-test-peer DEPENDS "${AOWIS_TEST_PEER_BIN}")
        add_executable(aowis-network-qt-wireguard-tests tests/qt_wireguard_e2e_test.cpp)
        target_link_libraries(aowis-network-qt-wireguard-tests PRIVATE AOWIS::NetworkQt)
        add_dependencies(aowis-network-qt-wireguard-tests aowis-network-test-peer)
        add_test(NAME aowis-network-qt-wireguard-e2e
            COMMAND aowis-network-qt-wireguard-tests "${AOWIS_TEST_PEER_BIN}")
        set_tests_properties(aowis-network-qt-wireguard-e2e PROPERTIES TIMEOUT 45)
    endif()
    add_executable(aowis-network-tests tests/wireguard_client_test.cpp)
    target_link_libraries(aowis-network-tests PRIVATE AOWIS::Network)
    add_test(NAME aowis-network-client COMMAND aowis-network-tests)
    add_executable(aowis-network-conf-tests tests/wireguard_conf_test.cpp)
    target_link_libraries(aowis-network-conf-tests PRIVATE AOWIS::Network)
    add_test(NAME aowis-network-wireguard-conf COMMAND aowis-network-conf-tests)
    if(AOWIS_NETWORK_WITH_WIREGUARD)
        add_test(NAME aowis-network-go-tests
            COMMAND "${AOWIS_GO_EXECUTABLE}" test -mod=readonly -count=1 -run "^(TestSOCKS5|TestTelemetry|TestReresolve|TestValidateConfig|TestDNS)" ./...)
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
