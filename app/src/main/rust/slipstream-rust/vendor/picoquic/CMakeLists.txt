cmake_minimum_required(VERSION 3.13)

# Building tests by default depends on whether this is a subproject
if(DEFINED PROJECT_NAME)
    option(picoquic_BUILD_TESTS "Build Tests for picoquic" OFF)
else()
    option(picoquic_BUILD_TESTS "Build Tests for picoquic" ON)
endif()

project(picoquic
        VERSION 1.1.28.4
        DESCRIPTION "picoquic library"
        LANGUAGES C CXX)

find_package(Threads REQUIRED)

option(DISABLE_DEBUG_PRINTF "Disable Picoquic debug output" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer (ASAN) for debugging" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer (UBSan) for debugging" OFF)
option(BUILD_DEMO "Build picoquicdemo" ON)
option(BUILD_HTTP "Build picohttp" ON)
option(BUILD_LOGLIB "Build picoquic-log" ON)
option(BUILD_LOGREADER "Build picolog_t the log reader" ON)

message(STATUS "Initial CMAKE_C_FLAGS=${CMAKE_C_FLAGS}")

if(DISABLE_DEBUG_PRINTF)
    list(APPEND PICOQUIC_COMPILE_DEFINITIONS DISABLE_DEBUG_PRINTF)
endif()

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CMakePushCheckState)

if(ENABLE_ASAN)
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=address")
    check_c_compiler_flag(-fsanitize=address C__fsanitize_address_VALID)
    check_cxx_compiler_flag(-fsanitize=address CXX__fsanitize_address_VALID)
    cmake_pop_check_state()
    if(NOT C__fsanitize_address_VALID OR NOT CXX__fsanitize_address_VALID)
        message(FATAL_ERROR "ENABLE_ASAN was requested, but not supported!")
    endif()
    list(APPEND PICOQUIC_ADDITIONAL_C_FLAGS -fsanitize=address)
    list(APPEND PICOQUIC_ADDITIONAL_CXX_FLAGS -fsanitize=address)
    list(APPEND PICOQUIC_LINKER_FLAGS -fsanitize=address)
endif()

if(ENABLE_UBSAN)
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=undefined")
    check_c_compiler_flag(-fsanitize=undefined C__fsanitize_undefined_VALID)
    check_cxx_compiler_flag(-fsanitize=undefined CXX__fsanitize_undefined_VALID)
    cmake_pop_check_state()
    if(NOT C__fsanitize_undefined_VALID OR NOT CXX__fsanitize_undefined_VALID)
        message(FATAL_ERROR "ENABLE_UBSAN was requested, but not supported!")
    endif()
    list(PREPEND PICOQUIC_ADDITIONAL_C_FLAGS -fsanitize=undefined)
    list(PREPEND PICOQUIC_ADDITIONAL_CXX_FLAGS -fsanitize=undefined)
    list(PREPEND PICOQUIC_LINKER_FLAGS -fsanitize=undefined)

    # Ease detecting of "Runtime errors". If such an error is found, print a verbose
    # error report and exit the program
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES "-fno-sanitize-recover")
    check_c_compiler_flag(-fno-sanitize-recover C__fnosanitize_recover_VALID)
    check_cxx_compiler_flag(-fno-sanitize-recover CXX__fnosanitize_recover_VALID)
    cmake_pop_check_state()
    if(NOT C__fnosanitize_recover_VALID OR NOT CXX__fnosanitize_recover_VALID)
        message(FATAL_ERROR "ENABLE_UBSAN was requested, but fno-sanitize-recover is not supported!")
    endif()
    list(APPEND PICOQUIC_ADDITIONAL_C_FLAGS -fno-sanitize-recover)
    list(APPEND PICOQUIC_ADDITIONAL_CXX_FLAGS -fno-sanitize-recover)
    list(APPEND PICOQUIC_LINKER_FLAGS -fno-sanitize-recover)
endif()

set(PICOQUIC_LIBRARY_FILES
    picoquic/bbr.c
    picoquic/bbr1.c
    picoquic/bytestream.c
    picoquic/cc_common.c
    picoquic/config.c
    picoquic/cubic.c
    picoquic/fastcc.c
    picoquic/frames.c
    picoquic/intformat.c
    picoquic/logger.c
    picoquic/logwriter.c
    picoquic/loss_recovery.c
    picoquic/newreno.c
    picoquic/pacing.c
    picoquic/packet.c
    picoquic/performance_log.c
    picoquic/picohash.c
    picoquic/picoquic_lb.c
    picoquic/picoquic_ptls_fusion.c
    picoquic/picoquic_ptls_minicrypto.c
    picoquic/picoquic_ptls_openssl.c
    picoquic/picoquic_mbedtls.c
    picoquic/picosocks.c
    picoquic/picosplay.c
    picoquic/port_blocking.c
    picoquic/prague.c
    picoquic/quicctx.c
    picoquic/sacks.c
    picoquic/sender.c
    picoquic/sim_link.c
    picoquic/sockloop.c
    picoquic/spinbit.c
    picoquic/ticket_store.c
    picoquic/timing.c
    picoquic/token_store.c
    picoquic/tls_api.c
    picoquic/transport.c
    picoquic/unified_log.c
    picoquic/util.c)

set(PICOQUIC_CORE_HEADERS
     picoquic/picoquic.h
     picoquic/picosocks.h
     picoquic/picoquic_utils.h
     picoquic/picoquic_packet_loop.h
     picoquic/picoquic_unified_log.h
     picoquic/picoquic_logger.h
     picoquic/picoquic_binlog.h
     picoquic/picoquic_config.h
     picoquic/picoquic_lb.h)

set(LOGLIB_LIBRARY_FILES
    loglib/autoqlog.c
    loglib/cidset.c
    loglib/csv.c
    loglib/logconvert.c
    loglib/logreader.c
    loglib/memory_log.c
    loglib/qlog.c
    loglib/svg.c)

set(PICOQUIC_LOGLIB_HEADERS
    loglib/autoqlog.h
    loglib/auto_memlog.h)

set(PICOQUIC_TEST_LIBRARY_FILES
    picoquictest/ack_of_ack_test.c
    picoquictest/ack_frequency_test.c
    picoquictest/app_limited.c
    picoquictest/bytestream_test.c
    picoquictest/cert_verify_test.c
    picoquictest/cleartext_aead_test.c
    picoquictest/code_version_test.c
    picoquictest/config_test.c
    picoquictest/congestion_test.c
    picoquictest/cnx_creation_test.c
    picoquictest/cnxstress.c
    picoquictest/cplusplus.cpp
    picoquictest/cpu_limited.c
    picoquictest/datagram_tests.c
    picoquictest/delay_tolerant_test.c
    picoquictest/edge_cases.c
    picoquictest/getter_test.c
    picoquictest/hashtest.c
    picoquictest/high_latency_test.c
    picoquictest/intformattest.c
    picoquictest/l4s_test.c
    picoquictest/mbedtls_test.c
    picoquictest/mediatest.c
    picoquictest/minicrypto_test.c
    picoquictest/multipath_test.c
    picoquictest/netperf_test.c
    picoquictest/openssl_test.c
    picoquictest/p2p_test.c
    picoquictest/pacing_test.c
    picoquictest/parseheadertest.c
    picoquictest/picoquic_lb_test.c
    picoquictest/pn2pn64test.c
    picoquictest/quic_tester.c
    picoquictest/sacktest.c
    picoquictest/satellite_test.c
    picoquictest/skip_frame_test.c
    picoquictest/socket_test.c
    picoquictest/sockloop_test.c
    picoquictest/spinbit_test.c
    picoquictest/splay_test.c
    picoquictest/stream0_frame_test.c
    picoquictest/stresstest.c
    picoquictest/ticket_store_test.c
    picoquictest/tls_api_test.c
    picoquictest/transport_param_test.c
    picoquictest/util_test.c
    picoquictest/warptest.c
    picoquictest/wifitest.c )

set(PICOHTTP_LIBRARY_FILES
    picohttp/democlient.c
    picohttp/demoserver.c
    picohttp/h3zero.c
    picohttp/h3zero_client.c
    picohttp/h3zero_common.c
    picohttp/h3zero_server.c
    picohttp/h3zero_uri.c
    picohttp/quicperf.c
    picohttp/webtransport.c
    picohttp/wt_baton.c)

set(PICOHTTP_HEADERS
     picohttp/h3zero.h
     picohttp/h3zero_common.h
     picohttp/h3zero_uri.h
     picohttp/democlient.h
     picohttp/demoserver.h
     picohttp/pico_webtransport.h
     picohttp/wt_baton.h)

set(PICOHTTP_TEST_LIBRARY_FILES
    picoquictest/h3zerotest.c
    picoquictest/h3zero_stream_test.c
    picoquictest/h3zero_uri_test.c
    picoquictest/quicperf_test.c
    picoquictest/webtransport_test.c)

OPTION(PICOQUIC_FETCH_PTLS "Fetch PicoTLS during configuration" OFF)
if(PICOQUIC_FETCH_PTLS)
    include(FetchContent)
    FetchContent_Declare(picotls
        GIT_REPOSITORY      https://github.com/h2o/picotls.git
        GIT_TAG             5a4461d8a3948d9d26bf861e7d90cb80d8093515)
    FetchContent_MakeAvailable(picotls)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(PTLS REQUIRED)
message(STATUS "picotls/include: ${PTLS_INCLUDE_DIRS}" )
message(STATUS "picotls libraries: ${PTLS_LIBRARIES}" )

OPTION(PTLS_WITH_FUSION "build 'fusion' AES-GCM engine" ${PTLS_WITH_FUSION_DEFAULT})
if(PTLS_WITH_FUSION)
    message(STATUS "PTLS Fusion is enabled")
else()
    message(STATUS "PTLS compiled without support for Fusion")
    list(APPEND PICOQUIC_COMPILE_DEFINITIONS PTLS_WITHOUT_FUSION)
endif()

OPTION(WITH_OPENSSL "build with OpenSSL" ON)

if(WITH_OPENSSL)
    find_package(OpenSSL REQUIRED)
    message(STATUS "root: ${OPENSSL_ROOT_DIR}")
    message(STATUS "OpenSSL_VERSION: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")
    message(STATUS "CMAKE_C_FLAGS: ${CMAKE_C_FLAGS}")
    message(STATUS "CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")
else()
    message(STATUS "Building without picotls-openssl")
    list(APPEND PICOQUIC_COMPILE_DEFINITIONS PTLS_WITHOUT_OPENSSL)
endif()

OPTION(WITH_MBEDTLS "enable MBEDTLS" OFF)

IF (WITH_MBEDTLS)
    FIND_PACKAGE(MbedTLS)
    IF (MbedTLS_FOUND)
        message(STATUS "Enabling MbedTLS support")
        message(STATUS "mbedtls/include: ${MBEDTLS_INCLUDE_DIRS}")
        message(STATUS "mbedtls libraries: ${MBEDTLS_LIBRARIES}")
        list(APPEND PICOQUIC_COMPILE_DEFINITIONS PICOQUIC_WITH_MBEDTLS)
        list(APPEND PICOQUIC_LIBRARY_FILES 
                    picoquic_mbedtls/ptls_mbedtls.c
                    picoquic_mbedtls/ptls_mbedtls_sign.c)
    ELSE ()
        message(STATUS "mbedtls/include: ${MBEDTLS_INCLUDE_DIRS}")
        message(STATUS "mbedtls libraries: ${MBEDTLS_LIBRARIES}")
        MESSAGE (FATAL_ERROR "MbedTLS not found")
    ENDIF()
ENDIF ()

# set_picoquic_compile_settings(TARGET) makes is easy to consistently
# assign compiler build options to each of the following targets
macro(set_picoquic_compile_settings)
    message(STATUS "PICOQUIC_ADDITIONAL_C_FLAGS in picoquic: ${PICOQUIC_ADDITIONAL_C_FLAGS}")
    set_target_properties(${ARGV0}
        PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED YES
            C_EXTENSIONS YES)
    set_target_properties(${ARGV0}
        PROPERTIES
            CXX_STANDARD 11
            CXX_STANDARD_REQUIRED YES
            CXX_EXTENSIONS YES)
    target_compile_options(${ARGV0}
        PRIVATE
            $<$<C_COMPILER_ID:Clang>: -Wall
                -fno-signed-zeros -fno-trapping-math
                ${PICOQUIC_ADDITIONAL_C_FLAGS}>
            $<$<C_COMPILER_ID:AppleClang>: -Wall
                -fno-signed-zeros -fno-trapping-math
                ${PICOQUIC_ADDITIONAL_C_FLAGS}>
            $<$<C_COMPILER_ID:GNU>: -Wall
                -fno-signed-zeros -frename-registers -fno-trapping-math
                ${PICOQUIC_ADDITIONAL_C_FLAGS}>
            $<$<C_COMPILER_ID:MSVC>: >
            $<$<CXX_COMPILER_ID:Clang>: -Wall
                -fno-signed-zeros -fno-trapping-math
                ${PICOQUIC_ADDITIONAL_CXX_FLAGS}>
            $<$<CXX_COMPILER_ID:AppleClang>: -Wall
                -fno-signed-zeros -fno-trapping-math
                ${PICOQUIC_ADDITIONAL_CXX_FLAGS}>
            $<$<CXX_COMPILER_ID:GNU>: -Wall
                -fno-signed-zeros -frename-registers -fno-trapping-math
                ${PICOQUIC_ADDITIONAL_CXX_FLAGS}>
            $<$<CXX_COMPILER_ID:MSVC>: >)
    target_compile_definitions(${ARGV0} PRIVATE ${PICOQUIC_COMPILE_DEFINITIONS})
    target_link_options(${ARGV0} PRIVATE ${PICOQUIC_LINKER_FLAGS})
endmacro()

add_library(picoquic-core ${PICOQUIC_CORE_HEADERS} ${PICOQUIC_LIBRARY_FILES})

message(STATUS "Defining picoquic-core")
message(STATUS "mbedtls/include: ${MBEDTLS_INCLUDE_DIRS}")

target_include_directories(picoquic-core
    PRIVATE
        ${PTLS_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
    PUBLIC
        ${MBEDTLS_INCLUDE_DIRS}
        picoquic
        picoquic_mbedtls)
target_link_libraries(picoquic-core
    PRIVATE
        ${OPENSSL_LIBRARIES}
        ${MBEDTLS_LIBRARIES}
    PUBLIC
        ${PTLS_LIBRARIES}
        Threads::Threads)
set_picoquic_compile_settings(picoquic-core)

if (BUILD_DEMO OR BUILD_LOGREADER OR (BUILD_TESTING AND picoquic_BUILD_TESTS))
    if (NOT BUILD_LOGLIB)
        set(BUILD_LOGLIB ON)
    endif()
endif()

if (BUILD_LOGLIB)
    add_library(picoquic-log ${LOGLIB_LIBRARY_FILES})
    target_include_directories(picoquic-log
        PRIVATE
            ${PTLS_INCLUDE_DIRS}
        PUBLIC
            picoquic
            loglib)
    set_picoquic_compile_settings(picoquic-log)
endif()

if (BUILD_DEMO)
    if (NOT BUILD_HTTP)
        set(BUILD_HTTP ON)
    endif()
endif()

if (BUILD_HTTP)
    add_library(picohttp-core ${PICOHTTP_LIBRARY_FILES})
    target_link_libraries(picohttp-core
        PRIVATE
            ${PTLS_LIBRARIES}
            ${OPENSSL_LIBRARIES}
            ${MBEDTLS_LIBRARIES}
        PUBLIC
            picoquic-core)
    target_include_directories(picohttp-core
        PRIVATE
            ${PTLS_INCLUDE_DIRS}
            ${OPENSSL_INCLUDE_DIR}
            ${MBEDTLS_INCLUDE_DIRS}
        PUBLIC
            picoquic)
    set_picoquic_compile_settings(picohttp-core)
endif()

if (BUILD_DEMO)
    add_executable(picoquicdemo
        picoquicfirst/picoquicdemo.c
        picoquicfirst/getopt.c)
    target_link_libraries(picoquicdemo
        PUBLIC
            ${PTLS_LIBRARIES}
            ${OPENSSL_LIBRARIES}
            ${MBEDTLS_LIBRARIES}
            picoquic-log
            picoquic-core
            picohttp-core)
    target_include_directories(picoquicdemo PRIVATE picohttp)
    set_picoquic_compile_settings(picoquicdemo)
endif()

if (BUILD_LOGREADER)
    add_executable(picolog_t picolog/picolog.c)
    target_link_libraries(picolog_t PRIVATE picoquic-log picoquic-core)
    target_include_directories(picolog_t PRIVATE loglib)
    set_picoquic_compile_settings(picolog_t)
endif()

include(CTest)

if(BUILD_TESTING AND picoquic_BUILD_TESTS)

    add_library(picoquic-test STATIC ${PICOQUIC_TEST_LIBRARY_FILES})
    target_link_libraries(picoquic-test PUBLIC picoquic-core picoquic-log)
    target_include_directories(picoquic-test
        PRIVATE
            ${MBEDTLS_INCLUDE_DIRS}
        PUBLIC
            ${PTLS_INCLUDE_DIRS}
            picoquic
            picoquictest)
    set_picoquic_compile_settings(picoquic-test)

    add_executable(picoquic_ct picoquic_t/picoquic_t.c)
    target_link_libraries(picoquic_ct PRIVATE picoquic-test ${MBEDTLS_LIBRARIES})
    set_picoquic_compile_settings(picoquic_ct)

    add_executable(picohttp_ct
        picohttp_t/picohttp_t.c
        ${PICOHTTP_TEST_LIBRARY_FILES})
    target_link_libraries(picohttp_ct PRIVATE picohttp-core picoquic-test)
    target_include_directories(picohttp_ct PRIVATE picohttp)
    set_picoquic_compile_settings(picohttp_ct)

    add_executable(pico_baton baton_app/baton_app.c)
    target_link_libraries(pico_baton PRIVATE picoquic-log picoquic-core picohttp-core)
    target_include_directories(pico_baton PRIVATE loglib picoquic picohttp)
    set_picoquic_compile_settings(pico_baton)

    add_executable(picoquic_sample
        sample/sample.c
        sample/sample_background.c
        sample/sample_client.c
        sample/sample_server.c)
    target_link_libraries(picoquic_sample PRIVATE picoquic-log picoquic-core)
    target_include_directories(picoquic_sample PRIVATE loglib picoquic)
    set_picoquic_compile_settings(picoquic_sample)

    add_test(NAME picoquic_ct
             COMMAND picoquic_ct -S ${PROJECT_SOURCE_DIR} -n -r)
    add_test(NAME picohttp_ct
             COMMAND picohttp_ct -S ${PROJECT_SOURCE_DIR} -n -r)

    add_executable(thread_test
        thread_tester/thread_test.c)
    target_link_libraries(thread_test PRIVATE picoquic-log picoquic-core)
    target_include_directories(thread_test PRIVATE loglib picoquic)
    set_picoquic_compile_settings(thread_test)

endif()

# get all project files for formatting
file(GLOB_RECURSE CLANG_FORMAT_SOURCE_FILES *.c *.h)

# Adds clangformat as target that formats all source files
add_custom_target(
    clangformat
    COMMAND clang-format
    -style=Webkit
    -i
    ${CLANG_FORMAT_SOURCE_FILES})

if (NOT CMAKE_INSTALL_INCLUDEDIR)
    set(CMAKE_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_PREFIX}/include)
endif()

if (NOT CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR ${CMAKE_INSTALL_PREFIX}/lib)
endif()

if (NOT CMAKE_INSTALL_BINDIR)
    set(CMAKE_INSTALL_BINDIR ${CMAKE_INSTALL_PREFIX}/bin)
endif()

if (TARGET picoquicdemo)
    install(TARGETS picoquicdemo
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if (TARGET picohttp-core)
    install(TARGETS picohttp-core
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(FILES
        ${PICOHTTP_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()

if (TARGET picolog_t)
    install(TARGETS picolog_t
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if (TARGET picoquic-log)
    install(TARGETS picoquic-log
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

    install(FILES
        ${PICOQUIC_LOGLIB_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()


install(TARGETS picoquic-core
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

if(PICOQUIC_FETCH_PTLS)
    set(LIB_PATH "${CMAKE_INSTALL_LIBDIR}/libpicoquic-core.a;${CMAKE_INSTALL_LIBDIR}/libpicotls-core.a;${CMAKE_INSTALL_LIBDIR}/libpicotls-fusion.a;${CMAKE_INSTALL_LIBDIR}/libpicotls-openssl.a;${CMAKE_INSTALL_LIBDIR}/libpicotls-minicrypto.a" CACHE PATH "Path of library files")

    install(TARGETS ${PTLS_LIBRARIES}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
else()
    set(LIB_PATH "${CMAKE_INSTALL_LIBDIR}/libpicoquic-core.a" CACHE PATH "Path of library file")
endif()

install(FILES
        ${PICOQUIC_CORE_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

include(CMakePackageConfigHelpers)

execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(PROJECT_VERSION "0.0.0-${GIT_HASH}")
message(STATUS "Project version: ${PROJECT_VERSION}")

if (NOT CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR ${CMAKE_INSTALL_PREFIX}/lib)
endif()

set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR} CACHE PATH "Location of header files")

set(INSTALL_CONFIG_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

configure_package_config_file(${PROJECT_NAME}-config.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake PATH_VARS PROJECT_VERSION LIB_PATH INCLUDE_INSTALL_DIR INSTALL_DESTINATION ${INSTALL_CONFIG_DIR})
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake VERSION ${PROJECT_VERSION} COMPATIBILITY ExactVersion)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake DESTINATION ${INSTALL_CONFIG_DIR})

set(PICOQUIC_ADDITIONAL_C_FLAGS ${PICOQUIC_ADDITIONAL_C_FLAGS} PARENT_SCOPE)
set(PICOQUIC_ADDITIONAL_CXX_FLAGS ${PICOQUIC_ADDITIONAL_CXX_FLAGS} PARENT_SCOPE)
set(PICOQUIC_LINKER_FLAGS ${PICOQUIC_LINKER_FLAGS} PARENT_SCOPE)
set(PICOQUIC_COMPILE_DEFINITIONS "${PICOQUIC_COMPILE_DEFINITIONS}" PARENT_SCOPE)
set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}" PARENT_SCOPE)
