# - Try to find MbedTLS
# set(MBEDTLS_LIBRARY mbedtls)
# set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_SOURCE_DIR}/include)

message(STATUS "mbedtls/prefix: ${MBEDTLS_PREFIX}")
message(STATUS "CMAKE_SOURCE_DIR: ${CMAKE_SOURCE_DIR}")
message(STATUS "CMAKE_BINARY_DIR: ${CMAKE_BINARY_DIR}")

find_path(MBEDTLS_INCLUDE_DIRS
    NAMES mbedtls/build_info.h psa/crypto.h
    HINTS ${MBEDTLS_PREFIX}/include/
        ${CMAKE_SOURCE_DIR}/../mbedtls/include/
        ${CMAKE_BINARY_DIR}/../mbedtls/include/
        ../mbedtls/include/ )

message(STATUS "MBEDTLS_INCLUDE_DIRS: ${MBEDTLS_INCLUDE_DIRS}")

set(MBEDTLS_HINTS ${MBEDTLS_PREFIX}/build/library 
    ${CMAKE_BINARY_DIR}/../mbedtls/build/library
    ../mbedtls/build/library ../mbedtls/library)

find_library(MBEDTLS_LIBRARY mbedtls HINTS ${MBEDTLS_HINTS})
find_library(MBEDTLS_CRYPTO mbedcrypto HINTS ${MBEDTLS_HINTS})
message(STATUS "MBEDTLS_CRYPTO: ${MBEDTLS_CRYPTO}")
find_library(MBEDTLS_X509 mbedx509 HINTS ${MBEDTLS_HINTS})
message(STATUS "MBEDTLS_X509: ${MBEDTLS_X509}")

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set PTLS_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(MbedTLS REQUIRED_VARS
    MBEDTLS_LIBRARY
    MBEDTLS_CRYPTO
    MBEDTLS_X509
    MBEDTLS_INCLUDE_DIRS)
    
if (MbedTLS_FOUND)
    set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY} ${MBEDTLS_X509} ${MBEDTLS_CRYPTO})
    mark_as_advanced(MBEDTLS_LIBRARIES MBEDTLS_INCLUDE_DIRS)
endif ()
