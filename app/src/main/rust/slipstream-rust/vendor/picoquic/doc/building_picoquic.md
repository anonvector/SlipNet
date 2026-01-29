# Building PicoQUIC

See the 'Building Picoquic' section [README](../README.md) for building picoquic for the first time and installing the dependencies.

## Dependencies

Direct dependencies
- [Picotls implementation of TLS 1.3](https://github.com/h2o/picotls)

Fetching and installing this package can be done through an option when invoking cmake, as follows.

```shell
 cmake -DPICOQUIC_FETCH_PTLS=Y .
```

Inherited dependencies
- [OpenSSL through PicoTLS](https://github.com/openssl/openssl)

TODO: Current issues and ongoing work

There is a current issue trying to enable the use of `mbedtls` instead of `openssl`.

## Targets

Targets are anything that is defined as an executable in `CMakeLists.txt`.
Available targets:

- picoquicdemo
- picolog_t
- picoquic_ct
- picohttp_ct
- pico_baton
- picoquic_sample
- thread_test

All of these targets are built when the `make .` or `cmake --build .` commands are used to build the project. After which the test program `picoquic_ct` can be used to verify the port.

`picoquicdemo` ([found in picoquicfirst/picoquicdemo.c](../picoquicfirst/picoquicdemo.c)) and `picoquic_sample` ([sample documentation](../sample/README.md)) are a good starting point for developing an application on top of this QUIC implementation.


## (Re)Building a Single Target

Targets defined in the `CMakeLists.txt`, listed above for convenience, can be build individually using cmake's `--target` option. The command `cmake --build . --target <target_name>` can be used to build a specific target and all it's dependcies. For example `cmake --build . --target picoquic_sample` will build the sample file transfer application in [sample/](../sample/README.md) as defined in the `CMakeLists.txt`. All the required components will also be built. This works if the command is issued in the top-level directory of the repository. This is useful for recompiling test programs and programs like `picoquic_sample` and `picoquicdemo` if they have been modified. Therefore reducing build times when making small changes.

This also works if `picoquic` has not been built as a whole before.

## Picoquic options

- building and fetching PTLS `-DPICOQUIC_FETCH_PTLS=Y`
- building with exported debug information `-DCMAKE_BUILD_TYPE=Debug`

These two options can be set when configuring cmake.

- adress sanitation `ASAN`
- undefined behaviour sanitation `UBSAN`

`ASAN` and `UBSAN` are C/C++ compiler features and can be set by setting compiler flags when using the `cmake`.
`cmake "-DCMAKE_C_FLAGS=-fsanitize=address,undefined -DCMAKE_CXX_FLAGS=-fsanitize=address,undefined"` sets both the `ASAN/UBSAN` options for C and C++.
Alternatively these options can be set using `ccmake` as well by setting the flieds `DCMAKE_C_FLAGS & DCMAKE_CXX_FLAGS` to `-fsanitize=address,undefined`.

## Picoquic as a Dependency

When using CMake [FetchContent](https://cmake.org/cmake/help/latest/module/FetchContent.html) can be used to fetch the `picoquic` repository from github.
A snipped that does this can be seen in the [quicrq](https://github.com/Quicr/quicrq) directory in the `dependencies` subdirectory and is shown below.

```cmake
# Enable fetching content
include(FetchContent)

# Fetch the picoquic library, which brings in picotls with it
FetchContent_Declare(
    picoquic
    GIT_REPOSITORY  https://github.com/private-octopus/picoquic.git
    GIT_TAG         master
)

# Set the option to force picoquic to fetch the picotls
find_package(PTLS)
if(NOT PTLS_FOUND)
set(PICOQUIC_FETCH_PTLS ON)
end_if()

# Make dependencies available
FetchContent_MakeAvailable(picoquic)
```

FetchContent can be used to fetch a specific release or tag, if a certain version or release is desired.
This can be used as fine grain as choosing a single commit, by specifying the commit hash.

In the main `CMakeLists.txt` the subdirectory can be added using the `add_subdirectory(<directory_name>)` directive.

```cmake
# Add the subdirectory dependencies, where dependencies/CMakeLists.txt looks as above
add_subdirectory(dependencies)

# check if the package was loaded/is available and stop the build if it was not
find_package(picoquic REQUIRED)
```

Additionally `cmake` needs to be told where to find the imported dependency, using hints defined in a `cmake/Find<DependencyName>.cmake` file placed in the top-most directory in the repository.
The cmake documentation describes how to [Create CMake Package Configuration Files](https://cmake.org/cmake/help/book/mastering-cmake/chapter/Finding%20Packages.html).

