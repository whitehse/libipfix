cmake_minimum_required(VERSION 3.14)
project(libipfix VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Strict warnings
add_compile_options(-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion)

# Main library
add_library(ipfix STATIC src/ipfix.c)
target_include_directories(ipfix PUBLIC include)

# Install rules (headers + lib)
include(GNUInstallDirs)
install(TARGETS ipfix
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# pkg-config
configure_file(libipfix.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libipfix.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libipfix.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# Man pages
install(DIRECTORY man/man3/ DESTINATION ${CMAKE_INSTALL_MANDIR}/man3
        FILES_MATCHING PATTERN "*.3")

# --- Tests ---
enable_testing()

add_executable(ipfix_smoke tests/ipfix_smoke.c)
target_link_libraries(ipfix_smoke PRIVATE ipfix)
add_test(NAME ipfix_smoke COMMAND ipfix_smoke)

add_executable(ipfix_dialectic tests/ipfix_dialectic.c)
target_link_libraries(ipfix_dialectic PRIVATE ipfix)
add_test(NAME ipfix_dialectic COMMAND ipfix_dialectic)

add_executable(ipfix_errors tests/ipfix_errors.c)
target_link_libraries(ipfix_errors PRIVATE ipfix)
add_test(NAME ipfix_errors COMMAND ipfix_errors)

# --- Example ---
add_executable(ipfix_example examples/ipfix_example.c)
target_link_libraries(ipfix_example PRIVATE ipfix)

# --- Fuzz (optional, needs libFuzzer + clang) ---
option(BUILD_FUZZ "Build fuzz harness (requires clang with libFuzzer)" OFF)
if(BUILD_FUZZ)
    # Instrument the library itself so ASan/UBSan catch parser bugs.
    target_compile_options(ipfix PRIVATE
        -g -O1 -fno-omit-frame-pointer
        -fsanitize=fuzzer-no-link,address,undefined)
    target_link_options(ipfix INTERFACE
        -fsanitize=address,undefined)

    add_executable(ipfix_fuzz fuzz/ipfix_fuzz.c)
    target_link_libraries(ipfix_fuzz PRIVATE ipfix)
    target_compile_options(ipfix_fuzz PRIVATE
        -g -O1 -fno-omit-frame-pointer
        -fsanitize=fuzzer,address,undefined)
    target_link_options(ipfix_fuzz PRIVATE
        -fsanitize=fuzzer,address,undefined)
endif()
