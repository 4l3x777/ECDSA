cmake_minimum_required(VERSION 3.22)

set(PATCH_VERSION "1" CACHE INTERNAL "Patch version")
set(PROJECT_VESRION 0.0.${PATCH_VERSION})
project(ECDSA VERSION ${PROJECT_VESRION})

include(FetchContent)

FetchContent_Declare(
  ttmath
  GIT_REPOSITORY https://gitea.ttmath.org/tomasz.sowa/ttmath.git
  GIT_TAG 0.9.3
)
FetchContent_MakeAvailable(ttmath)

if(NOT ttmath_POPULATED)
  FetchContent_Populate(ttmath)
  add_subdirectory(${ttmath_SOURCE_DIR} ${ttmath_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

include_directories(${ttmath_SOURCE_DIR})

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)

FetchContent_GetProperties(googletest)
if(NOT googletest_POPULATED)
  FetchContent_Populate(googletest)
  add_subdirectory(${googletest_SOURCE_DIR} ${googletest_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

include_directories(includes src tests)

add_library(
  ecdsa_primefield
  STATIC
  src/ecdsa_primefield.cpp
)

add_library(
  sha512
  STATIC
  src/sha512.cpp
)

add_library(
  thread_pool
  STATIC
  src/thread_pool.cpp
)

add_library(
  aes
  STATIC
  src/aes_encryption_mode.cpp
  src/aes_rijndael.cpp
  src/aes.cpp
)

add_library(
  crypto_pseudo_random_generator
  STATIC
  src/crypto_pseudo_random_generator.cpp
)

add_executable(
  test_ecdsa_gtest 
  tests/test_ecdsa.cpp
)

add_executable(
  test_ecdsa_primefield_gtest 
  tests/test_ecdsa_primefield.cpp
)

add_executable(
  test_crypto_pseudo_random_generator_gtest 
  tests/test_crypto_pseudo_random_generator.cpp
)

add_executable(
  test_sha512_gtest 
  tests/test_sha512.cpp
)

add_executable(
  test_aes_gtest 
  tests/test_aes.cpp
)

target_link_libraries(
  test_ecdsa_gtest
  crypto_pseudo_random_generator
  sha512
  aes
  gtest 
  gtest_main
  ecdsa_primefield)

target_link_libraries(
  crypto_pseudo_random_generator
  aes)

target_link_libraries(
  test_ecdsa_primefield_gtest
  crypto_pseudo_random_generator
  sha512
  aes
  gtest 
  gtest_main
  ecdsa_primefield)

target_link_libraries(
  ecdsa_primefield
  crypto_pseudo_random_generator
  sha512)

target_link_libraries(
  aes
  thread_pool)
  
target_link_libraries(
  test_crypto_pseudo_random_generator_gtest
  aes
  gtest 
  gtest_main
  crypto_pseudo_random_generator)

target_link_libraries(
  test_aes_gtest
  gtest 
  gtest_main
  aes)

target_link_libraries(
  test_sha512_gtest
  gtest 
  gtest_main
  sha512)

set_target_properties(
  test_ecdsa_primefield_gtest
  test_sha512_gtest
  test_aes_gtest
  test_crypto_pseudo_random_generator_gtest
  PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
)

if (MSVC)
  target_compile_options(test_ecdsa_gtest PRIVATE /W4)

  target_compile_options(test_ecdsa_primefield_gtest PRIVATE /W4)

  target_compile_options(test_sha512_gtest PRIVATE /W4)

  target_compile_options(test_aes_gtest PRIVATE /W4)

  target_compile_options(test_crypto_pseudo_random_generator_gtest PRIVATE /W4)
else ()
  target_link_options(test_ecdsa_gtest PRIVATE -static-libgcc -static-libstdc++)

  target_link_options(test_ecdsa_primefield_gtest PRIVATE -static-libgcc -static-libstdc++)

  target_link_options(test_sha512_gtest PRIVATE -static-libgcc -static-libstdc++)

  target_link_options(test_aes_gtest PRIVATE -static-libgcc -static-libstdc++)

  target_link_options(test_crypto_pseudo_random_generator_gtest PRIVATE -static-libgcc -static-libstdc++)

  target_compile_options(
    test_ecdsa_gtest 
    PRIVATE
    -Wall 
    -Wextra 
    -pedantic 
  )

  target_compile_options(
    test_ecdsa_primefield_gtest 
    PRIVATE
    -Wall 
    -Wextra 
    -pedantic 
  )

  target_compile_options(
    test_sha512_gtest 
    PRIVATE
    -Wall 
    -Wextra 
    -pedantic 
  )

  target_compile_options(
    test_aes_gtest 
    PRIVATE
    -Wall 
    -Wextra 
    -pedantic 
  )

  target_compile_options(
    test_crypto_pseudo_random_generator_gtest 
    PRIVATE
    -Wall 
    -Wextra 
    -pedantic 
  )
endif()

install(
    TARGETS 
    ecdsa_primefield aes thread_pool sha512 crypto_pseudo_random_generator
    RUNTIME DESTINATION lib COMPONENT release
    LIBRARY DESTINATION lib COMPONENT release
    ARCHIVE DESTINATION lib COMPONENT release
)

install(
  DIRECTORY includes
  DESTINATION .
  COMPONENT release
  FILES_MATCHING
  PATTERN "*.h"
)

install(
  DIRECTORY ${ttmath_SOURCE_DIR}/ttmath
  DESTINATION includes
  COMPONENT release
  FILES_MATCHING
  PATTERN "*.h"
)

set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL release)

# CPack area
if (WIN32)
  set(CPACK_GENERATOR "ZIP")
else()
  set(CPACK_GENERATOR "DEB")
endif()
set(CPACK_PACKAGE_VERSION "0.0.1")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "1")
set(CPACK_PACKAGE_CONTACT https://github.com/4l3x777/ECDSA)
include(CPack)

# Tests area
enable_testing()

add_test(
    NAME 
    unit_tests_test_ecdsa_gtest
    COMMAND 
    test_ecdsa_gtest
)

add_test(
    NAME 
    unit_tests_test_ecdsa_primefield_gtest
    COMMAND 
    test_ecdsa_primefield_gtest
)

add_test(
    NAME 
    unit_tests_test_aes_gtest
    COMMAND 
    test_aes_gtest
)

add_test(
    NAME 
    unit_tests_test_crypto_pseudo_random_generator_gtest
    COMMAND 
    test_crypto_pseudo_random_generator_gtest
)

add_test(
    NAME 
    unit_tests_test_sha512_gtest
    COMMAND 
    test_sha512_gtest
)