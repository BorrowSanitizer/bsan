cmake_minimum_required(VERSION 3.20)
project(bsan)

execute_process(
    COMMAND ${LLVM_CONFIG} --cxxflags
    OUTPUT_VARIABLE LLVM_CXXFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LLVM_CXXFLAGS}")

set(BSAN_SOURCES
  BorrowSanitizer.cpp
  BorrowSanitizerPass.cpp
  Provenance.cpp 
)

set(BSAN_HEADERS
  BorrowSanitizer.h
  BorrowSanitizerPass.h
  Provenance.h
  Declarations.h
)

set(CMAKE_CXX_CLANG_TIDY clang-tidy;-warnings-as-errors=*)

add_custom_target(clang-format
  COMMAND clang-format ${BSAN_SOURCES} ${BSAN_HEADERS} -i --style=file
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(clang-format-check
  COMMAND clang-format ${BSAN_SOURCES} ${BSAN_HEADERS} --dry-run --Werror --style=file
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_library(bsan_plugin SHARED ${BSAN_SOURCES} ${BSAN_HEADERS})
add_dependencies(bsan_plugin clang-format)
