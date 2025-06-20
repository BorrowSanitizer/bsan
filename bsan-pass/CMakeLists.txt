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
  BsanStackFrameLayout.cpp
)

set(BSAN_HEADERS
  BorrowSanitizer.h
  BsanStackFrameLayout.h
)

add_library(bsan_plugin SHARED ${BSAN_SOURCES} ${BSAN_HEADERS})
