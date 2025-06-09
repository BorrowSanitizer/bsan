cmake_minimum_required(VERSION 3.20)
project(bsan)

set(BSAN_SOURCES
  BorrowSanitizer.cpp
)

set(BSAN_HEADERS
  BorrowSanitizer.h
)

add_library(bsan_plugin SHARED ${BSAN_SOURCES} ${BSAN_HEADERS})
