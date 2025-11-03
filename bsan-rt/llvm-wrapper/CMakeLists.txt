set(BSAN_SUPPORTED_ARCH ${SANITIZER_COMMON_SUPPORTED_ARCH})

# Runtime library sources and build flags.
set(BSAN_SOURCES
  bsan.cpp
)

SET(BSAN_HEADERS
  bsan.h
)

add_custom_target(clang-format
  COMMAND clang-format ${BSAN_SOURCES} ${BSAN_HEADERS} -i --style=LLVM
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(clang-format-check
  COMMAND clang-format ${BSAN_SOURCES} ${BSAN_HEADERS} --dry-run --Werror --style=LLVM
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

set(BSAN_COMMON_CFLAGS ${SANITIZER_COMMON_CFLAGS})
append_rtti_flag(OFF BSAN_COMMON_CFLAGS)
# Prevent clang from generating libc calls.
append_list_if(COMPILER_RT_HAS_FFREESTANDING_FLAG -ffreestanding BSAN_COMMON_CFLAGS)
set(BSAN_DYNAMIC_CFLAGS ${BSAN_COMMON_CFLAGS})

set(BSAN_COMMON_DEFINITIONS "")
set(BSAN_DYNAMIC_DEFINITIONS ${BSAN_COMMON_DEFINITIONS} BSAN_DYNAMIC=1)

# Compile BorSan sources into an object library.

add_compiler_rt_object_libraries(RTBorsan_dynamic
  OS ${SANITIZER_COMMON_SUPPORTED_OS}
  ARCHS ${BSAN_SUPPORTED_ARCH}
  SOURCES ${BSAN_SOURCES}
  ADDITIONAL_HEADERS ${BSAN_HEADERS}
  CFLAGS ${BSAN_DYNAMIC_CFLAGS}
  DEFS ${BSAN_DYNAMIC_DEFINITIONS})

# Static runtime library.
add_compiler_rt_component(bsan)

if(APPLE)
  add_weak_symbols("sanitizer_common" WEAK_SYMBOL_LINK_FLAGS)

  add_compiler_rt_runtime(clang_rt.bsan
    SHARED
    OS ${SANITIZER_COMMON_SUPPORTED_OS}
    ARCHS ${BSAN_SUPPORTED_ARCH}
    OBJECT_LIBS RTBorsan_dynamic
                RTInterception
                RTSanitizerCommon
                RTSanitizerCommonLibc
                RTSanitizerCommonSymbolizer
    CFLAGS ${BSAN_DYNAMIC_CFLAGS}
    LINK_FLAGS ${WEAK_SYMBOL_LINK_FLAGS}
    DEFS ${BSAN_DYNAMIC_DEFINITIONS}
    PARENT_TARGET bsan)

  add_compiler_rt_runtime(clang_rt.bsan_static
    STATIC
    ARCHS ${BSAN_SUPPORTED_ARCH}
    OBJECT_LIBS RTBorsan_static
    CFLAGS ${BSAN_CFLAGS}
    DEFS ${BSAN_COMMON_DEFINITIONS}
    PARENT_TARGET bsan)
else()
  set(BSAN_CFLAGS ${BSAN_COMMON_CFLAGS})
  append_list_if(COMPILER_RT_HAS_FPIE_FLAG -fPIE BSAN_CFLAGS)

  foreach(arch ${BSAN_SUPPORTED_ARCH})
    if(CAN_TARGET_${arch})
      add_compiler_rt_runtime(clang_rt.bsan
        STATIC
        ARCHS ${arch}
        SOURCES ${BSAN_SOURCES}
        OBJECT_LIBS RTInterception
                    RTSanitizerCommon
                    RTSanitizerCommonLibc
                    RTSanitizerCommonSymbolizer
        CFLAGS ${BSAN_CFLAGS}
        PARENT_TARGET bsan)
    endif()
  endforeach()
endif()