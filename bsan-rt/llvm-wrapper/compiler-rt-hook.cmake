function(add_bsan_runtime)
  include("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/CMakeLists.txt")
endfunction()
cmake_language(DEFER CALL add_bsan_runtime)