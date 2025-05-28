cmake_minimum_required(VERSION 3.10)

add_executable(hook ${CMAKE_CURRENT_SOURCE_DIR}/hook.c)
target_link_libraries(hook PRIVATE NHook)

target_compile_definitions(hook PRIVATE
  LOG_LEVEL_3
  NEPTUNE_MODULERULES_HEADER="ntosutils_rules.h"
  NEPTUNE_API_IMPORT
)

