cmake_minimum_required(VERSION 3.10)

add_executable(hook ${CMAKE_CURRENT_SOURCE_DIR}/hook.c)
target_link_libraries(hook PRIVATE nhook)

target_compile_definitions(hook PRIVATE
  LOG_LEVEL_1
)

