cmake_minimum_required(VERSION 3.10)

add_executable(local_hook ${CMAKE_CURRENT_SOURCE_DIR}/local_hook.c)
target_link_libraries(local_hook PRIVATE nhook)
