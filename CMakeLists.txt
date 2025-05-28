cmake_minimum_required(VERSION 3.10)
project(NHook C)

add_subdirectory(Neptune)
add_subdirectory(NThread)
add_subdirectory(NThreadOSUtils)

set(NHOOK_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(NHOOK_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB_RECURSE NHOOK_HEADERS CONFIGURE_DEPENDS ${NHOOK_INCLUDE_DIR}/*.h)
file(GLOB_RECURSE NHOOK_SOURCES CONFIGURE_DEPENDS ${NHOOK_SOURCE_DIR}/*.c)

add_library(NHook SHARED ${NHOOK_SOURCES})

target_include_directories(NHook PUBLIC ${NHOOK_INCLUDE_DIR})
target_include_directories(NHook PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/NThreadOSUtils/include")
target_include_directories(NHook PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/NThread/include")
target_include_directories(NHook PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/Neptune/include")
target_link_libraries(NHook PRIVATE NThreadOSUtils)

target_compile_definitions(NHook PRIVATE
  LOG_LEVEL_3
  NEPTUNE_MODULERULES_HEADER="ntosutils_rules.h"
  LOG_ON_STDOUT=0
  NHOOK_EXPORTS
  LOG_FILE_PATH=L"nhook.log"
)

add_subdirectory(tests)

