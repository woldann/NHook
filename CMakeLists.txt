cmake_minimum_required(VERSION 3.10)
project(NHook VERSION 1.0.0 LANGUAGES C ASM_NASM)

add_subdirectory(submodules)

set(NHOOK_MODULE_RULES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/modulerules)
set(NHOOK_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(NHOOK_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB_RECURSE NHOOK_HEADERS CONFIGURE_DEPENDS ${NHOOK_INCLUDE_DIR}/*.h)
file(GLOB_RECURSE NHOOK_SOURCES CONFIGURE_DEPENDS ${NHOOK_SOURCE_DIR}/*.c)

set(CAPSTONE_SOURCES
  submodules/capstone/cs.c
  submodules/capstone/arch/X86/X86ATTInstPrinter.c
  submodules/capstone/arch/X86/X86Disassembler.c
  submodules/capstone/arch/X86/X86DisassemblerDecoder.c
  submodules/capstone/arch/X86/X86IntelInstPrinter.c
  submodules/capstone/arch/X86/X86Mapping.c
  submodules/capstone/arch/X86/X86Module.c
  submodules/capstone/MCInst.c
  submodules/capstone/MCRegisterInfo.c
  submodules/capstone/MCInstrDesc.c
  submodules/capstone/utils.c
  submodules/capstone/SStream.c
)

set(ABSOLUTE_CAPSTONE_SOURCES "")
foreach(SRC ${CAPSTONE_SOURCES})
  list(APPEND ABSOLUTE_CAPSTONE_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/${SRC}")
endforeach()

set(PROJECT_VERSION_STRING "${PROJECT_VERSION}" CACHE STRING "Project version")
string(TOLOWER ${PROJECT_NAME} PROJECT_NAME_LOWER)
if(NOT DEFINED LIBRARY_OUTPUT)
  set(LIBRARY_OUTPUT "${PROJECT_NAME_LOWER}-${PROJECT_VERSION_STRING}")
endif()

enable_language(ASM_NASM)

set(NHOOK_ASM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/asm)

file(GLOB_RECURSE NHOOK_ASM_SOURCES CONFIGURE_DEPENDS ${NHOOK_ASM_DIR}/*.asm)

set_source_files_properties(${ASM_SOURCES} PROPERTIES
  COMPILE_FLAGS "-f win64"
)

set_source_files_properties(${ABSOLUTE_CAPSTONE_SOURCES} PROPERTIES
  COMPILE_FLAGS "-std=c99"
)

add_library(${PROJECT_NAME_LOWER} SHARED ${NHOOK_SOURCES} ${NHOOK_ASM_SOURCES} ${ABSOLUTE_CAPSTONE_SOURCES})

set_target_properties(${PROJECT_NAME_LOWER} PROPERTIES
  OUTPUT_NAME "${LIBRARY_OUTPUT}"
  SUFFIX ".dll"
  PREFIX ""
)

target_include_directories(${PROJECT_NAME_LOWER} PUBLIC "${NHOOK_INCLUDE_DIR}")
target_include_directories(${PROJECT_NAME_LOWER} PUBLIC "${NHOOK_MODULE_RULES_DIR}")
target_include_directories(${PROJECT_NAME_LOWER} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/submodules/NThreadOSUtils/include")
target_include_directories(${PROJECT_NAME_LOWER} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/submodules/NThread/include")
target_include_directories(${PROJECT_NAME_LOWER} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/submodules/Neptune/include")
target_include_directories(${PROJECT_NAME_LOWER} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/submodules/capstone/include")
target_include_directories(${PROJECT_NAME_LOWER} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/submodules/capstone")
target_link_libraries(${PROJECT_NAME_LOWER} PRIVATE NThreadOSUtils)

set_property(TARGET ${PROJECT_NAME_LOWER} PROPERTY C_STANDARD 99)

target_compile_definitions(${PROJECT_NAME_LOWER} PRIVATE
  LOG_LEVEL_2
  NEPTUNE_MODULERULES_HEADER="nhook_rules.h"
  LOG_ON_STDOUT=0
  NEPTUNE_ENABLE_MEMMEM
  LOG_FILE_PATH=L"nhook.log"
  NHOOK_EXPORT
)

target_compile_definitions(${PROJECT_NAME_LOWER} PRIVATE CAPSTONE_USE_SYS_DYN_MEM CAPSTONE_X86 CAPSTONE_HAS_X86 CAPSTONE_DIET)

add_subdirectory(tests)
