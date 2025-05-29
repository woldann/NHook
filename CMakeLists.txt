cmake_minimum_required(VERSION 3.10)
project(NHook VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)

add_subdirectory(Neptune)
add_subdirectory(NThread)
add_subdirectory(NThreadOSUtils)

set(NHOOK_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(NHOOK_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB_RECURSE NHOOK_HEADERS CONFIGURE_DEPENDS ${NHOOK_INCLUDE_DIR}/*.h)
file(GLOB_RECURSE NHOOK_SOURCES CONFIGURE_DEPENDS ${NHOOK_SOURCE_DIR}/*.c)

set(CAPSTONE_SOURCES
    capstone/cs.c
    capstone/arch/X86/X86Disassembler.c
    capstone/arch/X86/X86DisassemblerDecoder.c
    capstone/arch/X86/X86Mapping.c
    capstone/arch/X86/X86Module.c
    capstone/arch/X86/X86InstPrinterCommon.c
    capstone/arch/X86/X86IntelInstPrinter.c
    capstone/arch/X86/X86ATTInstPrinter.c
    capstone/MCInst.c
    capstone/MCRegisterInfo.c
    capstone/MCInstrDesc.c
    capstone/utils.c
    capstone/SStream.c
    capstone/Mapping.c
)

string(TOLOWER ${PROJECT_NAME} PROJECT_NAME_LOWER)
set(LIBRARY_OUTPUT "${PROJECT_NAME_LOWER}-${PROJECT_VERSION}")

add_library(${PROJECT_NAME_LOWER} SHARED ${NHOOK_SOURCES} ${CAPSTONE_SOURCES})

set_target_properties(${PROJECT_NAME_LOWER} PROPERTIES OUTPUT_NAME "${LIBRARY_OUTPUT}")

target_include_directories(${PROJECT_NAME_LOWER} PUBLIC ${NHOOK_INCLUDE_DIR})
target_include_directories(${PROJECT_NAME_LOWER} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/NThreadOSUtils/include")
target_include_directories(${PROJECT_NAME_LOWER} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/NThread/include")
target_include_directories(${PROJECT_NAME_LOWER} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/Neptune/include")
target_include_directories(${PROJECT_NAME_LOWER} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/capstone/include")
target_link_libraries(${PROJECT_NAME_LOWER} PRIVATE NThreadOSUtils)

target_compile_definitions(${PROJECT_NAME_LOWER} PRIVATE
  LOG_LEVEL_3
  NEPTUNE_MODULERULES_HEADER="ntosutils_rules.h"
  LOG_ON_STDOUT=0
  NHOOK_EXPORTS
  LOG_FILE_PATH=L"nhook.log"
  NEPTUNE_API_EXPORT
)

target_compile_definitions(${PROJECT_NAME_LOWER} PRIVATE CAPSTONE_USE_SYS_DYN_MEM CAPSTONE_X86 CAPSTONE_HAS_X86)

add_subdirectory(tests)

