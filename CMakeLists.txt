cmake_minimum_required (VERSION 3.20)

project(ACRogueLangPatcher C CXX)

set(SRC_DIR "${PROJECT_SOURCE_DIR}/src")

message(STATUS "Downloading injector...")
include(cmake/injector.cmake)
message(STATUS "Downloading hooking...")
include(cmake/hooking.cmake)
message(STATUS "Downloading mINI...")
include(cmake/mINI.cmake)

file(GLOB_RECURSE SRC_MAIN
  "${SRC_DIR}/**.hpp"
  "${SRC_DIR}/**.cpp"
  "${SRC_DIR}/**.h"
  "${SRC_DIR}/**.c"
  "${SRC_DIR}/**.def"
)

add_library(ACRogueLangPatcher MODULE "${SRC_MAIN}")

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set_property(TARGET ACRogueLangPatcher PROPERTY CXX_STANDARD 23)
set_property(TARGET ACRogueLangPatcher PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET ACRogueLangPatcher PROPERTY CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(ACRogueLangPatcher PRIVATE "-masm=intel")
endif()

source_group(TREE ${SRC_DIR} PREFIX "src" FILES ${SRC_MAIN})

target_include_directories(ACRogueLangPatcher PRIVATE 
  "${SRC_DIR}"
  "${injector_SOURCE_DIR}/safetyhook"
  "${injector_SOURCE_DIR}/include"
  "${hooking_SOURCE_DIR}"
  "${mini_SOURCE_DIR}/src"
)

target_link_libraries(ACRogueLangPatcher PRIVATE injector hooking)

# Generate a JSON compilation database
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
