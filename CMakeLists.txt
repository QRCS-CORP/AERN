cmake_minimum_required(VERSION 3.15)

project(AERN_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Download and build QSC
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# AERN Static Library
file(GLOB_RECURSE AERN_SOURCES "Source/AERN/*.c")
file(GLOB_RECURSE AERN_HEADERS "Source/AERN/include/*.h")

add_library(aern STATIC ${AERN_SOURCES} ${AERN_HEADERS})
target_include_directories(aern PUBLIC "Source/AERN")
target_link_libraries(aern PUBLIC qsc)

# AERN ARS
file(GLOB_RECURSE AERN_ARS_SOURCES "Source/ARS/*.c")

add_executable(aern_ars ${AERN_ARS_SOURCES})
target_include_directories(aern_ars PRIVATE "Source/ARS")
target_link_libraries(aern_ars PRIVATE aern)

# AERN ADC
file(GLOB_RECURSE AERN_ADC_SOURCES "Source/ADC/*.c")

add_executable(aern_adc ${AERN_ADC_SOURCES})
target_include_directories(aern_adc PRIVATE "Source/ADC")
target_link_libraries(aern_adc PRIVATE aern)

# Warnings
foreach(target aern aern_ars aern_adc)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()
