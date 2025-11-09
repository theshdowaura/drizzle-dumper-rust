cmake_minimum_required(VERSION 3.22)

project(drizzlezygisk VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(nlohmann_json QUIET)

add_library(drizzlezygisk SHARED module.cpp)

target_include_directories(drizzlezygisk
  PRIVATE
    ${ANDROID_NDK}/sources/cxx-stl/llvm-libc++/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

if (nlohmann_json_FOUND)
  target_link_libraries(drizzlezygisk PRIVATE nlohmann_json::nlohmann_json)
else()
  target_compile_definitions(drizzlezygisk
    PRIVATE
      DRIZZLE_ZYGISK_EMBED_JSON=1)
endif()

target_link_libraries(drizzlezygisk
  PRIVATE
    log
)
