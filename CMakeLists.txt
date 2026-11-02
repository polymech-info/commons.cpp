cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(pm-commons
    VERSION 0.1.0
    DESCRIPTION "PolyMech portable commons"
    LANGUAGES CXX)
endif()

# Every translation unit under src/. Drop a file in and the next configure picks it up.
# The other platform's library unit cannot compile here.
file(GLOB_RECURSE PM_COMMONS_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.mm"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
if(WIN32)
  list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "[/\\\\]library_posix\\.cpp$")
else()
  list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "[/\\\\]library_win\\.cpp$")
endif()

# A purged src/ is a legal configure. The host still links pm-commons-lib.
if(PM_COMMONS_SOURCES)
  add_library(pm-commons-lib STATIC ${PM_COMMONS_SOURCES})
  # src/ is the include root, so callers use the subdirectory:
  # #include "fs/mask.hpp", "net/uri.hpp", "string/string_utils.hpp".
  target_include_directories(pm-commons-lib
    PUBLIC
      "${CMAKE_CURRENT_SOURCE_DIR}/include"
      "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_features(pm-commons-lib PUBLIC cxx_std_20)
  if(NOT WIN32)
    target_link_libraries(pm-commons-lib PUBLIC ${CMAKE_DL_LIBS})
  endif()
  if(MSVC)
    target_compile_definitions(pm-commons-lib PRIVATE
      _CRT_SECURE_NO_WARNINGS
      _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING=1)
    target_compile_options(pm-commons-lib PRIVATE /W3 /utf-8 /EHsc)
  else()
    target_compile_options(pm-commons-lib PRIVATE -Wall -Wextra)
  endif()
  # A few moved sources still include host headers that stayed in Tanit
  # (logging/pm_log.hpp, ui_defaults.hpp, output_path.hpp, media/probe.hpp).
  if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    target_include_directories(pm-commons-lib PRIVATE
      "${CMAKE_SOURCE_DIR}/src"
      "${CMAKE_SOURCE_DIR}/src/core")
    if(TARGET Boost::url)
      target_link_libraries(pm-commons-lib PUBLIC Boost::url Boost::asio)
    endif()
    if(TARGET CURL::libcurl)
      target_link_libraries(pm-commons-lib PUBLIC CURL::libcurl)
    endif()
    if(TARGET nlohmann_json::nlohmann_json)
      target_link_libraries(pm-commons-lib PUBLIC nlohmann_json::nlohmann_json)
    endif()
    if(TARGET pranav_glob)
      target_link_libraries(pm-commons-lib PUBLIC pranav_glob)
    endif()
    if(TARGET logger)
      target_link_libraries(pm-commons-lib PUBLIC logger)
    endif()
    if(FEATURE_JQ AND TARGET jq)
      target_compile_definitions(pm-commons-lib PRIVATE FEATURE_JQ=1)
      target_link_libraries(pm-commons-lib PUBLIC jq)
    endif()
    # string_utils.cpp compiles the embed bridge only when these are on.
    # The host sets them on pm-media; this target needs the same pair.
    if(FEATURE_LLAMA)
      target_compile_definitions(pm-commons-lib PRIVATE FEATURE_LLAMA=1)
    endif()
    if(FEATURE_COMMAND_LLAMA_INFERENCE)
      target_compile_definitions(pm-commons-lib PRIVATE FEATURE_COMMAND_LLAMA_INFERENCE=1)
    endif()
  endif()
else()
  add_library(pm-commons-lib INTERFACE)
  target_include_directories(pm-commons-lib INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_features(pm-commons-lib INTERFACE cxx_std_20)
endif()

# CLI11 and nlohmann exist only for the standalone test executable.
# The static library has no JSON, sockets, or Win32 types in its headers.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cli/main.cpp")
  if(NOT TARGET CLI11::CLI11 OR NOT TARGET nlohmann_json::nlohmann_json)
    include(FetchContent)
    if(NOT TARGET CLI11::CLI11)
      set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)
      set(CLI11_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
      FetchContent_Declare(cli11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG v2.4.2
        GIT_SHALLOW TRUE)
      FetchContent_MakeAvailable(cli11)
    endif()
    if(NOT TARGET nlohmann_json::nlohmann_json)
      set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
      FetchContent_Declare(nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
        GIT_SHALLOW TRUE)
      FetchContent_MakeAvailable(nlohmann_json)
    endif()
  endif()

  add_executable(pm-commons cli/main.cpp)
  target_link_libraries(pm-commons PRIVATE pm-commons-lib CLI11::CLI11 nlohmann_json::nlohmann_json)
  target_compile_features(pm-commons PRIVATE cxx_std_20)
  if(MSVC)
    target_compile_definitions(pm-commons PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(pm-commons PRIVATE /W3 /utf-8 /EHsc)
  else()
    target_compile_options(pm-commons PRIVATE -Wall -Wextra)
  endif()
endif()
