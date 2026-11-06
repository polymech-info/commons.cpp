cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(pm-commons
    VERSION 0.1.0
    DESCRIPTION "PolyMech portable commons"
    LANGUAGES CXX)
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/logging.cmake")

# Every translation unit under src/. Drop a file in and the next configure picks it up.
# The other platform's library unit cannot compile here.
file(GLOB_RECURSE PM_COMMONS_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.mm"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
if(WIN32)
  list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "[/\\\\]library_posix\\.cpp$")
  list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "[/\\\\]file_watcher\\.cpp$")
else()
  list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "[/\\\\]library_win\\.cpp$")
  list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "[/\\\\]file_watcher_win32\\.cpp$")
endif()

# Standalone Asio and FEATURE_COMMAND_IPC_NEXT live on the host image.
# The source stays here; pm-media compiles it.
list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "ipc[/\\\\]cmd_ipc\\.cpp$")
list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "commands[/\\\\].*\\.cpp$")
# Compiled by the logger target in cmake/logging.cmake, then linked into this lib.
list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "logging[/\\\\]logger\\.cpp$")
# kainjow/Mustache is fetched by the host image.
list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "mustache_render\\.cpp$")
# Host image compiles these. They need branding, the settings profile, or Win32
# headers that this static library does not set up on every platform.
foreach(_drop IN ITEMS
    "fs_size_win32\\.cpp$"
    "stdio_child_runner\\.cpp$"
    "cli_cancel\\.cpp$"
    "app_exe_directory\\.cpp$"
    "app_storage\\.cpp$"
    "pmbackup\\.cpp$"
    "app_resolver\\.cpp$"
    "system_browser\\.cpp$")
  list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "${_drop}")
endforeach()

# Android has no libsodium, libmagic, or Win32 security backends. Probe is
# stubbed in the Android host. URI parsing still needs Boost, fetched by the app.
if(ANDROID)
  foreach(_drop IN ITEMS
      "storage[/\\\\]secure_storage\\.cpp$"
      "storage[/\\\\]secure_storage_win\\.cpp$"
      "storage[/\\\\]asset_bundle\\.cpp$"
      "security[/\\\\]ToolIdentity\\.cpp$"
      "media[/\\\\]probe\\.cpp$"
      "[/\\\\]win[/\\\\]")
    list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "${_drop}")
  endforeach()
endif()

# Host call sites. They keep the settings store and CLI registration headers.
foreach(_drop IN ITEMS
    "security[/\\\\]cli\\.cpp$"
    "security[/\\\\]cli_info\\.cpp$"
    "security[/\\\\]consent_surface\\.cpp$"
    "security[/\\\\]ConsentDelegateRegistry\\.cpp$"
    "security[/\\\\]ui[/\\\\]win[/\\\\]ConsentDlg\\.cpp$"
    "security[/\\\\]ui[/\\\\]win[/\\\\]ConsentDlg_i18n\\.cpp$"
    "security[/\\\\]shim[/\\\\]pm_sb_shim\\.cpp$"
    "cli[/\\\\]cli_command_tree_doc\\.cpp$")
  list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "${_drop}")
endforeach()

# A sibling that only needs paths, strings, and process helpers. Net, libmagic,
# and libsodium units stay out until that parent fetches Boost, curl, and sodium.
option(PM_COMMONS_LEAN "Skip net, media probe, and libsodium translation units" OFF)
if(PM_COMMONS_LEAN)
  foreach(_drop IN ITEMS
      "net[/\\\\]url_fetch\\.cpp$"
      "media[/\\\\]probe\\.cpp$"
      "storage[/\\\\]secure_storage\\.cpp$"
      "storage[/\\\\]asset_bundle\\.cpp$"
      "security[/\\\\]ToolIdentity\\.cpp$")
    list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "${_drop}")
  endforeach()
endif()

option(PM_COMMONS_HOST_SINGLETONS "Host compiles host/services.cpp once per process" OFF)
if(PM_COMMONS_HOST_SINGLETONS)
  list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "host[/\\\\]services\\.cpp$")
endif()

# The profile TUs stay on the host targets. tanit-security compiles the Windows
# store with FEATURE_COMMAND_IPC_NEXT=0; pm-media compiles it with the app flags.
# file_store.cpp is the Store interface and is part of this library.
list(FILTER PM_COMMONS_SOURCES EXCLUDE REGEX "settings[/\\\\].*\\.cpp$")
set(_PM_COMMONS_FILE_STORE "${CMAKE_CURRENT_SOURCE_DIR}/src/settings/file_store.cpp")
if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR AND EXISTS "${_PM_COMMONS_FILE_STORE}")
  list(APPEND PM_COMMONS_SOURCES "${_PM_COMMONS_FILE_STORE}")
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
      _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING=1
      NOMINMAX
      _WIN32_WINNT=0x0A00)
    target_compile_options(pm-commons-lib PRIVATE /W3 /utf-8 /EHsc)
  else()
    target_compile_options(pm-commons-lib PRIVATE -Wall -Wextra)
  endif()
  # file_store.cpp includes the profile header, which still includes host layout types.
  if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    target_include_directories(pm-commons-lib PRIVATE "${CMAKE_SOURCE_DIR}/src")
    target_compile_definitions(pm-commons-lib PRIVATE POLYMECH_STATIC_BUILD=1)
  endif()
  # Host facts arrive through host/services.hpp. The settings store stays on the host.
  if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    if(TARGET Boost::url)
      target_link_libraries(pm-commons-lib PUBLIC Boost::url Boost::asio)
    endif()
    if(TARGET CURL::libcurl)
      target_link_libraries(pm-commons-lib PUBLIC CURL::libcurl)
    endif()
    if(TARGET nlohmann_json::nlohmann_json)
      target_link_libraries(pm-commons-lib PUBLIC nlohmann_json::nlohmann_json)
    endif()
    if(picosha2_SOURCE_DIR)
      target_include_directories(pm-commons-lib PRIVATE "${picosha2_SOURCE_DIR}")
    endif()
    if(TARGET pranav_glob)
      target_link_libraries(pm-commons-lib PUBLIC pranav_glob)
    endif()
    if(TARGET logger)
      target_link_libraries(pm-commons-lib PUBLIC logger)
    endif()
    if(TARGET pm-libmagic)
      target_link_libraries(pm-commons-lib PUBLIC pm-libmagic)
    endif()
    if(TARGET sodium)
      target_link_libraries(pm-commons-lib PUBLIC sodium)
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
    foreach(_feat IN ITEMS
        FEATURE_INSTALLER_VFS
        FEATURE_INSTALLER_SHELL
        FEATURE_INSTALLER_EXTRACT
        FEATURE_WINDOWS_GPO
        FEATURE_PLUGINS
        FEATURE_SECURE_STORAGE
        FEATURE_SECURE_STORAGE_WIN_HELLO
        FEATURE_SECURITY_AUDIT_LOG
        FEATURE_SECURITY_GATEWAY
        FEATURE_SECURITY_SANDBOX
        FEATURE_SECURITY_WIN_ACL
        FEATURE_SECURITY_CRYPTO_WIN_DPAPI
        FEATURE_ANTI_HACKING)
      if(DEFINED ${_feat})
        if(${_feat})
          target_compile_definitions(pm-commons-lib PRIVATE ${_feat}=1)
        else()
          target_compile_definitions(pm-commons-lib PRIVATE ${_feat}=0)
        endif()
      endif()
    endforeach()
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
