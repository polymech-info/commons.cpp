# Logger used to be packages/logger. The sources live in src/logging.
# This target stays named `logger` so existing link lines keep working.
include(FetchContent)
if(NOT TARGET spdlog::spdlog)
  FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.15.1
    GIT_SHALLOW    TRUE
  )
  FetchContent_MakeAvailable(spdlog)
endif()

if(NOT TARGET logger)
  add_library(logger STATIC
    "${CMAKE_CURRENT_LIST_DIR}/../src/logging/logger.cpp")
  target_include_directories(logger
    PUBLIC "${CMAKE_CURRENT_LIST_DIR}/../src")
  target_link_libraries(logger PUBLIC spdlog::spdlog)
  target_compile_features(logger PUBLIC cxx_std_20)
  if(MSVC)
    target_compile_options(logger PRIVATE /W3 /utf-8 /EHsc)
    target_compile_definitions(logger PRIVATE
      _CRT_SECURE_NO_WARNINGS
      NOMINMAX
      _WIN32_WINNT=0x0A00)
  endif()
endif()
