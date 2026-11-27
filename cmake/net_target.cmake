# Optional pm-commons-net (pinned_http.cpp). Safe to call after add_subdirectory(commons)
# when CURL::libcurl may have appeared later in the same configure, or from commons itself.

function(pm_commons_add_net_target)
  if(TARGET pm-commons-net)
    return()
  endif()
  if(NOT TARGET CURL::libcurl)
    return()
  endif()
  if(DEFINED PM_COMMONS_WITH_NET AND NOT PM_COMMONS_WITH_NET)
    return()
  endif()

  get_filename_component(_pm_commons_root
    "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)

  add_library(pm-commons-net STATIC
    "${_pm_commons_root}/src/net/pinned_http.cpp")
  target_include_directories(pm-commons-net
    PUBLIC
      $<BUILD_INTERFACE:${_pm_commons_root}/include>
      $<INSTALL_INTERFACE:include>
    PRIVATE
      "${_pm_commons_root}/src")
  target_compile_features(pm-commons-net PUBLIC cxx_std_20)
  target_link_libraries(pm-commons-net PUBLIC CURL::libcurl)
  if(TARGET pm-commons-lib)
    target_link_libraries(pm-commons-net PUBLIC pm-commons-lib)
  endif()
  if(MSVC)
    target_compile_definitions(pm-commons-net PRIVATE
      _CRT_SECURE_NO_WARNINGS
      NOMINMAX
      _WIN32_WINNT=0x0A00)
    target_compile_options(pm-commons-net PRIVATE /W3 /utf-8 /EHsc)
  else()
    target_compile_options(pm-commons-net PRIVATE -Wall -Wextra)
  endif()
  if(NOT TARGET pm::commons-net)
    add_library(pm::commons-net ALIAS pm-commons-net)
  endif()
endfunction()