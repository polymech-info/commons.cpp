# Sibling entry for a host tree that keeps packages/commons.cpp next to
# packages/audio.cpp and packages/video.cpp.
# A standalone checkout of audio or video does not include this file.

function(pm_commons_add_sibling binary_dir)
  if(TARGET pm-commons-lib)
    return()
  endif()
  get_filename_component(_pm_commons_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
  add_subdirectory("${_pm_commons_dir}" "${binary_dir}" EXCLUDE_FROM_ALL)
endfunction()
