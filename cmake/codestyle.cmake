# porcelain for format and lint rules

# Create format and lint rules for module files
#
# usage:
# format_and_lint(module
#                 bar.h bar.cc
#                 CMAKE CMakeLists.txt test/CMakeLists.txt
#                 CC foo.h foo.cc
#                 PY foo.py)
#
# Will create rules `${module}_lint` and `${module}_format` using the standard
# code formatters and lint checkers for the appropriate language. These
# tools are:
#
# CMAKE:
#   formatter: cmake-format
#
# CPP:
#   formatter: clang-format
#   linter: cpplint
#
# PYTHON:
#   formatter: autopep8
#   linter: pylint
#
function(format_and_lint module)
  set(cmake_files_)
  set(cc_files_)
  set(py_files_)
  set(unknown_files_)
  set(state_ "AUTO")

  foreach(arg ${ARGN})
    # assign by filename
    if(state_ STREQUAL "AUTO")
      if(arg STREQUAL "CMAKE" OR arg STREQUAL "CC" OR arg STREQUAL "PY")
        set(state_ SPECIFIC)
        string(TOLOWER ${arg} typename_)
        set(active_list_ ${typename}_files_)
      else()
        if(arg MATCHES ".*\.cmake" OR arg MATCHES ".*CMakeLists.txt")
          list(APPEND cmake_files_ ${arg})
        elseif(arg MATCHES ".*\.py")
          list(APPEND py_files_ ${arg})
        elseif(arg MATCHES ".*\.(cc|h)")
          list(APPEND cc_files_ ${arg})
        else()
          list(APPEND unknown_files_ ${arg})
        endif()
      endif()
    elseif(state_ STREQUAL "SPECIFIC")
      if(arg STREQUAL "CMAKE" OR arg STREQUAL "CC" OR arg STREQUAL "PY")
        string(TOLOWER ${arg} typename_)
        set(active_list_ ${typename}_files_)
      else()
        list(APPEND ${active_list_} ${arg})
      endif()
    endif()
  endforeach()

  set(fmtcmds_)
  set(depfiles_)
  if(cmake_files_)
    list(APPEND fmtcmds_ COMMAND python -Bm cmake_format -i ${cmake_files_})
    list(APPEND depfiles_ ${cmake_files_})
  endif()
  if(cc_files_)
    list(APPEND fmtcmds_ COMMAND clang-format -style file -i ${cc_files_})
    list(APPEND lntcmds_ COMMAND cpplint ${cc_files_})
    list(APPEND depfiles_ ${cc_files_})
  endif()
  if(py_files_)
    list(APPEND fmtcmds_ COMMAND autopep8 -i ${py_files_})
    list(APPEND lntcmds_ COMMAND pylint ${py_files_})
    list(APPEND depfiles_ ${py_files_})
  endif()

  set(fmtstamp_ ${CMAKE_CURRENT_BINARY_DIR}/${module}_format.stamp)
  add_custom_command(OUTPUT ${fmtstamp_}
                     ${fmtcmds_}
                     COMMAND touch ${fmtstamp_}
                     DEPENDS ${depfiles_}
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
  add_custom_target(${module}_format DEPENDS ${fmtstamp_})
  add_dependencies(format ${module}_format)

  set(lntstamp_ ${CMAKE_CURRENT_BINARY_DIR}/${module}_lint.stamp)
  add_custom_command(OUTPUT ${lntstamp_}
                     ${lntcmds_}
                     COMMAND touch ${lntstamp_}
                     DEPENDS ${depfiles_}
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
  add_custom_target(${module}_lint DEPENDS ${lntstamp_})
  add_dependencies(lint ${module}_lint)

  if(unknown_files_)
    string(REPLACE ";" "\n  " filelist_ "${unknown_files_}")
    message(WARNING
      "The following files will not be linted/formatted because their"
      " extension is not recognized: \n  ${filelist_}")
  endif()
endfunction()