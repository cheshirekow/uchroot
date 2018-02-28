set(uchroot_py_files __init__.py __main__.py dump_constants.py)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/uchroot_format.stamp
                   COMMAND autopep8 -i ${uchroot_py_files}
                   COMMAND python -Bm cmake_format -i CMakeLists.txt
                           doc/CMakeLists.txt
                   COMMAND touch
                           ${CMAKE_CURRENT_BINARY_DIR}/uchroot_format.stamp
                   DEPENDS ${uchroot_py_files}
                   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(uchroot_format
                  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/uchroot_format.stamp)
add_dependencies(format uchroot_format)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/uchroot_lint.stamp
                   COMMAND pylint ${uchroot_py_files}
                   COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/uchroot_lint.stamp
                   DEPENDS ${uchroot_py_files}
                   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(uchroot_lint
                  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/uchroot_lint.stamp)

# NOTE(josh): format before lint-check, avoid formatting lint
add_dependencies(uchroot_lint uchroot_format)
add_dependencies(lint uchroot_lint)

add_subdirectory(doc)
