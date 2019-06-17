set(uchroot_py_files #
    __init__.py __main__.py dump_constants.py)

format_and_lint(uchroot #
                ${uchroot_py_files}
                CMakeLists.txt
                doc/CMakeLists.txt)

add_subdirectory(doc)
