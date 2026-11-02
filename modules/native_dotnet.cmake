# The shared, allocation-free CIL decoder needs no xxfclib runtime library.
include_guard(DIRECTORY)
set(_xscan_dotnet_root "${CMAKE_CURRENT_LIST_DIR}/../../xxfclib")
include_directories("${_xscan_dotnet_root}/include")
set(XSCAN_DOTNET_SOURCES
    "${_xscan_dotnet_root}/src/formats/executable/dotnet/xx_dotnet_cil.c"
    "${CMAKE_CURRENT_LIST_DIR}/native_dotnet_helpers.h")
set_property(SOURCE
    "${_xscan_dotnet_root}/src/formats/executable/dotnet/xx_dotnet_cil.c"
    "${CMAKE_CURRENT_LIST_DIR}/pe_script.cpp"
    APPEND PROPERTY COMPILE_DEFINITIONS XXFC_STATIC)
