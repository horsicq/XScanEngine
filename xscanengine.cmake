include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/modules)

if (NOT DEFINED XFORMATS_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xformats.cmake)
    set(XSCANENGINE_SOURCES ${XSCANENGINE_SOURCES} ${XFORMATS_SOURCES})
endif()
if (NOT DEFINED XDEX_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XDEX/xdex.cmake)
    set(XSCANENGINE_SOURCES ${XSCANENGINE_SOURCES} ${XDEX_SOURCES})
endif()
if (NOT DEFINED XPDF_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XPDF/xpdf.cmake)
    set(XSCANENGINE_SOURCES ${XSCANENGINE_SOURCES} ${XPDF_SOURCES})
endif()
if (NOT DEFINED XARCHIVES_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XArchive/xarchives.cmake)
    set(XSCANENGINE_SOURCES ${XSCANENGINE_SOURCES} ${XARCHIVES_SOURCES})
endif()
if (NOT DEFINED XSTATICUNPACKER_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XStaticUnpacker/xstaticunpacker.cmake)
    set(XSCANENGINE_SOURCES ${XSCANENGINE_SOURCES} ${XSTATICUNPACKER_SOURCES})
endif()
if (NOT DEFINED XOPTIONS_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XOptions/xoptions.cmake)
    set(XSCANENGINE_SOURCES ${XSCANENGINE_SOURCES} ${XOPTIONS_SOURCES})
endif()
if (NOT DEFINED XDISASMCORE_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XDisasmCore/xdisasmcore.cmake)
    set(XSCANENGINE_SOURCES ${XSCANENGINE_SOURCES} ${XDISASMCORE_SOURCES})
endif()

set(XSCANENGINE_SOURCES
    ${XSCANENGINE_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xscanengine.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xscanengine.h
    ${CMAKE_CURRENT_LIST_DIR}/scanitem.cpp
    ${CMAKE_CURRENT_LIST_DIR}/scanitem.h
    ${CMAKE_CURRENT_LIST_DIR}/scanitemmodel.cpp
    ${CMAKE_CURRENT_LIST_DIR}/scanitemmodel.h

    ${CMAKE_CURRENT_LIST_DIR}/modules/amiga_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/amiga_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/archive_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/archive_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/binary_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/binary_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/com_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/com_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/dos16m_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/dos16m_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/dos4g_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/dos4g_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/elf_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/elf_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/le_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/le_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/lx_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/lx_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/mach_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/mach_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/msdos_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/msdos_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/ne_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/ne_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/pe_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/pe_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/zip_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/zip_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/jar_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/jar_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/apk_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/apk_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/ipa_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/ipa_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/dex_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/dex_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/npm_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/npm_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/rar_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/rar_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/machofat_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/machofat_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/javaclass_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/javaclass_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/pdf_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/pdf_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/cfbf_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/cfbf_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/jpeg_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/jpeg_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/png_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/png_script.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/image_script.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/image_script.h
)


