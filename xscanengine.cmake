include_directories(${CMAKE_CURRENT_LIST_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xformats.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XExtractor/xextractor.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XDEX/xdex.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XPDF/xpdf.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XArchive/xarchives.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XOptions/xoptions.cmake)

set(XSCANENGINE_SOURCES
    ${XFORMATS_SOURCES}
    ${XDEX_SOURCES}
    ${XPDF_SOURCES}
    ${XARCHIVES_SOURCES}
    ${XFORMATS_SOURCES}
    ${XOPTIONS_SOURCES}
    ${XEXTRACTOR_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xscanengine.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xscanengine.h
    ${CMAKE_CURRENT_LIST_DIR}/scanitem.cpp
    ${CMAKE_CURRENT_LIST_DIR}/scanitem.h
    ${CMAKE_CURRENT_LIST_DIR}/scanitemmodel.cpp
    ${CMAKE_CURRENT_LIST_DIR}/scanitemmodel.h
)
