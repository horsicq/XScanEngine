include_directories(${CMAKE_CURRENT_LIST_DIR})

if (NOT DEFINED XFORMATS_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xformats.cmake)
    set(XSCANENGINE_SOURCES ${XSCANENGINE_SOURCES} ${XFORMATS_SOURCES})
endif()
if (NOT DEFINED XEXTRACTOR_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XExtractor/xextractor.cmake)
    set(XSCANENGINE_SOURCES ${XSCANENGINE_SOURCES} ${XEXTRACTOR_SOURCES})
endif()


include(${CMAKE_CURRENT_LIST_DIR}/../XDEX/xdex.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XPDF/xpdf.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XArchive/xarchives.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XOptions/xoptions.cmake)

set(XSCANENGINE_SOURCES
    ${XSCANENGINE_SOURCES}
    ${XFORMATS_SOURCES}
    ${XEXTRACTOR_SOURCES}
    ${XDEX_SOURCES}
    ${XPDF_SOURCES}
    ${XARCHIVES_SOURCES}
    ${XFORMATS_SOURCES}
    ${XOPTIONS_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xscanengine.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xscanengine.h
    ${CMAKE_CURRENT_LIST_DIR}/scanitem.cpp
    ${CMAKE_CURRENT_LIST_DIR}/scanitem.h
    ${CMAKE_CURRENT_LIST_DIR}/scanitemmodel.cpp
    ${CMAKE_CURRENT_LIST_DIR}/scanitemmodel.h
)
