include_directories(${CMAKE_CURRENT_LIST_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xformats.cmake)

set(XSCANENGINE_SOURCES
    ${XFORMATS_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xscanengine.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xscanengine.h
)
