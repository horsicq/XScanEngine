include_directories(${CMAKE_CURRENT_LIST_DIR})

if (NOT DEFINED SCANITEM_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/scanitem.cmake)
    set(XSCANWIDGETS_SOURCES ${XSCANWIDGETS_SOURCES} ${SCANITEM_SOURCES})
endif()

if (NOT DEFINED XDIALOGPROCESS_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../FormatDialogs/xdialogprocess.cmake)
    set(XSCANWIDGETS_SOURCES ${XSCANWIDGETS_SOURCES} ${XDIALOGPROCESS_SOURCES})
endif()

set(XSCANWIDGETS_SOURCES
    ${XSCANWIDGETS_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xscansortwidget.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xscansortwidget.h
    ${CMAKE_CURRENT_LIST_DIR}/xscansortwidget.ui
)
