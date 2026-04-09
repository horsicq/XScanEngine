include_directories(${CMAKE_CURRENT_LIST_DIR})

if (NOT DEFINED SCANITEM_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/scanitem.cmake)
    set(XSCANWIDGETS_SOURCES ${XSCANWIDGETS_SOURCES} ${SCANITEM_SOURCES})
endif()

if (NOT DEFINED XSCANENGINE_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/xscanengine.cmake)
    set(XSCANWIDGETS_SOURCES ${XSCANWIDGETS_SOURCES} ${XSCANENGINE_SOURCES})
endif()

if (NOT DEFINED XDIALOGPROCESS_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../FormatDialogs/xdialogprocess.cmake)
    set(XSCANWIDGETS_SOURCES ${XSCANWIDGETS_SOURCES} ${XDIALOGPROCESS_SOURCES})
endif()

if (NOT DEFINED XOPTIONSWIDGET_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XOptions/xoptionswidget.cmake)
    set(XSCANWIDGETS_SOURCES ${XSCANWIDGETS_SOURCES} ${XOPTIONSWIDGET_SOURCES})
endif()

if (NOT DEFINED XCOMBOBOXEX_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../Controls/xcomboboxex.cmake)
    set(XSCANWIDGETS_SOURCES ${XSCANWIDGETS_SOURCES} ${XCOMBOBOXEX_SOURCES})
endif()

set(XSCANWIDGETS_SOURCES
    ${XSCANWIDGETS_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xscansortwidget.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xscansortwidget.h
    ${CMAKE_CURRENT_LIST_DIR}/xscansortwidget.ui
    ${CMAKE_CURRENT_LIST_DIR}/xscanengineoptionswidget.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xscanengineoptionswidget.h
    ${CMAKE_CURRENT_LIST_DIR}/xscanengineoptionswidget.ui
    ${CMAKE_CURRENT_LIST_DIR}/xscanenginewidget.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xscanenginewidget.h
    ${CMAKE_CURRENT_LIST_DIR}/xscanenginewidget.ui
    # ${CMAKE_CURRENT_LIST_DIR}/dialogxscanenginedirectory.cpp
    # ${CMAKE_CURRENT_LIST_DIR}/dialogxscanenginedirectory.h
    # ${CMAKE_CURRENT_LIST_DIR}/dialogxscanenginedirectory.ui
    # ${CMAKE_CURRENT_LIST_DIR}/dialogxscanengineelapsed.cpp
    # ${CMAKE_CURRENT_LIST_DIR}/dialogxscanengineelapsed.h
    # ${CMAKE_CURRENT_LIST_DIR}/dialogxscanengineelapsed.ui
)
