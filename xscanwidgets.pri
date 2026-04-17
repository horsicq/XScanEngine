INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xscansortwidget.h \
    $$PWD/xscanengineoptionswidget.h \
    $$PWD/dialogxscansort.h \
    $$PWD/xscanenginewidget.h \
    $$PWD/dialogxscanenginedirectory.h
    # $$PWD/dialogxscanengineelapsed.h

SOURCES += \
    $$PWD/xscansortwidget.cpp \
    $$PWD/xscanengineoptionswidget.cpp \
    $$PWD/dialogxscansort.cpp \
    $$PWD/xscanenginewidget.cpp \
    $$PWD/dialogxscanenginedirectory.cpp
    # $$PWD/dialogxscanengineelapsed.cpp

FORMS += \
    $$PWD/xscansortwidget.ui \
    $$PWD/xscanengineoptionswidget.ui \
    $$PWD/dialogxscansort.ui \
    $$PWD/xscanenginewidget.ui \
    $$PWD/dialogxscanenginedirectory.ui
    # $$PWD/dialogxscanengineelapsed.ui

!contains(XCONFIG, xscanengine) {
    XCONFIG += xscanengine
    include($$PWD/xscanengine.pri)
}

!contains(XCONFIG, xdialogprocess) {
    XCONFIG += xdialogprocess
    include($$PWD/../FormatDialogs/xdialogprocess.pri)
}

!contains(XCONFIG, dialogtextinfo) {
    XCONFIG += dialogtextinfo
    include($$PWD/../FormatDialogs/dialogtextinfo.pri)

DISTFILES += \
    $$PWD/xscanwidgets.cmake
