INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xscansortwidget.h

SOURCES += \
    $$PWD/xscansortwidget.cpp

FORMS += \
    $$PWD/xscansortwidget.ui

!contains(XCONFIG, xscanengine) {
    XCONFIG += xscanengine
    include($$PWD/xscanengine.pri)
}

!contains(XCONFIG, xdialogprocess) {
    XCONFIG += xdialogprocess
    include($$PWD/../FormatDialogs/xdialogprocess.pri)
}

DISTFILES += \
    $$PWD/xscanwidgets.cmake
