INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xscansortwidget.h \
    $$PWD/xscanengineoptionswidget.h

SOURCES += \
    $$PWD/xscansortwidget.cpp \
    $$PWD/xscanengineoptionswidget.cpp

FORMS += \
    $$PWD/xscansortwidget.ui \
    $$PWD/xscanengineoptionswidget.ui

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
