INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xscanengineconsole.h

SOURCES += \
    $$PWD/xscanengineconsole.cpp

!contains(XCONFIG, xscanengine) {
    XCONFIG += xscanengine
    include($$PWD/xscanengine.pri)
}

!contains(XCONFIG, xfmodel) {
    XCONFIG += xfmodel
    include($$PWD/../Formats/xfmodel.pri)
}

DISTFILES += \
    $$PWD/xscanengineconsole.cmake
