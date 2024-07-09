INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

XCONFIG += use_dex
XCONFIG += use_pdf
XCONFIG += use_archive

HEADERS += \
    $$PWD/xscanengine.h

SOURCES += \
    $$PWD/xscanengine.cpp

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/../Formats/xformats.pri)
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/xscanengine.cmake
