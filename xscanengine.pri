INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

XCONFIG += use_dex
XCONFIG += use_pdf
XCONFIG += use_archive

HEADERS += \
    $$PWD/scanitem.h \
    $$PWD/scanitemmodel.h \
    $$PWD/xscanengine.h

SOURCES += \
    $$PWD/scanitem.cpp \
    $$PWD/scanitemmodel.cpp \
    $$PWD/xscanengine.cpp

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/../Formats/xformats.pri)
}

!contains(XCONFIG, xarchives) {
    XCONFIG += xarchives
    include($$PWD/../XArchive/xarchives.pri)
}

!contains(XCONFIG, xdex) {
    XCONFIG += xdex
    include($$PWD/../XDEX/xdex.pri)
}

!contains(XCONFIG, xoptions) {
    XCONFIG += xoptions
    include($$PWD/../XOptions/xoptions.pri)
}

!contains(XCONFIG, xextractor) {
    XCONFIG += xextractor
    include($$PWD/../XExtractor/xextractor.pri)
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/xscanengine.cmake
