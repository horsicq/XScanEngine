INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD
INCLUDEPATH += $$PWD/modules
DEPENDPATH += $$PWD/modules

XCONFIG += use_dex
XCONFIG += use_pdf
XCONFIG += use_archive

HEADERS += \
    $$PWD/scanitem.h \
    $$PWD/scanitemmodel.h \
    $$PWD/xscanengine.h \
    $$PWD/modules/amiga_script.h \
    $$PWD/modules/atarist_script.h \
    $$PWD/modules/archive_script.h \
    $$PWD/modules/binary_script.h \
    $$PWD/modules/com_script.h \
    $$PWD/modules/dos16m_script.h \
    $$PWD/modules/dos4g_script.h \
    $$PWD/modules/elf_script.h \
    $$PWD/modules/le_script.h \
    $$PWD/modules/lx_script.h \
    $$PWD/modules/mach_script.h \
    $$PWD/modules/msdos_script.h \
    $$PWD/modules/ne_script.h \
    $$PWD/modules/pe_script.h \
    $$PWD/modules/zip_script.h \
    $$PWD/modules/jar_script.h \
    $$PWD/modules/apk_script.h \
    $$PWD/modules/ipa_script.h \
    $$PWD/modules/dex_script.h \
    $$PWD/modules/npm_script.h \
    $$PWD/modules/rar_script.h \
    $$PWD/modules/iso9660_script.h \
    $$PWD/modules/machofat_script.h \
    $$PWD/modules/javaclass_script.h \
    $$PWD/modules/pdf_script.h \
    $$PWD/modules/cfbf_script.h \
    $$PWD/modules/jpeg_script.h \
    $$PWD/modules/png_script.h \
    $$PWD/modules/image_script.h

SOURCES += \
    $$PWD/scanitem.cpp \
    $$PWD/scanitemmodel.cpp \
    $$PWD/xscanengine.cpp \
    $$PWD/modules/amiga_script.cpp \
    $$PWD/modules/atarist_script.cpp \
    $$PWD/modules/archive_script.cpp \
    $$PWD/modules/binary_script.cpp \
    $$PWD/modules/com_script.cpp \
    $$PWD/modules/dos16m_script.cpp \
    $$PWD/modules/dos4g_script.cpp \
    $$PWD/modules/elf_script.cpp \
    $$PWD/modules/le_script.cpp \
    $$PWD/modules/lx_script.cpp \
    $$PWD/modules/mach_script.cpp \
    $$PWD/modules/msdos_script.cpp \
    $$PWD/modules/ne_script.cpp \
    $$PWD/modules/pe_script.cpp \
    $$PWD/modules/zip_script.cpp \
    $$PWD/modules/jar_script.cpp \
    $$PWD/modules/apk_script.cpp \
    $$PWD/modules/ipa_script.cpp \
    $$PWD/modules/dex_script.cpp \
    $$PWD/modules/npm_script.cpp \
    $$PWD/modules/rar_script.cpp \
    $$PWD/modules/iso9660_script.cpp \
    $$PWD/modules/machofat_script.cpp \
    $$PWD/modules/javaclass_script.cpp \
    $$PWD/modules/pdf_script.cpp \
    $$PWD/modules/cfbf_script.cpp \
    $$PWD/modules/jpeg_script.cpp \
    $$PWD/modules/png_script.cpp \
    $$PWD/modules/image_script.cpp

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/../Formats/xformats.pri)
}

!contains(XCONFIG, xarchives) {
    XCONFIG += xarchives
    include($$PWD/../XArchive/xarchives.pri)
}

!contains(XCONFIG, xstaticunpacker) {
    XCONFIG += xstaticunpacker
    include($$PWD/../XStaticUnpacker/xstaticunpacker.pri)
}

!contains(XCONFIG, xdex) {
    XCONFIG += xdex
    include($$PWD/../XDEX/xdex.pri)
}

!contains(XCONFIG, xoptions) {
    XCONFIG += xoptions
    include($$PWD/../XOptions/xoptions.pri)
}

!contains(XCONFIG, xdisasmcore) {
    XCONFIG += xdisasmcore
    include($$PWD/../XDisasmCore/xdisasmcore.pri)
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/xscanengine.cmake
