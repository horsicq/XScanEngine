/* Copyright (c) 2024-2025 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "xscanengine.h"

bool _sortItems(const XScanEngine::SCANSTRUCT &v1, const XScanEngine::SCANSTRUCT &v2)
{
    bool bResult = false;

    bResult = (v1.nPrio < v2.nPrio);

    return bResult;
}

XScanEngine::XScanEngine(QObject *pParent) : QObject(pParent)
{
}

XScanEngine::XScanEngine(const XScanEngine &other)
{
    this->g_sFileName = other.g_sFileName;
    this->g_sDirectoryName = other.g_sDirectoryName;
    this->g_pDevice = other.g_pDevice;
    this->g_pData = other.g_pData;
    this->g_nDataSize = other.g_nDataSize;
    this->g_pScanOptions = other.g_pScanOptions;
    this->g_pScanResult = other.g_pScanResult;
    this->g_scanType = other.g_scanType;
    this->g_pPdStruct = other.g_pPdStruct;
}

void XScanEngine::setData(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct)
{
    g_sFileName = sFileName;
    g_pScanOptions = pScanOptions;
    g_pScanResult = pScanResult;
    g_pPdStruct = pPdStruct;

    g_scanType = SCAN_TYPE_FILE;
}

void XScanEngine::setData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct)
{
    g_pDevice = pDevice;
    g_pScanOptions = pOptions;
    g_pScanResult = pScanResult;
    g_pPdStruct = pPdStruct;

    g_scanType = SCAN_TYPE_DEVICE;
}

void XScanEngine::setData(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct)
{
    g_pData = pData;
    g_nDataSize = nDataSize;
    g_pScanOptions = pOptions;
    g_pScanResult = pScanResult;
    g_pPdStruct = pPdStruct;

    g_scanType = SCAN_TYPE_MEMORY;
}

void XScanEngine::setData(const QString &sDirectoryName, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    g_sDirectoryName = sDirectoryName;
    g_pScanOptions = pOptions;
    g_pPdStruct = pPdStruct;

    g_scanType = SCAN_TYPE_DIRECTORY;
}

QString XScanEngine::createTypeString(const SCANSTRUCT *pScanStruct)
{
    QString sResult;

    if (pScanStruct->parentId.filePart != XBinary::FILEPART_HEADER) {
        sResult += XBinary::recordFilePartIdToString(pScanStruct->parentId.filePart);

        if (pScanStruct->parentId.sVersion != "") {
            sResult += QString("(%1)").arg(pScanStruct->parentId.sVersion);
        }

        if (pScanStruct->parentId.sInfo != "") {
            sResult += QString("[%1]").arg(pScanStruct->parentId.sInfo);
        }

        sResult += ": ";
    }

    sResult += XBinary::fileTypeIdToString(pScanStruct->id.fileType);

    if ((pScanStruct->parentId.filePart != XBinary::FILEPART_HEADER) && (pScanStruct->parentId.filePart != XBinary::FILEPART_ARCHIVERECORD)) {
        sResult += QString("[%1=0x%2,%3=0x%4]")
                       .arg(tr("Offset"), XBinary::valueToHexEx(pScanStruct->parentId.nOffset), tr("Size"), XBinary::valueToHexEx(pScanStruct->parentId.nSize));
    }

    return sResult;
}

XScanEngine::SCANSTRUCT XScanEngine::createHeaderScanStruct(const SCANSTRUCT *pScanStruct)
{
    SCANSTRUCT result = *pScanStruct;

    result.id.sUuid = XBinary::generateUUID();
    result.sType = "";
    result.sName = "";
    result.sVersion = "";
    result.sInfo = "";
    result.varInfo.clear();
    result.varInfo2.clear();
    result.globalColor = Qt::transparent;

    return result;
}

QString XScanEngine::createResultStringEx(SCAN_OPTIONS *pOptions, const SCANSTRUCT *pScanStruct)
{
    QString sResult;

    if (pScanStruct->bIsHeuristic) {
        sResult += "(Heur)";
    }

    if (pOptions->bShowType) {
        sResult += QString("%1: ").arg(pScanStruct->sType);
    }

    sResult += pScanStruct->sName;

    if ((pOptions->bShowVersion) && (pScanStruct->sVersion != "")) {
        sResult += QString("(%1)").arg(pScanStruct->sVersion);
    }

    if ((pOptions->bShowInfo) && (pScanStruct->sInfo != "")) {
        sResult += QString("[%1]").arg(pScanStruct->sInfo);
    }

    return sResult;
}

QString XScanEngine::createShortResultString(XScanEngine::SCAN_OPTIONS *pOptions, const SCAN_RESULT &scanResult)
{
    QString sResult;

    qint64 nNumberOfRecords = scanResult.listRecords.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        SCANSTRUCT scanStruct = scanResult.listRecords.at(i);

        if (scanStruct.id.fileType != XBinary::FT_BINARY) {
            // sResult = createFullResultString2(&scanStruct);
            sResult = QString("%1: %2").arg(XBinary::fileTypeIdToString(scanStruct.id.fileType), createResultStringEx(pOptions, &scanStruct));
            break;
        } else if (!scanStruct.bIsUnknown) {
            sResult = createResultStringEx(pOptions, &scanStruct);
            break;
        }
    }

    return sResult;
}

Qt::GlobalColor XScanEngine::typeToColor(const QString &sType) {
    static const QMap<QString, Qt::GlobalColor> colorMap = {
        {"installer", Qt::blue},
        {"sfx", Qt::blue},
        {"archive", Qt::blue},
        {"pe tool", Qt::green},
        {"apk tool", Qt::green},
        {"operation system", Qt::darkYellow},
        {"virtual machine", Qt::darkYellow},
        {"platform", Qt::darkYellow},
        {"dos extender", Qt::darkYellow},
        {"format", Qt::darkGreen},
        {"sign tool", Qt::darkMagenta},
        {"certificate", Qt::darkMagenta},
        {"licensing", Qt::darkMagenta},
        {"language", Qt::darkCyan},
        {"virus", Qt::darkRed},
        {"trojan", Qt::darkRed},
        {"malware", Qt::darkRed},
        {"debug", Qt::darkBlue},
        {"debug data", Qt::darkBlue}
    };

    QString _sType = sType.toLower().remove("~").remove("!");

    if (isProtection(_sType)) {
        return Qt::red;
    }

    return colorMap.value(_sType, Qt::transparent);
}

qint32 XScanEngine::typeToPrio(const QString &sType) {
    static const QMap<QString, qint32> priorityMap = {
        {"operation system", 10},
        {"virtual machine", 10},
        {"format", 12},
        {"platform", 14},
        {"dos extender", 14},
        {"linker", 20},
        {"compiler", 30},
        {"language", 40},
        {"library", 50},
        {"tool", 60},
        {"pe tool", 60},
        {"sign tool", 60},
        {"apk tool", 60},
        {"protector", 70},
        {"cryptor", 70},
        {"crypter", 70},
        {".net obfuscator", 80},
        {"apk obfuscator", 80},
        {"jar obfuscator", 80},
        {"dongle protection", 90},
        {"protection", 90},
        {"packer", 100},
        {".net compressor", 100},
        {"joiner", 110},
        {"sfx", 120},
        {"installer", 120},
        {"virus", 70},
        {"malware", 70},
        {"trojan", 70},
        {"debug data", 200},
        {"installer", 200}
    };

    QString _sType = sType.toLower().remove("~").remove("!");
    return priorityMap.value(_sType, 1000);
}

QString XScanEngine::translateType(const QString &sType)
{
    QString sResult;

    QString _sType = sType;
    bool bHeur = false;
    bool bAHeur = false;

    if (_sType.size() > 1) {
        if (_sType[0] == QChar('~')) {
            bHeur = true;
            _sType.remove(0, 1);
        }

        if (_sType[0] == QChar('!')) {
            bHeur = false;
            bAHeur = true;
            _sType.remove(0, 1);
        }
    }

    sResult = _translate(_sType);

    if (sResult.size()) {
        sResult[0] = sResult.at(0).toUpper();
    }

    if (bHeur) {
        sResult = QString("(Heur)%1").arg(sResult);
    } else if (bAHeur) {
        sResult = QString("(A-Heur)%1").arg(sResult);
    }

    return sResult;
}

QString XScanEngine::_translate(const QString &sString) {
    static const QMap<QString, QString> translationMap = {
        {"apk obfuscator", "APK obfuscator"},
        {"apk tool", "APK Tool"},
        {"archive", "Archive"},
        {"certificate", "Certificate"},
        {"compiler", "Compiler"},
        {"converter", "Converter"},
        {"crypter", "Crypter"},
        {"cryptor", "Cryptor"},
        {"data", "Data"},
        {"database", "Database"},
        {"debug data", "Debug data"},
        {"dongle protection", "Dongle protection"},
        {"dos extender", "DOS extender"},
        {"format", "Format"},
        {"generic", "Generic"},
        {"image", "Image"},
        {"installer", "Installer"},
        {"installer data", "Installer data"},
        {"jar obfuscator", "JAR obfuscator"},
        {"joiner", "Joiner"},
        {"language", "Language"},
        {"library", "Library"},
        {"linker", "Linker"},
        {".net compressor", ".NET compressor"},
        {".net obfuscator", ".NET obfuscator"},
        {"operation system", "Operation system"},
        {"overlay", "Overlay"},
        {"packer", "Packer"},
        {"pe tool", "PE Tool"},
        {"platform", "Platform"},
        {"player", "Player"},
        {"protection", "Protection"},
        {"protector", "Protector"},
        {"protector data", "Protector data"},
        {"sfx data", "SFX data"},
        {"sign tool", "Sign tool"},
        {"source code", "Source code"},
        {"stub", "Stub"},
        {"tool", "Tool"},
        {"virtual machine", "Virtual machine"},
        {"virus", "Virus"},
        {"trojan", "Trojan"},
        {"malware", "Malware"},
        {"package", "Package"},
        {"licensing", "Licensing"},
        {"rom", "ROM"}
    };

    QString sResult = translationMap.value(sString.toLower(), sString);

    if (sResult[0].isUpper()) {
        sResult[0] = sResult.at(0).toUpper();
    } else {
        sResult[0] = sResult.at(0).toLower();
    }

    return sResult;
}

void XScanEngine::sortRecords(QList<SCANSTRUCT> *pListRecords)
{
    std::sort(pListRecords->begin(), pListRecords->end(), _sortItems);
}

QString XScanEngine::getProtection(SCAN_OPTIONS *pScanOptions, QList<SCANSTRUCT> *pListRecords)
{
    QString sResult;

    qint32 nNumberOfRecords = pListRecords->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if (pListRecords->at(i).bIsProtection) {
            SCANSTRUCT scanStruct = pListRecords->at(i);
            sResult = createResultStringEx(pScanOptions, &scanStruct);
            break;
        }
    }

    return sResult;
}

bool XScanEngine::isProtection(const QString &sType)
{
    bool bResult = false;

    QString _sType = sType;
    _sType = _sType.toLower();

    if ((_sType == "protector") || (_sType == "apk obfuscator") || (_sType == "jar obfuscator") || (_sType == ".net obfuscator") || (_sType == ".net compressor") ||
        (_sType == "dongle protection") || (_sType == "joiner") || (_sType == "packer") || (_sType == "protection") || (_sType == "crypter") || (_sType == "cryptor")) {
        bResult = true;
    }

    return bResult;
}

bool XScanEngine::isScanable(const QSet<XBinary::FT> &stFT)
{
    return (stFT.contains(XBinary::FT_MSDOS) || stFT.contains(XBinary::FT_NE) || stFT.contains(XBinary::FT_LE) || stFT.contains(XBinary::FT_LX) ||
            stFT.contains(XBinary::FT_PE) || stFT.contains(XBinary::FT_ELF) || stFT.contains(XBinary::FT_MACHO) || stFT.contains(XBinary::FT_DEX) ||
            stFT.contains(XBinary::FT_ARCHIVE));
}

XScanEngine::SCAN_RESULT XScanEngine::scanDevice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};

    XScanEngine::SCANID parentId = {};
    parentId.fileType = XBinary::FT_UNKNOWN;

    if (pOptions->initFilePart == XBinary::FILEPART_UNKNOWN) {
        parentId.filePart = XBinary::FILEPART_HEADER;
    } else {
        parentId.filePart = pOptions->initFilePart;
    }

    scanProcess(pDevice, &result, 0, pDevice->size(), parentId, pOptions, true, pPdStruct);

    return result;
}

XScanEngine::SCAN_RESULT XScanEngine::scanFile(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};

    if (sFileName != "") {
        QFile file;
        file.setFileName(sFileName);

        if (file.open(QIODevice::ReadOnly)) {
            result = scanDevice(&file, pOptions, pPdStruct);
            file.close();
        }
    }

    return result;
}

XScanEngine::SCAN_RESULT XScanEngine::scanMemory(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};

    QBuffer buffer;

    buffer.setData(pData, nDataSize);

    if (buffer.open(QIODevice::ReadOnly)) {
        result = scanDevice(&buffer, pOptions, pPdStruct);

        buffer.close();
    }

    return result;
}

XScanEngine::SCAN_RESULT XScanEngine::scanSubdevice(QIODevice *pDevice, qint64 nOffset, qint64 nSize, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};

    if (XBinary::isOffsetAndSizeValid(pDevice, nOffset, nSize)) {
        SubDevice sd(pDevice, nOffset, nSize);

        if (sd.open(QIODevice::ReadOnly)) {
            result = scanDevice(&sd, pOptions, pPdStruct);

            sd.close();
        }
    }

    return result;
}

void XScanEngine::scanProcess(QIODevice *pDevice, SCAN_RESULT *pScanResult, qint64 nOffset, qint64 nSize, SCANID parentId, SCAN_OPTIONS *pScanOptions, bool bInit,
                              XBinary::PDSTRUCT *pPdStruct)
{
    XBinary::PDSTRUCT pdStructEmpty = {};

    if (!pPdStruct) {
        pdStructEmpty = XBinary::createPdStruct();
        pPdStruct = &pdStructEmpty;
    }

    QElapsedTimer *pScanTimer = nullptr;

    if (bInit) {
        pScanTimer = new QElapsedTimer;
        pScanTimer->start();
        pScanResult->sFileName = XBinary::getDeviceFileName(pDevice);
        pScanResult->nSize = nSize;
    }

    QIODevice *_pDevice = nullptr;
    SubDevice *pSd = nullptr;
    char *pBuffer = nullptr;
    QBuffer *bufDevice = nullptr;

    if ((nOffset == 0) && (pDevice->size() == nSize)) {
        _pDevice = pDevice;
    } else {
        pSd = new SubDevice(pDevice, nOffset, nSize);
        pSd->open(QIODevice::ReadOnly);
        _pDevice = pSd;
    }

    bool bMemory = false;

    if (pScanOptions->nBufferSize) {
        if (nSize <= pScanOptions->nBufferSize) {
            QBuffer *pBuffer = dynamic_cast<QBuffer *>(_pDevice);

            if (!pBuffer) {
                bMemory = true;
            }
        }
    }

    if (bMemory) {
        pBuffer = new char[nSize];

        XBinary::read_array(_pDevice, 0, pBuffer, nSize, pPdStruct);

        bufDevice = new QBuffer;

        bufDevice->setData(pBuffer, nSize);
        bufDevice->open(QIODevice::ReadOnly);

        bufDevice->setProperty("DeviceDirectory", XBinary::getDeviceDirectory(_pDevice));
        bufDevice->setProperty("DeviceFileBaseName", XBinary::getDeviceFileBaseName(_pDevice));
        bufDevice->setProperty("DeviceFileCompleteSuffix", XBinary::getDeviceFileCompleteSuffix(_pDevice));
        bufDevice->setProperty("DeviceFileSuffix", XBinary::getDeviceFileSuffix(_pDevice));

        _pDevice = bufDevice;
    }

    QSet<XBinary::FT> stFT = XFormats::getFileTypes(_pDevice, true, pPdStruct);
    QSet<XBinary::FT> stFTOriginal = stFT;

    if (bInit || (pScanOptions->fileType == XBinary::FT_BINARY)) {
        if (pScanOptions->fileType != XBinary::FT_UNKNOWN) {
            XBinary::filterFileTypes(&stFT, pScanOptions->fileType);
        }
    }

    if (pScanOptions->bIsAllTypesScan) {
        if (stFT.contains(XBinary::FT_PE32) || stFT.contains(XBinary::FT_PE64) || stFT.contains(XBinary::FT_LE) || stFT.contains(XBinary::FT_LX) ||
            stFT.contains(XBinary::FT_NE)) {
            _processDetect(0, pScanResult, _pDevice, parentId, XBinary::FT_MSDOS, pScanOptions, true, pPdStruct);
        }

        if (stFT.contains(XBinary::FT_APK) || stFT.contains(XBinary::FT_IPA)) {
            _processDetect(0, pScanResult, _pDevice, parentId, XBinary::FT_JAR, pScanOptions, true, pPdStruct);
            _processDetect(0, pScanResult, _pDevice, parentId, XBinary::FT_ZIP, pScanOptions, true, pPdStruct);
        }

        if (stFT.contains(XBinary::FT_JAR)) {
            _processDetect(0, pScanResult, _pDevice, parentId, XBinary::FT_ZIP, pScanOptions, true, pPdStruct);
        }

        if (stFT.contains(XBinary::FT_DOS4G)) {
            _processDetect(0, pScanResult, _pDevice, parentId, XBinary::FT_DOS16M, pScanOptions, true, pPdStruct);
        }
    }

    XScanEngine::SCANID scanIdMain = {};

    QMap<XBinary::FT, std::function<void()>> fileTypeMap = {
        {XBinary::FT_PE32,    [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_PE32, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_PE64,    [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_PE64, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_ELF32,   [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_ELF32, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_ELF64,   [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_ELF64, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_MACHO32, [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_MACHO32, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_MACHO64, [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_MACHO64, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_LX,      [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_LX, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_LE,      [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_LE, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_NE,      [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_NE, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_MSDOS,   [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_MSDOS, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_APK,     [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_APK, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_IPA,     [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_BINARY, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_JAR,     [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_JAR, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_ZIP,     [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_BINARY, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_DEX,     [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_DEX, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_NPM,     [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_NPM, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_MACHOFAT,[&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_MACHOFAT, pScanOptions, false, pPdStruct); }},
        {XBinary::FT_BWDOS16M,[&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_BWDOS16M, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_AMIGAHUNK,[&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_AMIGAHUNK, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_PDF,     [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_BINARY, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_RAR,     [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_BINARY, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_COM,     [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_COM, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_ARCHIVE, [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_BINARY, pScanOptions, true, pPdStruct); }},
        {XBinary::FT_BINARY,  [&]() { _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_BINARY, pScanOptions, true, pPdStruct); }}
    };

    for (const auto &fileType : fileTypeMap.keys()) {
        if (stFT.contains(fileType)) {
            fileTypeMap[fileType]();
            if (bInit) {
                pScanResult->ftInit = fileType;
            }
            return;
        }
    }

    if (pScanOptions->bIsRecursiveScan) {
        if (stFT.contains(XBinary::FT_PE32) || stFT.contains(XBinary::FT_PE64)) {
            XPE pe(_pDevice);

            if (pe.isValid()) {
                XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap(XBinary::MAPMODE_SECTIONS, pPdStruct);

                if (pe.isResourcesPresent()) {
                    QList<XPE::RESOURCE_RECORD> listResources = pe.getResources(&memoryMap, 10000, pPdStruct);

                    qint32 nNumberOfRecords = listResources.count();
                    qint32 nMaxCount = 20;
                    qint32 nCount = 0;

                    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
                    XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nNumberOfRecords);

                    for (qint32 i = 0; (i < nNumberOfRecords) && (!(pPdStruct->bIsStop)); i++) {
                        qint64 nResourceOffset = listResources.at(i).nOffset;
                        qint64 nResourceSize = listResources.at(i).nSize;

                        if (pe.checkOffsetSize(nResourceOffset, nResourceSize)) {
                            QSet<XBinary::FT> _stFT = XFormats::getFileTypes(_pDevice, nResourceOffset, nResourceSize, true, pPdStruct);

                            if (isScanable(_stFT)) {
                                if (nCount < nMaxCount) {
                                    XScanEngine::SCANID scanIdResource = scanIdMain;
                                    scanIdResource.filePart = XBinary::FILEPART_RESOURCE;
                                    scanIdResource.nOffset = nResourceOffset;
                                    scanIdResource.nSize = nResourceSize;

                                    XScanEngine::SCAN_OPTIONS _options = *pScanOptions;
                                    _options.fileType = XBinary::FT_UNKNOWN;
                                    _options.bIsRecursiveScan = false;

                                    scanProcess(_pDevice, pScanResult, nResourceOffset, nResourceSize, scanIdResource, &_options, false, pPdStruct);
                                    nCount++;
                                }
                            }
                        }

                        XBinary::setPdStructCurrentIncrement(pPdStruct, _nFreeIndex);
                    }

                    XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
                }

                if (pe.isDebugPresent()) {
                    QList<XPE_DEF::S_IMAGE_DEBUG_DIRECTORY> listDebug = pe.getDebugList(&memoryMap);

                    qint32 nNumberOfRecords = listDebug.count();
                    qint32 nMaxCount = 20;
                    qint32 nCount = 0;

                    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
                    XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nNumberOfRecords);

                    for (qint32 i = 0; (i < nNumberOfRecords) && (!(pPdStruct->bIsStop)); i++) {
                        qint64 nRecordOffset = listDebug.at(i).PointerToRawData;
                        qint64 nRecordSize = listDebug.at(i).SizeOfData;
                        quint32 nRecordType = listDebug.at(i).Type;

                        if ((nRecordType == 0) || (nRecordType == 2)) {
                            if (pe.checkOffsetSize(nRecordOffset, nRecordSize)) {
                                if (nCount < nMaxCount) {
                                    XScanEngine::SCANID scanIdDebug = scanIdMain;
                                    scanIdDebug.filePart = XBinary::FILEPART_DEBUGDATA;
                                    scanIdDebug.nOffset = nRecordOffset;
                                    scanIdDebug.nSize = nRecordSize;

                                    XScanEngine::SCAN_OPTIONS _options = *pScanOptions;
                                    _options.fileType = XBinary::FT_BINARY;
                                    _options.bIsRecursiveScan = false;

                                    scanProcess(_pDevice, pScanResult, nRecordOffset, nRecordSize, scanIdDebug, &_options, false, pPdStruct);

                                    nCount++;
                                }
                            }
                        }

                        XBinary::setPdStructCurrentIncrement(pPdStruct, _nFreeIndex);
                    }

                    XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
                }

                if (pe.isOverlayPresent(&memoryMap, pPdStruct)) {
                    XScanEngine::SCANID scanIdOverlay = scanIdMain;
                    scanIdOverlay.filePart = XBinary::FILEPART_OVERLAY;
                    scanIdOverlay.nOffset = pe.getOverlayOffset(&memoryMap, pPdStruct);
                    scanIdOverlay.nSize = pe.getOverlaySize(&memoryMap, pPdStruct);

                    XScanEngine::SCAN_OPTIONS _options = *pScanOptions;
                    _options.fileType = XBinary::FT_UNKNOWN;
                    _options.bIsRecursiveScan = false;

                    scanProcess(_pDevice, pScanResult, scanIdOverlay.nOffset, scanIdOverlay.nSize, scanIdOverlay, &_options, false, pPdStruct);
                }
            }
            // } else if (stFT.contains(XBinary::FT_ELF32) || stFT.contains(XBinary::FT_ELF64)) {
            //     XELF elf(_pDevice);

            //     if (elf.isValid()) {
            //         XBinary::_MEMORY_MAP memoryMap = elf.getMemoryMap(XBinary::MAPMODE_SEGMENTS, pPdStruct); // TODO use sections!

            //         if (elf.isOverlayPresent(&memoryMap, pPdStruct)) {
            //             XScanEngine::SCANID scanIdOverlay = scanIdMain;
            //             scanIdOverlay.filePart = XBinary::FILEPART_OVERLAY;
            //             scanIdOverlay.nOffset = elf.getOverlayOffset(&memoryMap, pPdStruct);
            //             scanIdOverlay.nSize = elf.getOverlaySize(&memoryMap, pPdStruct);

            //             XScanEngine::SCAN_OPTIONS _options = *pScanOptions;
            //             _options.fileType = XBinary::FT_UNKNOWN;
            //             _options.bIsRecursiveScan = false;

            //             scanProcess(_pDevice, pScanResult, scanIdOverlay.nOffset, scanIdOverlay.nSize, scanIdOverlay, &_options, false, pPdStruct);
            //         }
            //     }
        } else if (stFT.contains(XBinary::FT_LE) || stFT.contains(XBinary::FT_LX)) {
            XLE le(_pDevice);

            if (le.isValid()) {
                XBinary::_MEMORY_MAP memoryMap = le.getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);

                if (le.isOverlayPresent(&memoryMap, pPdStruct)) {
                    XScanEngine::SCANID scanIdOverlay = scanIdMain;
                    scanIdOverlay.filePart = XBinary::FILEPART_OVERLAY;
                    scanIdOverlay.nOffset = le.getOverlayOffset(&memoryMap, pPdStruct);
                    scanIdOverlay.nSize = le.getOverlaySize(&memoryMap, pPdStruct);

                    XScanEngine::SCAN_OPTIONS _options = *pScanOptions;
                    _options.fileType = XBinary::FT_UNKNOWN;
                    _options.bIsRecursiveScan = false;

                    scanProcess(_pDevice, pScanResult, scanIdOverlay.nOffset, scanIdOverlay.nSize, scanIdOverlay, &_options, false, pPdStruct);
                }
            }
        } else if (stFT.contains(XBinary::FT_NE)) {
            XNE ne(_pDevice);

            if (ne.isValid()) {
                XBinary::_MEMORY_MAP memoryMap = ne.getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);

                if (ne.isOverlayPresent(&memoryMap, pPdStruct)) {
                    XScanEngine::SCANID scanIdOverlay = scanIdMain;
                    scanIdOverlay.filePart = XBinary::FILEPART_OVERLAY;
                    scanIdOverlay.nOffset = ne.getOverlayOffset(&memoryMap, pPdStruct);
                    scanIdOverlay.nSize = ne.getOverlaySize(&memoryMap, pPdStruct);

                    XScanEngine::SCAN_OPTIONS _options = *pScanOptions;
                    _options.fileType = XBinary::FT_UNKNOWN;
                    _options.bIsRecursiveScan = false;

                    scanProcess(_pDevice, pScanResult, scanIdOverlay.nOffset, scanIdOverlay.nSize, scanIdOverlay, &_options, false, pPdStruct);
                }
            }
        } else if (stFT.contains(XBinary::FT_MSDOS)) {
            XMSDOS msdos(_pDevice);

            if (msdos.isValid()) {
                XBinary::_MEMORY_MAP memoryMap = msdos.getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);

                if (msdos.isOverlayPresent(&memoryMap, pPdStruct)) {
                    XScanEngine::SCANID scanIdOverlay = scanIdMain;
                    scanIdOverlay.filePart = XBinary::FILEPART_OVERLAY;
                    scanIdOverlay.nOffset = msdos.getOverlayOffset(&memoryMap, pPdStruct);
                    scanIdOverlay.nSize = msdos.getOverlaySize(&memoryMap, pPdStruct);

                    XScanEngine::SCAN_OPTIONS _options = *pScanOptions;
                    _options.fileType = XBinary::FT_UNKNOWN;
                    _options.bIsRecursiveScan = false;

                    scanProcess(_pDevice, pScanResult, scanIdOverlay.nOffset, scanIdOverlay.nSize, scanIdOverlay, &_options, false, pPdStruct);
                }
            }
        } else {
            QList<XArchive::RECORD> listRecords;
            XBinary::FT _fileType = XBinary::FT_UNKNOWN;

            if (stFTOriginal.contains(XBinary::FT_ARCHIVE) || stFTOriginal.contains(XBinary::FT_DOS16M) || stFTOriginal.contains(XBinary::FT_DOS4G)) {
                _fileType = XBinary::_getPrefFileType(&stFT);
                listRecords = XArchives::getRecords(_pDevice, _fileType, 20000, pPdStruct);
            } else {
                if (pScanOptions->bIsDeepScan) {
                    XExtractor::OPTIONS options = {};
                    options.bHeuristicScan = true;
                    options.fileType = XBinary::FT_BINARY;
                    options.listFileTypes.append(XBinary::FT_PE);
                    options.listFileTypes.append(XBinary::FT_ELF);
                    options.listFileTypes.append(XBinary::FT_MACHO);
                    options.listFileTypes.append(XBinary::FT_PDF);
                    options.listFileTypes.append(XBinary::FT_ZIP);
                    options.listFileTypes.append(XBinary::FT_RAR);
                    // options.listFileTypes.append(XBinary::FT_GZIP);
                    // options.listFileTypes.append(XBinary::FT_ZLIB);
                    options.listFileTypes.append(XBinary::FT_7Z);
                    options.listFileTypes.append(XBinary::FT_CAB);

                    QList<XExtractor::RECORD> listExtractRecords = XExtractor::scanDevice(_pDevice, options, pPdStruct);
                    qint32 nNumberOfRecords = listExtractRecords.count();
                    qint32 nMaxCount = 20;
                    // qint32 nMaxCount = -1;
                    qint32 nCount = 0;

                    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
                    XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nNumberOfRecords);

                    for (qint32 i = 0; (i < nNumberOfRecords) && (!(pPdStruct->bIsStop)); i++) {
                        XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, listExtractRecords.at(i).sString);

                        if (listExtractRecords.at(i).nOffset != 0) {
                            if ((nCount < nMaxCount) || (nMaxCount == -1)) {
                                XScanEngine::SCANID scanIdRegion = scanIdMain;
                                scanIdRegion.filePart = XBinary::FILEPART_REGION;
                                scanIdRegion.fileType = listExtractRecords.at(i).fileType;
                                scanIdRegion.nOffset = listExtractRecords.at(i).nOffset;
                                scanIdRegion.nSize = listExtractRecords.at(i).nSize;

                                XScanEngine::SCAN_OPTIONS _options = *pScanOptions;
                                _options.fileType = XBinary::FT_UNKNOWN;
                                _options.bIsRecursiveScan = false;

                                scanProcess(_pDevice, pScanResult, listExtractRecords.at(i).nOffset, listExtractRecords.at(i).nSize, scanIdRegion, &_options, false,
                                            pPdStruct);

                                nCount++;
                            }
                        }
                        XBinary::setPdStructCurrent(pPdStruct, _nFreeIndex, i);
                    }

                    XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
                }
            }

            if (listRecords.count()) {
                qint32 nNumberOfRecords = listRecords.count();
                qint32 nMaxCount = 20;
                // qint32 nMaxCount = -1;
                qint32 nCount = 0;

                bool bScanAll = false;
                bool bShowFileName = true;

                if (((_fileType == XBinary::FT_ZLIB) || (_fileType == XBinary::FT_LHA) || (_fileType == XBinary::FT_GZIP)) && (nNumberOfRecords == 1)) {
                    bScanAll = true;
                    bShowFileName = false;
                } else if ((_fileType == XBinary::FT_MACHOFAT) || (_fileType == XBinary::FT_DOS16M) || (_fileType == XBinary::FT_DOS4G)) {
                    bScanAll = true;
                }

                qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
                XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nNumberOfRecords);

                for (qint32 i = 0; (i < nNumberOfRecords) && (!(pPdStruct->bIsStop)); i++) {
                    XArchive::RECORD _record = listRecords.at(i);
                    QByteArray baRecordData = XArchives::decompress(_pDevice, &_record, pPdStruct, 0, 0x200);

                    QSet<XBinary::FT> _stFT = XFormats::getFileTypes(&baRecordData, true);

                    if (bScanAll || isScanable(_stFT)) {
                        if ((nCount < nMaxCount) || (nMaxCount == -1)) {
                            XScanEngine::SCANID scanIdArchiveRecord = scanIdMain;
                            scanIdArchiveRecord.filePart = XBinary::FILEPART_ARCHIVERECORD;
                            scanIdArchiveRecord.fileType = _fileType;

                            XScanEngine::SCAN_OPTIONS _options = *pScanOptions;
                            _options.fileType = XBinary::FT_UNKNOWN;
                            _options.bIsRecursiveScan = false;

                            if (bShowFileName) {
                                scanIdArchiveRecord.sInfo = listRecords.at(i).sFileName;
                            }

                            qint64 _nUncompressedSize = listRecords.at(i).nUncompressedSize;
                            qint64 _nRecordDataSize = baRecordData.size();

                            if (_nUncompressedSize && _nRecordDataSize) {
                                if (_nUncompressedSize > _nRecordDataSize) {
                                    bool _bMemory = false;

                                    if (pScanOptions->nBufferSize) {
                                        if (_nUncompressedSize <= pScanOptions->nBufferSize) {
                                            _bMemory = true;
                                        }
                                    }

                                    if (_bMemory) {
                                        char *pArchBuffer = new char[_nUncompressedSize];

                                        QBuffer buffer;
                                        buffer.setData(pArchBuffer, _nUncompressedSize);

                                        if (buffer.open(QIODevice::ReadWrite)) {
                                            if (XArchives::decompressToDevice(_pDevice, &_record, &buffer, pPdStruct)) {
                                                scanProcess(&buffer, pScanResult, 0, buffer.size(), scanIdArchiveRecord, &_options, false, pPdStruct);
                                            }

                                            buffer.close();
                                        }

                                        delete[] pArchBuffer;
                                    } else {
                                        QTemporaryFile fileTemp;

                                        if (fileTemp.open()) {
                                            QString sTempFileName = fileTemp.fileName();

                                            if (XArchives::decompressToFile(_pDevice, &_record, sTempFileName, pPdStruct)) {
                                                QFile file;
                                                file.setFileName(sTempFileName);

                                                if (file.open(QIODevice::ReadOnly)) {
                                                    scanProcess(&file, pScanResult, 0, file.size(), scanIdArchiveRecord, &_options, false, pPdStruct);
                                                    file.close();
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    QBuffer buffer(&baRecordData);

                                    if (buffer.open(QIODevice::ReadOnly)) {
                                        scanProcess(&buffer, pScanResult, 0, buffer.size(), scanIdArchiveRecord, &_options, false, pPdStruct);

                                        buffer.close();
                                    }
                                }
                            }
                            nCount++;
                        }
                    }

                    XBinary::setPdStructCurrentIncrement(pPdStruct, _nFreeIndex);
                    XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, listRecords.at(i).sFileName);
                }

                XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
            }
        }
    }

    if (bufDevice) {
        bufDevice->close();
        delete bufDevice;
    }

    if (pBuffer) {
        delete[] pBuffer;
    }

    if (pSd) {
        pSd->close();

        delete pSd;
    }

    if (pScanTimer) {
        pScanResult->nScanTime = pScanTimer->elapsed();

        delete pScanTimer;
    }
}

QMap<quint64, QString> XScanEngine::getScanFlags()
{
    QMap<quint64, QString> mapResult;

    mapResult.insert(SF_RECURSIVESCAN, tr("Recursive scan"));
    mapResult.insert(SF_DEEPSCAN, tr("Deep scan"));
    mapResult.insert(SF_HEURISTICSCAN, tr("Heuristic scan"));
#ifdef QT_DEBUG
    mapResult.insert(SF_AGGRESSIVESCAN, tr("Aggressive scan"));
#endif
    mapResult.insert(SF_VERBOSE, tr("Verbose"));
    mapResult.insert(SF_ALLTYPESSCAN, tr("All types"));

    return mapResult;
}

quint64 XScanEngine::getScanFlags(SCAN_OPTIONS *pScanOptions)
{
    quint64 nResult = 0;

    if (pScanOptions->bIsRecursiveScan) {
        nResult |= SF_RECURSIVESCAN;
    }

    if (pScanOptions->bIsDeepScan) {
        nResult |= SF_DEEPSCAN;
    }

    if (pScanOptions->bIsHeuristicScan) {
        nResult |= SF_HEURISTICSCAN;
    }

    if (pScanOptions->bIsAggressiveScan) {
        nResult |= SF_AGGRESSIVESCAN;
    }

    if (pScanOptions->bIsVerbose) {
        nResult |= SF_VERBOSE;
    }

    if (pScanOptions->bIsAllTypesScan) {
        nResult |= SF_ALLTYPESSCAN;
    }

    if (pScanOptions->bResultAsJSON) {
        nResult |= SF_RESULTASJSON;
    }

    if (pScanOptions->bResultAsXML) {
        nResult |= SF_RESULTASXML;
    }

    if (pScanOptions->bResultAsCSV) {
        nResult |= SF_RESULTASCSV;
    }

    return nResult;
}

void XScanEngine::setScanFlags(SCAN_OPTIONS *pScanOptions, quint64 nFlags)
{
    pScanOptions->bIsRecursiveScan = nFlags & SF_RECURSIVESCAN;
    pScanOptions->bIsDeepScan = nFlags & SF_DEEPSCAN;
    pScanOptions->bIsHeuristicScan = nFlags & SF_HEURISTICSCAN;
    pScanOptions->bIsAggressiveScan = nFlags & SF_AGGRESSIVESCAN;
    pScanOptions->bIsVerbose = nFlags & SF_VERBOSE;
    pScanOptions->bIsAllTypesScan = nFlags & SF_ALLTYPESSCAN;
    pScanOptions->bResultAsJSON = nFlags & SF_RESULTASJSON;
    pScanOptions->bResultAsXML = nFlags & SF_RESULTASXML;
    pScanOptions->bResultAsCSV = nFlags & SF_RESULTASCSV;
}

quint64 XScanEngine::getScanFlagsFromGlobalOptions(XOptions *pGlobalOptions)
{
    quint64 nResult = 0;

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FLAG_RECURSIVE).toBool()) {
        nResult |= SF_RECURSIVESCAN;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FLAG_DEEP).toBool()) {
        nResult |= SF_DEEPSCAN;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FLAG_HEURISTIC).toBool()) {
        nResult |= SF_HEURISTICSCAN;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FLAG_AGGRESSIVE).toBool()) {
        nResult |= SF_AGGRESSIVESCAN;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FLAG_VERBOSE).toBool()) {
        nResult |= SF_VERBOSE;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FLAG_ALLTYPES).toBool()) {
        nResult |= SF_ALLTYPESSCAN;
    }

    return nResult;
}

void XScanEngine::setScanFlagsToGlobalOptions(XOptions *pGlobalOptions, quint64 nFlags)
{
    pGlobalOptions->setValue(XOptions::ID_SCAN_FLAG_RECURSIVE, nFlags & SF_RECURSIVESCAN);
    pGlobalOptions->setValue(XOptions::ID_SCAN_FLAG_DEEP, nFlags & SF_DEEPSCAN);
    pGlobalOptions->setValue(XOptions::ID_SCAN_FLAG_HEURISTIC, nFlags & SF_HEURISTICSCAN);
    pGlobalOptions->setValue(XOptions::ID_SCAN_FLAG_AGGRESSIVE, nFlags & SF_AGGRESSIVESCAN);
    pGlobalOptions->setValue(XOptions::ID_SCAN_FLAG_VERBOSE, nFlags & SF_VERBOSE);
    pGlobalOptions->setValue(XOptions::ID_SCAN_FLAG_ALLTYPES, nFlags & SF_ALLTYPESSCAN);
}

XScanEngine::SCAN_OPTIONS XScanEngine::getDefaultOptions(quint64 nFlags)
{
    XScanEngine::SCAN_OPTIONS result = {};

    result.bShowType = true;
    result.bShowVersion = true;
    result.bShowInfo = true;
    result.nBufferSize = 2 * 1024 * 1024;

    setScanFlags(&result, nFlags);

    return result;
}

QMap<quint64, QString> XScanEngine::getDatabases()
{
    QMap<quint64, QString> mapResult;

    mapResult.insert(DATABASE_MAIN, tr("Main"));
    mapResult.insert(DATABASE_EXTRA, tr("Extra"));
    mapResult.insert(DATABASE_CUSTOM, tr("Custom"));

    return mapResult;
}

quint64 XScanEngine::getDatabases(SCAN_OPTIONS *pScanOptions)
{
    quint64 nResult = DATABASE_MAIN;

    if (pScanOptions->bUseExtraDatabase) {
        nResult |= DATABASE_EXTRA;
    }

    if (pScanOptions->bUseCustomDatabase) {
        nResult |= DATABASE_CUSTOM;
    }

    return nResult;
}

void XScanEngine::setDatabases(SCAN_OPTIONS *pScanOptions, quint64 nDatabases)
{
    pScanOptions->bUseExtraDatabase = (nDatabases & DATABASE_EXTRA);
    pScanOptions->bUseCustomDatabase = (nDatabases & DATABASE_CUSTOM);
}

quint64 XScanEngine::getDatabasesFromGlobalOptions(XOptions *pGlobalOptions)
{
    quint64 nResult = DATABASE_MAIN;

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_DATABASE_EXTRA_ENABLED).toBool()) {
        nResult |= DATABASE_EXTRA;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_DATABASE_CUSTOM_ENABLED).toBool()) {
        nResult |= DATABASE_CUSTOM;
    }

    return nResult;
}

void XScanEngine::setDatabasesToGlobalOptions(XOptions *pGlobalOptions, quint64 nDatabases)
{
    pGlobalOptions->setValue(XOptions::ID_SCAN_DATABASE_EXTRA_ENABLED, nDatabases & DATABASE_EXTRA);
    pGlobalOptions->setValue(XOptions::ID_SCAN_DATABASE_CUSTOM_ENABLED, nDatabases & DATABASE_CUSTOM);
}

void XScanEngine::process()
{
    XBinary::PDSTRUCT *pPdStruct = g_pPdStruct;

    XBinary::PDSTRUCT pdStructEmpty = {};

    if (!pPdStruct) {
        pdStructEmpty = XBinary::createPdStruct();
        pPdStruct = &pdStructEmpty;
    }

    QElapsedTimer scanTimer;
    scanTimer.start();

    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);

    if (g_scanType == SCAN_TYPE_FILE) {
        if ((g_pScanResult) && (g_sFileName != "")) {
            XBinary::setPdStructInit(pPdStruct, _nFreeIndex, 0);
            XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, tr("File scan"));

            emit scanFileStarted(g_sFileName);

            *g_pScanResult = scanFile(g_sFileName, g_pScanOptions, pPdStruct);

            emit scanResult(*g_pScanResult);
        }
    } else if (g_scanType == SCAN_TYPE_DEVICE) {
        if (g_pDevice) {
            XBinary::setPdStructInit(pPdStruct, _nFreeIndex, 0);
            XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, tr("Device scan"));

            *g_pScanResult = scanDevice(g_pDevice, g_pScanOptions, pPdStruct);

            emit scanResult(*g_pScanResult);
        }
    } else if (g_scanType == SCAN_TYPE_MEMORY) {
        XBinary::setPdStructInit(pPdStruct, _nFreeIndex, 0);
        XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, tr("Memory scan"));

        *g_pScanResult = scanMemory(g_pData, g_nDataSize, g_pScanOptions, pPdStruct);

        emit scanResult(*g_pScanResult);
    } else if (g_scanType == SCAN_TYPE_DIRECTORY) {
        if (g_sDirectoryName != "") {
            XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, tr("Directory scan"));
            QList<QString> listFileNames;

            XBinary::findFiles(g_sDirectoryName, &listFileNames, g_pScanOptions->bSubdirectories, 0, pPdStruct);

            qint32 nTotal = listFileNames.count();

            XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nTotal);

            for (qint32 i = 0; (i < nTotal) && (!(pPdStruct->bIsStop)); i++) {
                QString sFileName = listFileNames.at(i);

                XBinary::setPdStructCurrent(pPdStruct, _nFreeIndex, i);
                XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, sFileName);

                emit scanFileStarted(sFileName);

                XScanEngine::SCAN_RESULT _scanResult = scanFile(sFileName, g_pScanOptions, pPdStruct);

                emit scanResult(_scanResult);
            }
        }
    }

    XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);

    emit completed(scanTimer.elapsed());
}

void XScanEngine::_errorMessage(SCAN_OPTIONS *pOptions, const QString &sErrorMessage)
{
    Q_UNUSED(pOptions)
    // g_bIsErrorLogEnable = true;
    // g_bIsWarningLogEnable = false;
    // g_bIsInfoLogEnable = false;

    // if ((pOptions->bResultAsCSV) || (pOptions->bResultAsJSON) || (pOptions->bResultAsTSV) || (pOptions->bResultAsXML)) {
    //     g_bIsErrorLogEnable = false;
    //     g_bIsWarningLogEnable = false;
    //     g_bIsInfoLogEnable = false;
    // }

    // if (pOptions->bLogProfiling) {
    //     g_bIsInfoLogEnable = true;
    //     g_bIsWarningLogEnable = true;
    // }

    emit errorMessage(sErrorMessage);
}

void XScanEngine::_warningMessage(SCAN_OPTIONS *pOptions, const QString &sWarningMessage)
{
    Q_UNUSED(pOptions)
    emit errorMessage(sWarningMessage);
}

void XScanEngine::_infoMessage(SCAN_OPTIONS *pOptions, const QString &sInfoMessage)
{
    Q_UNUSED(pOptions)
    emit errorMessage(sInfoMessage);
}
