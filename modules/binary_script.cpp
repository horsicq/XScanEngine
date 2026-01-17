/* Copyright (c) 2019-2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "binary_script.h"

Binary_Script::Binary_Script(XBinary *pBinary, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    this->m_pBinary = pBinary;
    this->m_filePart = filePart;
    this->m_pPdStruct = pPdStruct;
    this->m_pOptions = pOptions;

    connect(pBinary, SIGNAL(errorMessage(QString)), this, SIGNAL(errorMessage(QString)));
    connect(pBinary, SIGNAL(infoMessage(QString)), this, SIGNAL(infoMessage(QString)));

    m_nSize = pBinary->getSize();
    m_memoryMap = pBinary->getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);
    m_nBaseAddress = pBinary->getBaseAddress();

    m_nEntryPointOffset = pBinary->getEntryPointOffset(&m_memoryMap);
    m_nEntryPointAddress = pBinary->getEntryPointAddress(&m_memoryMap);
    m_nOverlayOffset = pBinary->getOverlayOffset(&m_memoryMap, pPdStruct);
    m_nOverlaySize = pBinary->getOverlaySize(&m_memoryMap, pPdStruct);
    m_bIsOverlayPresent = pBinary->isOverlayPresent(&m_memoryMap, pPdStruct);
    m_bIsBigEndian = pBinary->isBigEndian();

    m_sHeaderSignature = pBinary->getSignature(0, 256);  // TODO const
    m_nHeaderSignatureSize = m_sHeaderSignature.size() / 2;

    m_sEntryPointSignature = pBinary->getSignature(m_nEntryPointOffset, 256);  // TODO const
    m_nEntryPointSignatureSize = m_sEntryPointSignature.size();

    if (m_nOverlayOffset > 0) {
        m_sOverlaySignature = pBinary->getSignature(m_nOverlayOffset, 256);  // TODO const
        m_nOverlaySignatureSize = m_sOverlaySignature.size();
    }

    m_sFileDirectory = XBinary::getDeviceDirectory(pBinary->getDevice());
    m_sFileBaseName = XBinary::getDeviceFileBaseName(pBinary->getDevice());
    m_sFileCompleteSuffix = XBinary::getDeviceFileCompleteSuffix(pBinary->getDevice());
    m_sFileSuffix = XBinary::getDeviceFileSuffix(pBinary->getDevice());

    m_bIsPlainText = pBinary->isPlainTextType();
    m_bIsUTF8Text = pBinary->isUTF8TextType();
    XBinary::UNICODE_TYPE unicodeType = pBinary->getUnicodeType();

    if (unicodeType != XBinary::UNICODE_TYPE_NONE) {
        m_sHeaderString = pBinary->read_unicodeString(2, qMin(m_nSize, (qint64)0x1000), (unicodeType == XBinary::UNICODE_TYPE_BE));
        m_bIsUnicodeText = true;
    } else if (m_bIsUTF8Text) {
        m_sHeaderString = pBinary->read_utf8String(3, qMin(m_nSize, (qint64)0x1000));
    } else if (m_bIsPlainText) {
        m_sHeaderString = pBinary->read_ansiString(0, qMin(m_nSize, (qint64)0x1000));
    }

    m_bIsSigned = pBinary->isSigned();
    m_fileFormatInfo = pBinary->getFileFormatInfo(pPdStruct);
    m_sFileFormatInfoString = XBinary::getFileFormatInfoString(&m_fileFormatInfo);

    m_bIsFmtChecking = false;
    m_bIsFmtCheckingDeep = false;

    m_disasmOptions = {};
    m_disasmOptions.bIsUppercase = true;
    m_disasmCore.setMode(XBinary::getDisasmMode(&m_memoryMap));
}

Binary_Script::~Binary_Script()
{
}

qint64 Binary_Script::getSize()
{
    return m_nSize;
}

bool Binary_Script::compare(const QString &sSignature, qint64 nOffset)
{
    bool bResult = false;

    QString _sSignature = XBinary::convertSignature(sSignature);

    qint32 nSignatureSize = _sSignature.size();

    if ((nSignatureSize + nOffset < m_nHeaderSignatureSize) && (!_sSignature.contains('$')) && (!_sSignature.contains('#')) && (!_sSignature.contains('+')) &&
        (!_sSignature.contains('%')) && (!_sSignature.contains('*'))) {
        bResult = m_pBinary->compareSignatureStrings(m_sHeaderSignature.mid(nOffset * 2, nSignatureSize * 2), _sSignature);
    } else {
        bResult = m_pBinary->compareSignature(&m_memoryMap, _sSignature, nOffset, m_pPdStruct);
    }

    return bResult;
}

bool Binary_Script::compareEP(const QString &sSignature, qint64 nOffset)
{
    bool bResult = false;

    QString _sSignature = XBinary::convertSignature(sSignature);

    qint32 nSignatureSize = sSignature.size();

    if ((nSignatureSize + nOffset < m_nEntryPointSignatureSize) && (!_sSignature.contains('$')) && (!_sSignature.contains('#')) && (!_sSignature.contains('+')) &&
        (!_sSignature.contains('%')) && (!_sSignature.contains('*'))) {
        bResult = m_pBinary->compareSignatureStrings(m_sEntryPointSignature.mid(nOffset * 2, nSignatureSize * 2), _sSignature);
    } else {
        bResult = m_pBinary->compareEntryPoint(&m_memoryMap, _sSignature, nOffset);  // TODO m_pPdStruct
    }

    return bResult;
}

quint8 Binary_Script::readByte(qint64 nOffset)
{
    return m_pBinary->read_uint8(nOffset);
}

qint16 Binary_Script::readSByte(qint64 nOffset)
{
    return m_pBinary->read_int8(nOffset);
}

quint16 Binary_Script::readWord(qint64 nOffset)
{
    return m_pBinary->read_uint16(nOffset);
}

qint16 Binary_Script::readSWord(qint64 nOffset)
{
    return m_pBinary->read_int16(nOffset);
}

quint32 Binary_Script::readDword(qint64 nOffset)
{
    return m_pBinary->read_uint32(nOffset);
}

qint32 Binary_Script::readSDword(qint64 nOffset)
{
    return m_pBinary->read_int32(nOffset);
}

quint64 Binary_Script::readQword(qint64 nOffset)
{
    return m_pBinary->read_uint64(nOffset);
}

qint64 Binary_Script::readSQword(qint64 nOffset)
{
    return m_pBinary->read_int64(nOffset);
}

QString Binary_Script::getString(qint64 nOffset, qint64 nMaxSize)
{
    return m_pBinary->read_ansiString(nOffset, nMaxSize);
}

qint64 Binary_Script::findSignature(qint64 nOffset, qint64 nSize, const QString &sSignature)
{
    qint64 nResult = -1;

    QElapsedTimer *pTimer = _startProfiling();

    qint64 nResultSize = 0;

    _fixOffsetAndSize(&nOffset, &nSize);

    nResult = m_pBinary->find_signature(&m_memoryMap, nOffset, nSize, sSignature, &nResultSize, m_pPdStruct);

    if (pTimer) {
        _finishProfiling(pTimer, QString("find_signature[%1]: %2 %3").arg(sSignature, XBinary::valueToHexEx(nOffset), XBinary::valueToHexEx(nSize)));
    }

    return nResult;
}

qint64 Binary_Script::findString(qint64 nOffset, qint64 nSize, const QString &sString)
{
    qint64 nResult = -1;

    QElapsedTimer *pTimer = _startProfiling();

    _fixOffsetAndSize(&nOffset, &nSize);

    nResult = m_pBinary->find_ansiString(nOffset, nSize, sString, m_pPdStruct);

    if (pTimer) {
        _finishProfiling(pTimer, QString("findString[%1]: %2 %3").arg(sString, XBinary::valueToHexEx(nOffset), XBinary::valueToHexEx(nSize)));
    }

    return nResult;
}

qint64 Binary_Script::findByte(qint64 nOffset, qint64 nSize, quint8 nValue)
{
    qint64 nResult = -1;

    QElapsedTimer *pTimer = _startProfiling();

    _fixOffsetAndSize(&nOffset, &nSize);

    nResult = m_pBinary->find_uint8(nOffset, nSize, nValue, m_pPdStruct);

    if (pTimer) {
        _finishProfiling(pTimer, QString("findByte[%1]: %2 %3").arg(XBinary::valueToHex(nValue), XBinary::valueToHexEx(nOffset), XBinary::valueToHexEx(nSize)));
    }

    return nResult;
}

qint64 Binary_Script::findWord(qint64 nOffset, qint64 nSize, quint16 nValue)
{
    qint64 nResult = -1;

    QElapsedTimer *pTimer = _startProfiling();

    _fixOffsetAndSize(&nOffset, &nSize);

    nResult = m_pBinary->find_uint16(nOffset, nSize, nValue, m_pPdStruct);

    if (pTimer) {
        _finishProfiling(pTimer, QString("findWord[%1]: %2 %3").arg(XBinary::valueToHex(nValue), XBinary::valueToHexEx(nOffset), XBinary::valueToHexEx(nSize)));
    }

    return nResult;
}

qint64 Binary_Script::findDword(qint64 nOffset, qint64 nSize, quint32 nValue)
{
    qint64 nResult = -1;

    QElapsedTimer *pTimer = _startProfiling();

    _fixOffsetAndSize(&nOffset, &nSize);

    nResult = m_pBinary->find_uint32(nOffset, nSize, nValue, m_pPdStruct);

    if (pTimer) {
        _finishProfiling(pTimer, QString("findDword[%1]: %2 %3").arg(XBinary::valueToHex(nValue), XBinary::valueToHexEx(nOffset), XBinary::valueToHexEx(nSize)));
    }

    return nResult;
}

qint64 Binary_Script::getEntryPointOffset()
{
    return m_nEntryPointOffset;
}

qint64 Binary_Script::getOverlayOffset()
{
    return m_nOverlayOffset;
}

qint64 Binary_Script::getOverlaySize()
{
    return m_nOverlaySize;
}

qint64 Binary_Script::getAddressOfEntryPoint()
{
    return m_nEntryPointAddress;
}

bool Binary_Script::isOverlayPresent()
{
    return m_bIsOverlayPresent;
}

bool Binary_Script::compareOverlay(const QString &sSignature, qint64 nOffset)
{
    bool bResult = false;

    QString _sSignature = XBinary::convertSignature(sSignature);

    qint32 nSignatureSize = sSignature.size();

    if ((nSignatureSize + nOffset < m_nOverlaySignatureSize) && (!_sSignature.contains('$')) && (!_sSignature.contains('#')) && (!_sSignature.contains('+')) &&
        (!_sSignature.contains('%')) && (!_sSignature.contains('*'))) {
        bResult = m_pBinary->compareSignatureStrings(m_sOverlaySignature.mid(nOffset * 2, nSignatureSize * 2), _sSignature);
    } else {
        bResult = m_pBinary->compareOverlay(&m_memoryMap, _sSignature, nOffset, m_pPdStruct);
    }

    return bResult;
}

bool Binary_Script::isSignaturePresent(qint64 nOffset, qint64 nSize, const QString &sSignature)
{
    bool bResult = false;

    QElapsedTimer *pTimer = _startProfiling();

    bResult = m_pBinary->isSignaturePresent(&m_memoryMap, nOffset, nSize, sSignature, m_pPdStruct);

    if (pTimer) {
        _finishProfiling(pTimer, QString("isSignaturePresent[%1]: %2 %3").arg(sSignature, XBinary::valueToHexEx(nOffset), XBinary::valueToHexEx(nSize)));
    }

    return bResult;
}

quint32 Binary_Script::swapBytes(quint32 nValue)
{
    return m_pBinary->swapBytes(nValue);
}

QString Binary_Script::getGeneralOptions()
{
    return "";
}

qint64 Binary_Script::RVAToOffset(qint64 nRVA)
{
    return m_pBinary->addressToOffset(&m_memoryMap, nRVA + m_nBaseAddress);
}

qint64 Binary_Script::VAToOffset(qint64 nVA)
{
    return m_pBinary->addressToOffset(&m_memoryMap, nVA);
}

qint64 Binary_Script::OffsetToVA(qint64 nOffset)
{
    return m_pBinary->offsetToAddress(&m_memoryMap, nOffset);
}

qint64 Binary_Script::OffsetToRVA(qint64 nOffset)
{
    qint64 nResult = m_pBinary->offsetToAddress(&m_memoryMap, nOffset);

    if (nResult != -1) {
        nResult -= m_nBaseAddress;
    }

    return nResult;
}

QString Binary_Script::getFileDirectory()
{
    return m_sFileDirectory;
}

QString Binary_Script::getFileBaseName()
{
    return m_sFileBaseName;
}

QString Binary_Script::getFileCompleteSuffix()
{
    return m_sFileCompleteSuffix;
}

QString Binary_Script::getFileSuffix()
{
    return m_sFileSuffix;
}

QString Binary_Script::getSignature(qint64 nOffset, qint64 nSize)
{
    return m_pBinary->getSignature(nOffset, nSize);
}

double Binary_Script::calculateEntropy(qint64 nOffset, qint64 nSize)
{
    return m_pBinary->getBinaryStatus(XBinary::BSTATUS_ENTROPY, nOffset, nSize, m_pPdStruct);
}

QString Binary_Script::calculateMD5(qint64 nOffset, qint64 nSize)
{
    return m_pBinary->getHash(XBinary::HASH_MD5, nOffset, nSize, m_pPdStruct);
}

quint32 Binary_Script::calculateCRC32(qint64 nOffset, qint64 nSize)
{
    return m_pBinary->_getCRC32(nOffset, nSize, 0, m_pBinary->_getCRC32Table_EDB88320(), m_pPdStruct);
}

quint16 Binary_Script::crc16(qint64 nOffset, qint64 nSize, quint16 nInit)
{
    return m_pBinary->_getCRC16(nOffset, nSize, nInit, m_pPdStruct);
}

quint32 Binary_Script::crc32(qint64 nOffset, qint64 nSize, quint32 nInit)
{
    return m_pBinary->_getCRC32(nOffset, nSize, nInit, m_pBinary->_getCRC32Table_EDB88320(), m_pPdStruct);
}

quint32 Binary_Script::adler32(qint64 nOffset, qint64 nSize)
{
    return m_pBinary->getAdler32(nOffset, nSize, m_pPdStruct);
}

bool Binary_Script::isSignatureInSectionPresent(quint32 nNumber, const QString &sSignature)
{
    bool bResult = false;

    QElapsedTimer *pTimer = _startProfiling();

    qint32 _nNumber = nNumber;
    QString sClassName = metaObject()->className();

    if (sClassName == "PE_Script") {
        _nNumber++;
    }

    bResult = m_pBinary->isSignatureInFilePartPresent(&m_memoryMap, _nNumber, sSignature, m_pPdStruct);

    if (pTimer) {
        _finishProfiling(pTimer, QString("isSignatureInSectionPresent[%1]: %2 ").arg(sSignature, QString::number(nNumber)));
    }

    return bResult;
}

qint64 Binary_Script::getImageBase()
{
    return m_memoryMap.nModuleAddress;
}

QString Binary_Script::upperCase(const QString &sString)
{
    return sString.toUpper();
}

QString Binary_Script::lowerCase(const QString &sString)
{
    return sString.toLower();
}

bool Binary_Script::isPlainText()
{
    return m_bIsPlainText;
}

bool Binary_Script::isUTF8Text()
{
    return m_bIsUTF8Text;
}

bool Binary_Script::isUnicodeText()
{
    return m_bIsUnicodeText;
}

bool Binary_Script::isText()
{
    return m_bIsPlainText | m_bIsUTF8Text | m_bIsUnicodeText;
}

QString Binary_Script::getHeaderString()
{
    return m_sHeaderString;
}

qint32 Binary_Script::getDisasmLength(qint64 nAddress)
{
    return m_disasmCore.disAsm(m_pBinary->getDevice(), XBinary::addressToOffset(&m_memoryMap, nAddress), nAddress, m_disasmOptions).nSize;
}

QString Binary_Script::getDisasmString(qint64 nAddress)
{
    qint64 nOffset = XBinary::addressToOffset(&m_memoryMap, nAddress);

    XDisasmAbstract::DISASM_RESULT _disasmResult = m_disasmCore.disAsm(m_pBinary->getDevice(), nOffset, nAddress, m_disasmOptions);

    QString sResult = _disasmResult.sMnemonic;
    if (_disasmResult.sOperands != "") {
        sResult += " " + _disasmResult.sOperands;
    }

    return sResult;
}

qint64 Binary_Script::getDisasmNextAddress(qint64 nAddress)
{
    return m_disasmCore.disAsm(m_pBinary->getDevice(), XBinary::addressToOffset(&m_memoryMap, nAddress), nAddress, m_disasmOptions).nNextAddress;
}

bool Binary_Script::is16()
{
    return XBinary::is16(&m_memoryMap);
}

bool Binary_Script::is32()
{
    return XBinary::is32(&m_memoryMap);
}

bool Binary_Script::is64()
{
    return XBinary::is64(&m_memoryMap);
}

bool Binary_Script::isDeepScan()
{
    return m_pOptions->bIsDeepScan;
}

bool Binary_Script::isHeuristicScan()
{
    return m_pOptions->bIsHeuristicScan;
}

bool Binary_Script::isAggressiveScan()
{
    return m_pOptions->bIsAggressiveScan;
}

bool Binary_Script::isRecursiveScan()
{
    return m_pOptions->bIsRecursiveScan;
}

bool Binary_Script::isVerbose()
{
    return m_pOptions->bIsVerbose;
}

bool Binary_Script::isProfiling()
{
    return m_pOptions->bIsProfiling;
}

qint64 Binary_Script::getStartOffset()
{
    return XIODevice::getInitLocation(m_pBinary->getDevice());
}

quint8 Binary_Script::read_uint8(qint64 nOffset)
{
    return m_pBinary->read_uint8(nOffset);
}

qint16 Binary_Script::read_int8(qint64 nOffset)
{
    return m_pBinary->read_int8(nOffset);
}

quint16 Binary_Script::read_uint16(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_uint16(nOffset, bIsBigEndian);
}

qint16 Binary_Script::read_int16(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_int16(nOffset, bIsBigEndian);
}

quint32 Binary_Script::read_uint32(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_uint32(nOffset, bIsBigEndian);
}

qint32 Binary_Script::read_int32(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_int32(nOffset, bIsBigEndian);
}

quint64 Binary_Script::read_uint64(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_uint64(nOffset, bIsBigEndian);
}

qint64 Binary_Script::read_int64(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_int64(nOffset, bIsBigEndian);
}

QString Binary_Script::read_ansiString(qint64 nOffset, qint64 nMaxSize)
{
    return m_pBinary->read_ansiString(nOffset, nMaxSize);
}

QString Binary_Script::read_unicodeString(qint64 nOffset, qint64 nMaxSize)
{
    return m_pBinary->read_unicodeString(nOffset, nMaxSize);
}

QString Binary_Script::read_utf8String(qint64 nOffset, qint64 nMaxSize)
{
    return m_pBinary->read_utf8String(nOffset, nMaxSize);
}

QString Binary_Script::read_ucsdString(qint64 nOffset)
{
    return m_pBinary->read_ucsdString(nOffset);
}

QString Binary_Script::read_codePageString(qint64 nOffset, qint64 nMaxByteSize, const QString &sCodePage)
{
    return m_pBinary->read_codePageString(nOffset, nMaxByteSize, sCodePage);
}

QString Binary_Script::bytesCountToString(quint64 nValue)
{
    return m_pBinary->bytesCountToString(nValue);
}

qint64 Binary_Script::find_ansiString(qint64 nOffset, qint64 nSize, const QString &sString)
{
    qint64 nResult = -1;

    nResult = m_pBinary->find_ansiString(nOffset, nSize, sString, m_pPdStruct);

    return nResult;
}

qint64 Binary_Script::find_unicodeString(qint64 nOffset, qint64 nSize, const QString &sString)
{
    qint64 nResult = -1;

    nResult = m_pBinary->find_unicodeString(nOffset, nSize, sString, m_bIsBigEndian, m_pPdStruct);

    return nResult;
}

qint64 Binary_Script::find_utf8String(qint64 nOffset, qint64 nSize, const QString &sString)
{
    qint64 nResult = -1;

    nResult = m_pBinary->find_utf8String(nOffset, nSize, sString, m_pPdStruct);

    return nResult;
}

QString Binary_Script::read_UUID_bytes(qint64 nOffset)
{
    return m_pBinary->read_UUID_bytes(nOffset);
}

QString Binary_Script::read_UUID(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_UUID(nOffset, bIsBigEndian);
}

float Binary_Script::read_float(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_float(nOffset, bIsBigEndian);
}

double Binary_Script::read_double(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_double(nOffset, bIsBigEndian);
}

float Binary_Script::read_float16(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_float16(nOffset, bIsBigEndian);
}

float Binary_Script::read_float32(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_float(nOffset, bIsBigEndian);
}

double Binary_Script::read_float64(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_double(nOffset, bIsBigEndian);
}

quint32 Binary_Script::read_uint24(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_uint24(nOffset, bIsBigEndian);
}

qint32 Binary_Script::read_int24(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_int24(nOffset, bIsBigEndian);
}

quint8 Binary_Script::read_bcd_uint8(qint64 nOffset)
{
    return m_pBinary->read_bcd_uint8(nOffset);
}

quint16 Binary_Script::read_bcd_uint16(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_bcd_uint16(nOffset, bIsBigEndian);
}

quint16 Binary_Script::read_bcd_uint32(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_bcd_uint32(nOffset, bIsBigEndian);
}

quint16 Binary_Script::read_bcd_uint64(qint64 nOffset, bool bIsBigEndian)
{
    return m_pBinary->read_bcd_uint64(nOffset, bIsBigEndian);
}

QString Binary_Script::getOperationSystemName()
{
    return XBinary::osNameIdToString(m_fileFormatInfo.osName);
}

QString Binary_Script::getOperationSystemVersion()
{
    return m_fileFormatInfo.sOsVersion;
}

QString Binary_Script::getOperationSystemOptions()
{
    QString sResult = QString("%1, %2, %3").arg(m_fileFormatInfo.sArch, XBinary::modeIdToString(m_fileFormatInfo.mode), m_fileFormatInfo.sType);

    if (m_fileFormatInfo.endian == XBinary::ENDIAN_BIG) {
        if (sResult != "") {
            sResult.append(", ");
        }
        sResult.append(XBinary::endianToString(XBinary::ENDIAN_BIG));
    }

    return sResult;
}

QString Binary_Script::getFileFormatName()
{
    // return XBinary::getFileFormatString(&m_fileFormatInfo);
    return XBinary::fileTypeIdToString(m_fileFormatInfo.fileType);
}

QString Binary_Script::getFileFormatVersion()
{
    return m_fileFormatInfo.sVersion;
}

QString Binary_Script::getFileFormatOptions()
{
    return m_sFileFormatInfoString;
}

bool Binary_Script::isSigned()
{
    return m_bIsSigned;
}

QString Binary_Script::cleanString(const QString &sString)
{
    return XBinary::cleanString(sString);
}

quint8 Binary_Script::U8(qint64 nOffset)
{
    return read_uint8(nOffset);
}

qint16 Binary_Script::I8(qint64 nOffset)
{
    return read_int8(nOffset);
}

quint16 Binary_Script::U16(qint64 nOffset, bool bIsBigEndian)
{
    return read_uint16(nOffset, bIsBigEndian);
}

qint16 Binary_Script::I16(qint64 nOffset, bool bIsBigEndian)
{
    return read_int16(nOffset, bIsBigEndian);
}

quint32 Binary_Script::U24(qint64 nOffset, bool bIsBigEndian)
{
    return read_uint24(nOffset, bIsBigEndian);
}

qint32 Binary_Script::I24(qint64 nOffset, bool bIsBigEndian)
{
    return read_int24(nOffset, bIsBigEndian);
}

quint32 Binary_Script::U32(qint64 nOffset, bool bIsBigEndian)
{
    return read_uint32(nOffset, bIsBigEndian);
}

qint32 Binary_Script::I32(qint64 nOffset, bool bIsBigEndian)
{
    return read_int32(nOffset, bIsBigEndian);
}

quint64 Binary_Script::U64(qint64 nOffset, bool bIsBigEndian)
{
    return read_uint64(nOffset, bIsBigEndian);
}

qint64 Binary_Script::I64(qint64 nOffset, bool bIsBigEndian)
{
    return read_int64(nOffset, bIsBigEndian);
}

float Binary_Script::F16(qint64 nOffset, bool bIsBigEndian)
{
    return read_float16(nOffset, bIsBigEndian);
}

float Binary_Script::F32(qint64 nOffset, bool bIsBigEndian)
{
    return read_float32(nOffset, bIsBigEndian);
}

double Binary_Script::F64(qint64 nOffset, bool bIsBigEndian)
{
    return read_float64(nOffset, bIsBigEndian);
}

QString Binary_Script::SA(qint64 nOffset, qint64 nMaxSize)
{
    return read_ansiString(nOffset, nMaxSize);
}

QString Binary_Script::SU16(qint64 nOffset, qint64 nMaxSize)
{
    return read_unicodeString(nOffset, nMaxSize);
}

QString Binary_Script::SU8(qint64 nOffset, qint64 nMaxSize)
{
    return read_utf8String(nOffset, nMaxSize);
}

QString Binary_Script::UCSD(qint64 nOffset)
{
    return read_ucsdString(nOffset);
}

QString Binary_Script::SC(qint64 nOffset, qint64 nMaxByteSize, const QString &sCodePage)
{
    return read_codePageString(nOffset, nMaxByteSize, sCodePage);
}

qint64 Binary_Script::Sz()
{
    return getSize();
}

qint64 Binary_Script::fSig(qint64 nOffset, qint64 nSize, const QString &sSignature)
{
    return findSignature(nOffset, nSize, sSignature);
}

qint64 Binary_Script::fStr(qint64 nOffset, qint64 nSize, const QString &sString)
{
    return findString(nOffset, nSize, sString);
}

bool Binary_Script::c(const QString &sSignature, qint64 nOffset)
{
    return compare(sSignature, nOffset);
}

QList<QVariant> Binary_Script::BA(qint64 nOffset, qint64 nSize, bool bReplaceZeroWithSpace)
{
    return readBytes(nOffset, nSize, bReplaceZeroWithSpace);
}

void Binary_Script::_fixOffsetAndSize(qint64 *pnOffset, qint64 *pnSize)
{
    if ((*pnOffset) < m_nSize) {
        if ((*pnOffset) + (*pnSize) > m_nSize) {
            *pnSize = m_nSize - (*pnOffset);
        }
    }
}

QElapsedTimer *Binary_Script::_startProfiling()
{
    QElapsedTimer *pResult = nullptr;

    if (m_pOptions->bIsProfiling) {
        pResult = new QElapsedTimer;
        pResult->start();
    }

    return pResult;
}

void Binary_Script::_finishProfiling(QElapsedTimer *pElapsedTimer, const QString &sInfo)
{
    if (m_pOptions->bIsProfiling) {
        qint64 nElapsed = pElapsedTimer->elapsed();
        delete pElapsedTimer;

        emit warningMessage(QString("%1 [%2 ms]").arg(sInfo, QString::number(nElapsed)));
    }
}

bool Binary_Script::_loadFmtChecking(bool bDeep, XBinary::PDSTRUCT *pPdStruct)
{
    if ((!m_bIsFmtCheckingDeep) && bDeep) {
        m_bIsFmtCheckingDeep = true;
        m_bIsFmtChecking = true;
        m_listFmtMsg = m_pBinary->checkFileFormat(true, pPdStruct);
        m_listFormatMessages = m_pBinary->getFileFormatMessages(&m_listFmtMsg);
    } else if (!m_bIsFmtChecking) {
        m_bIsFmtChecking = true;
        m_listFmtMsg = m_pBinary->checkFileFormat(false, pPdStruct);
        m_listFormatMessages = m_pBinary->getFileFormatMessages(&m_listFmtMsg);
    }

    return true;
}

qint64 Binary_Script::startTiming()
{
    quint32 nResult = 0;

    QElapsedTimer *pElapsedTimer = _startProfiling();

    nResult = XBinary::random32();

    m_mapProfiling.insert(nResult, pElapsedTimer);

    return nResult;
}

qint64 Binary_Script::endTiming(qint64 nHandle, const QString &sInfo)
{
    qint64 nResult = 0;

    if (m_mapProfiling.contains(nHandle)) {
        QElapsedTimer *pElapsedTimer = m_mapProfiling.value(nHandle);

        _finishProfiling(pElapsedTimer, sInfo);

        m_mapProfiling.remove(nHandle);
    } else {
        emit errorMessage(QString("%1: %2").arg(tr("Invalid handle"), QString::number(nHandle)));
    }

    return nResult;
}

qint64 Binary_Script::detectZLIB(qint64 nOffset, qint64 nSize)
{
    qint64 nResult = XFormats::getFileFormatSize(XBinary::FT_ZLIB, m_pBinary->getDevice(), false, -1, m_pPdStruct, nOffset, nSize);

    if (nResult) {
        return nResult;
    } else {
        return -1;
    }
}

qint64 Binary_Script::detectGZIP(qint64 nOffset, qint64 nSize)
{
    qint64 nResult = XFormats::getFileFormatSize(XBinary::FT_GZIP, m_pBinary->getDevice(), false, -1, m_pPdStruct, nOffset, nSize);

    if (nResult) {
        return nResult;
    } else {
        return -1;
    }
}

qint64 Binary_Script::detectZIP(qint64 nOffset, qint64 nSize)
{
    qint64 nResult = XFormats::getFileFormatSize(XBinary::FT_ZIP, m_pBinary->getDevice(), false, -1, m_pPdStruct, nOffset, nSize);

    if (nResult) {
        return nResult;
    } else {
        return -1;
    }
}

bool Binary_Script::isOverlay()
{
    return (m_filePart == XBinary::FILEPART_OVERLAY);
}

bool Binary_Script::isResource()
{
    return (m_filePart == XBinary::FILEPART_RESOURCE);
}

bool Binary_Script::isDebugData()
{
    return (m_filePart == XBinary::FILEPART_DEBUGDATA);
}

bool Binary_Script::isFilePart()
{
    return (m_filePart != XBinary::FILEPART_HEADER);
}

QList<QVariant> Binary_Script::readBytes(qint64 nOffset, qint64 nSize, bool bReplaceZeroWithSpace)
{
    QList<QVariant> listResult;

    QByteArray baData = m_pBinary->read_array_process(nOffset, nSize, m_pPdStruct);
    qint32 _nSize = baData.size();
    listResult.reserve(_nSize);

    for (qint32 i = 0; (i < _nSize) && XBinary::isPdStructNotCanceled(m_pPdStruct); i++) {
        if (bReplaceZeroWithSpace && baData.at(i) == 0) {
            listResult.append(32);
        } else {
            quint32 nRecord = (quint8)(baData.at(i));
            listResult.append(nRecord);
        }
    }

    return listResult;
}

QList<QVariant> Binary_Script::decompressBytes(qint64 nOffset, qint64 nSize, QString sCompressionMethod)
{
    QList<QVariant> listResult;

    XBinary::HANDLE_METHOD compressionMethod = XBinary::ftStringToHandleMethod(sCompressionMethod);

    if (compressionMethod != XBinary::HANDLE_METHOD_UNKNOWN) {
        QByteArray baData = XDecompress().decomressToByteArray(m_pBinary->getDevice(), nOffset, nSize, compressionMethod, m_pPdStruct);
        qint32 _nSize = baData.size();
        listResult.reserve(_nSize);

        for (qint32 i = 0; (i < _nSize) && XBinary::isPdStructNotCanceled(m_pPdStruct); i++) {
            quint32 nRecord = (quint8)(baData.at(i));
            listResult.append(nRecord);
        }
    } else {
        emit errorMessage(QString("%1: %2").arg(tr("Unknown compression method"), sCompressionMethod));
    }

    return listResult;
}

qint64 Binary_Script::getCompressedDataSize(qint64 nOffset, qint64 nSize, QString sCompressionMethod)
{
    qint64 nResult = 0;

    XBinary::HANDLE_METHOD compressionMethod = XBinary::ftStringToHandleMethod(sCompressionMethod);

    if (compressionMethod != XBinary::HANDLE_METHOD_UNKNOWN) {
        nResult = XDecompress().getCompressedDataSize(m_pBinary->getDevice(), nOffset, nSize, compressionMethod, m_pPdStruct);
    } else {
        emit errorMessage(QString("%1: %2").arg(tr("Unknown compression method"), sCompressionMethod));
    }

    return nResult;
}

QList<QString> Binary_Script::getListOfCompressionMethods()
{
    QList<QString> listResult;

    // Only without known unpacked size!
    listResult.append(XBinary::handleMethodToFtString(XBinary::HANDLE_METHOD_STORE));
    listResult.append(XBinary::handleMethodToFtString(XBinary::HANDLE_METHOD_BZIP2));
    listResult.append(XBinary::handleMethodToFtString(XBinary::HANDLE_METHOD_LZMA));
    listResult.append(XBinary::handleMethodToFtString(XBinary::HANDLE_METHOD_DEFLATE));
    listResult.append(XBinary::handleMethodToFtString(XBinary::HANDLE_METHOD_DEFLATE64));
    listResult.append(XBinary::handleMethodToFtString(XBinary::HANDLE_METHOD_IT214_8));
    listResult.append(XBinary::handleMethodToFtString(XBinary::HANDLE_METHOD_IT214_16));
    listResult.append(XBinary::handleMethodToFtString(XBinary::HANDLE_METHOD_IT215_8));
    listResult.append(XBinary::handleMethodToFtString(XBinary::HANDLE_METHOD_IT215_16));

    return listResult;
}

bool Binary_Script::isReleaseBuild()
{
    return m_pBinary->isReleaseBuild();
}

bool Binary_Script::isDebugBuild()
{
    return m_pBinary->isDebugBuild();
}

QStringList Binary_Script::getFormatMessages()
{
    _loadFmtChecking(true, m_pPdStruct);

    return m_listFormatMessages;
}

bool Binary_Script::isChecksumCorrect()
{
    _loadFmtChecking(true, m_pPdStruct);
    return !(XBinary::isFmtMsgCodePresent(&m_listFmtMsg, XBinary::FMT_MSG_CODE_INVALID_CHECKSUM, XBinary::FMT_MSG_TYPE_ERROR, m_pPdStruct));
}

bool Binary_Script::isEntryPointCorrect()
{
    _loadFmtChecking(false, m_pPdStruct);
    return !(XBinary::isFmtMsgCodePresent(&m_listFmtMsg, XBinary::FMT_MSG_CODE_INVALID_ENTRYPOINT, XBinary::FMT_MSG_TYPE_ERROR, m_pPdStruct));
}

bool Binary_Script::isSectionAlignmentCorrect()
{
    _loadFmtChecking(false, m_pPdStruct);
    return !(XBinary::isFmtMsgCodePresent(&m_listFmtMsg, XBinary::FMT_MSG_CODE_INVALID_SECTIONALIGNMENT, XBinary::FMT_MSG_TYPE_ERROR, m_pPdStruct));
}

bool Binary_Script::isFileAlignmentCorrect()
{
    _loadFmtChecking(false, m_pPdStruct);
    return !(XBinary::isFmtMsgCodePresent(&m_listFmtMsg, XBinary::FMT_MSG_CODE_INVALID_FILEALIGNMENT, XBinary::FMT_MSG_TYPE_ERROR, m_pPdStruct));
}

bool Binary_Script::isHeaderCorrect()
{
    _loadFmtChecking(false, m_pPdStruct);
    return !(XBinary::isFmtMsgCodePresent(&m_listFmtMsg, XBinary::FMT_MSG_CODE_INVALID_HEADER, XBinary::FMT_MSG_TYPE_ERROR, m_pPdStruct));
}

bool Binary_Script::isRelocsTableCorrect()
{
    _loadFmtChecking(false, m_pPdStruct);
    return !(XBinary::isFmtMsgCodePresent(&m_listFmtMsg, XBinary::FMT_MSG_CODE_INVALID_RELOCSTABLE, XBinary::FMT_MSG_TYPE_ERROR, m_pPdStruct));
}

bool Binary_Script::isImportTableCorrect()
{
    _loadFmtChecking(false, m_pPdStruct);
    return !(XBinary::isFmtMsgCodePresent(&m_listFmtMsg, XBinary::FMT_MSG_CODE_INVALID_IMPORTTABLE, XBinary::FMT_MSG_TYPE_ERROR, m_pPdStruct));
}

bool Binary_Script::isExportTableCorrect()
{
    _loadFmtChecking(false, m_pPdStruct);
    return !(XBinary::isFmtMsgCodePresent(&m_listFmtMsg, XBinary::FMT_MSG_CODE_INVALID_EXPORTTABLE, XBinary::FMT_MSG_TYPE_ERROR, m_pPdStruct));
}

bool Binary_Script::isResourcesTableCorrect()
{
    _loadFmtChecking(false, m_pPdStruct);
    return !(XBinary::isFmtMsgCodePresent(&m_listFmtMsg, XBinary::FMT_MSG_CODE_INVALID_RESOURCESTABLE, XBinary::FMT_MSG_TYPE_ERROR, m_pPdStruct));
}

bool Binary_Script::isSectionsTableCorrect()
{
    _loadFmtChecking(false, m_pPdStruct);
    return !(XBinary::isFmtMsgCodePresent(&m_listFmtMsg, XBinary::FMT_MSG_CODE_INVALID_SECTIONSTABLE, XBinary::FMT_MSG_TYPE_ERROR, m_pPdStruct));
}

XBinary::_MEMORY_MAP *Binary_Script::getMemoryMap()
{
    return &m_memoryMap;
}

XADDR Binary_Script::getBaseAddress()
{
    return m_nBaseAddress;
}

XBinary::PDSTRUCT *Binary_Script::getPdStruct()
{
    return m_pPdStruct;
}
