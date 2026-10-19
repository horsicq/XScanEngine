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
#include "native_scan_helpers.h"
#if defined(QT_QML_LIB) && !defined(QT_SCRIPT_LIB)
#include <QJSEngine>
#endif

#include <limits>

namespace {
const quint64 JAVASCRIPT_HISTORY_MASK = Q_UINT64_C(0x00FFFFFFFFFFFFFF);

enum JAVASCRIPT_LEX_STATE {
    JS_CODE = 0,
    JS_TOP_SINGLE,
    JS_TOP_DOUBLE,
    JS_TOP_TEMPLATE,
    JS_TOP_EXPRESSION,
    JS_TOP_EXPRESSION_SINGLE,
    JS_TOP_EXPRESSION_DOUBLE,
    JS_NESTED_TEMPLATE,
    JS_NESTED_EXPRESSION,
    JS_NESTED_EXPRESSION_SINGLE,
    JS_NESTED_EXPRESSION_DOUBLE
};

struct JAVASCRIPT_SEGMENT {
    quint64 nHistory = 0;
    quint32 nHistoryLength = 0;
    quint32 nPatternAState = 0;
    quint32 nPatternAPairs = 0;
    bool bHasBytes = false;
    bool bInvalidSpacing = false;
    bool bPatternAFound = false;
    bool bPatternBFound = false;
};

struct JAVASCRIPT_SCANNER {
    JAVASCRIPT_LEX_STATE state = JS_CODE;
    JAVASCRIPT_SEGMENT segment;
    quint64 nTopBraceDepth = 0;
    quint64 nNestedTemplateDepth = 0;
    bool bSkipNext = false;
    bool bTemplateDollar = false;
};

inline bool javascriptAsciiAlpha(quint8 nValue)
{
    return ((nValue >= (quint8)'A') && (nValue <= (quint8)'Z')) || ((nValue >= (quint8)'a') && (nValue <= (quint8)'z'));
}

inline bool javascriptAsciiWord(quint8 nValue)
{
    return javascriptAsciiAlpha(nValue) || ((nValue >= (quint8)'0') && (nValue <= (quint8)'9')) || (nValue == (quint8)'_');
}

inline quint8 javascriptHistoryByte(const JAVASCRIPT_SEGMENT &segment, quint32 nBack)
{
    return (quint8)(segment.nHistory >> (nBack * 8U));
}

bool javascriptHistoryIsKeyword(const JAVASCRIPT_SEGMENT &segment)
{
    if (segment.nHistoryLength >= 3U) {
        const quint8 a = javascriptHistoryByte(segment, 2U);
        const quint8 b = javascriptHistoryByte(segment, 1U);
        const quint8 c = javascriptHistoryByte(segment, 0U);
        if (((a == (quint8)'v') && (b == (quint8)'a') && (c == (quint8)'r')) ||
            ((a == (quint8)'l') && (b == (quint8)'e') && (c == (quint8)'t'))) {
            return true;
        }
    }

    return (segment.nHistoryLength >= 5U) && (javascriptHistoryByte(segment, 4U) == (quint8)'c') &&
           (javascriptHistoryByte(segment, 3U) == (quint8)'o') && (javascriptHistoryByte(segment, 2U) == (quint8)'n') &&
           (javascriptHistoryByte(segment, 1U) == (quint8)'s') && (javascriptHistoryByte(segment, 0U) == (quint8)'t');
}

inline void javascriptHistoryPush(JAVASCRIPT_SEGMENT *pSegment, quint8 nValue)
{
    pSegment->nHistory = ((pSegment->nHistory << 8U) | nValue) & JAVASCRIPT_HISTORY_MASK;
    if (pSegment->nHistoryLength < 7U) {
        pSegment->nHistoryLength++;
    }
}

bool javascriptPatternBEndsHere(const JAVASCRIPT_SEGMENT &segment)
{
    if (segment.nHistoryLength < 5U) {
        return false;
    }

    const quint8 nEnd = javascriptHistoryByte(segment, 0U);
    const quint8 nBit = javascriptHistoryByte(segment, 1U);
    if (((nEnd != (quint8)';') && (nEnd != (quint8)',') && (nEnd != (quint8)'}') && (nEnd != (quint8)')')) ||
        ((nBit != (quint8)'0') && (nBit != (quint8)'1')) || (javascriptHistoryByte(segment, 2U) != (quint8)'!')) {
        return false;
    }

    if ((javascriptHistoryByte(segment, 3U) == (quint8)'=') && javascriptAsciiAlpha(javascriptHistoryByte(segment, 4U))) {
        return true;
    }
    if ((segment.nHistoryLength >= 6U) && (javascriptHistoryByte(segment, 3U) == (quint8)'=') &&
        ((javascriptHistoryByte(segment, 4U) == (quint8)'!') || (javascriptHistoryByte(segment, 4U) == (quint8)'=')) &&
        javascriptAsciiAlpha(javascriptHistoryByte(segment, 5U))) {
        return true;
    }

    return (segment.nHistoryLength >= 7U) && (javascriptHistoryByte(segment, 3U) == (quint8)'=') &&
           (javascriptHistoryByte(segment, 4U) == (quint8)'=') &&
           ((javascriptHistoryByte(segment, 5U) == (quint8)'!') || (javascriptHistoryByte(segment, 5U) == (quint8)'=')) &&
           javascriptAsciiAlpha(javascriptHistoryByte(segment, 6U));
}

void javascriptSegmentFeed(JAVASCRIPT_SEGMENT *pSegment, quint8 nValue)
{
    pSegment->bHasBytes = true;

    if ((nValue == (quint8)'\t') ||
        ((nValue == (quint8)' ') && pSegment->nHistoryLength && (javascriptHistoryByte(*pSegment, 0U) == (quint8)' '))) {
        pSegment->bInvalidSpacing = true;
        return;
    }
    if (pSegment->bInvalidSpacing) {
        return;
    }

    switch (pSegment->nPatternAState) {
        case 1U:
            if (javascriptAsciiAlpha(nValue)) {
                pSegment->nPatternAState = 2U;
                pSegment->nPatternAPairs = 0U;
            } else {
                pSegment->nPatternAState = 0U;
            }
            break;
        case 2U:
            if (nValue == (quint8)',') {
                if (pSegment->nPatternAPairs >= 3U) {
                    pSegment->bPatternAFound = true;
                }
                pSegment->nPatternAState = 3U;
            } else {
                if ((pSegment->nPatternAPairs >= 3U) && !javascriptAsciiWord(nValue)) {
                    pSegment->bPatternAFound = true;
                }
                pSegment->nPatternAState = 0U;
            }
            break;
        case 3U:
            if (javascriptAsciiAlpha(nValue)) {
                pSegment->nPatternAPairs++;
                pSegment->nPatternAState = 2U;
            } else {
                pSegment->nPatternAState = 0U;
            }
            break;
        default: break;
    }

    const bool bStartsPatternA = (nValue == (quint8)'(') ||
                                 (((nValue == (quint8)' ') || (nValue == (quint8)'\t')) && javascriptHistoryIsKeyword(*pSegment));
    if (bStartsPatternA) {
        pSegment->nPatternAState = 1U;
        pSegment->nPatternAPairs = 0U;
    }

    javascriptHistoryPush(pSegment, nValue);
    if (javascriptPatternBEndsHere(*pSegment)) {
        pSegment->bPatternBFound = true;
    }
}

bool javascriptSegmentFinish(JAVASCRIPT_SEGMENT *pSegment)
{
    if (!pSegment->bInvalidSpacing && (pSegment->nPatternAState == 2U) && (pSegment->nPatternAPairs >= 3U)) {
        pSegment->bPatternAFound = true;
    }

    const bool bResult = pSegment->bHasBytes && !pSegment->bInvalidSpacing && (pSegment->bPatternAFound || pSegment->bPatternBFound);
    *pSegment = JAVASCRIPT_SEGMENT();
    return bResult;
}

// Returns 1 for a completed matching segment, 0 to continue, and -1 on depth overflow.
int javascriptScanByte(JAVASCRIPT_SCANNER *pScanner, quint8 nValue)
{
    if (pScanner->bSkipNext) {
        pScanner->bSkipNext = false;
        return 0;
    }

    if (pScanner->bTemplateDollar) {
        pScanner->bTemplateDollar = false;
        if (nValue == (quint8)'{') {
            if (pScanner->state == JS_TOP_TEMPLATE) {
                pScanner->nTopBraceDepth = 1U;
                pScanner->state = JS_TOP_EXPRESSION;
            } else {
                pScanner->state = JS_NESTED_EXPRESSION;
            }
            return 0;
        }
    }

    switch (pScanner->state) {
        case JS_CODE:
            if ((nValue == (quint8)'\'') || (nValue == (quint8)'"') || (nValue == (quint8)'`')) {
                const bool bResult = javascriptSegmentFinish(&pScanner->segment);
                pScanner->state = (nValue == (quint8)'\'') ? JS_TOP_SINGLE : ((nValue == (quint8)'"') ? JS_TOP_DOUBLE : JS_TOP_TEMPLATE);
                return bResult ? 1 : 0;
            }
            javascriptSegmentFeed(&pScanner->segment, nValue);
            return 0;

        case JS_TOP_SINGLE:
        case JS_TOP_DOUBLE:
            if (nValue == (quint8)'\\') {
                pScanner->bSkipNext = true;
            } else if (((pScanner->state == JS_TOP_SINGLE) && (nValue == (quint8)'\'')) ||
                       ((pScanner->state == JS_TOP_DOUBLE) && (nValue == (quint8)'"'))) {
                pScanner->state = JS_CODE;
            }
            return 0;

        case JS_TOP_TEMPLATE:
            if (nValue == (quint8)'\\') {
                pScanner->bSkipNext = true;
            } else if (nValue == (quint8)'`') {
                pScanner->state = JS_CODE;
            } else if (nValue == (quint8)'$') {
                pScanner->bTemplateDollar = true;
            }
            return 0;

        case JS_TOP_EXPRESSION:
            if (nValue == (quint8)'\\') {
                pScanner->bSkipNext = true;
            } else if (nValue == (quint8)'\'') {
                pScanner->state = JS_TOP_EXPRESSION_SINGLE;
            } else if (nValue == (quint8)'"') {
                pScanner->state = JS_TOP_EXPRESSION_DOUBLE;
            } else if (nValue == (quint8)'`') {
                pScanner->nNestedTemplateDepth = 1U;
                pScanner->state = JS_NESTED_TEMPLATE;
            } else if (nValue == (quint8)'{') {
                if (pScanner->nTopBraceDepth == (std::numeric_limits<quint64>::max)()) {
                    return -1;
                }
                pScanner->nTopBraceDepth++;
                javascriptSegmentFeed(&pScanner->segment, nValue);
            } else if (nValue == (quint8)'}') {
                if (pScanner->nTopBraceDepth > 1U) {
                    pScanner->nTopBraceDepth--;
                    javascriptSegmentFeed(&pScanner->segment, nValue);
                } else {
                    pScanner->nTopBraceDepth = 0U;
                    pScanner->state = JS_TOP_TEMPLATE;
                }
            } else {
                javascriptSegmentFeed(&pScanner->segment, nValue);
            }
            return 0;

        case JS_TOP_EXPRESSION_SINGLE:
        case JS_TOP_EXPRESSION_DOUBLE:
            if (nValue == (quint8)'\\') {
                pScanner->bSkipNext = true;
            } else if (((pScanner->state == JS_TOP_EXPRESSION_SINGLE) && (nValue == (quint8)'\'')) ||
                       ((pScanner->state == JS_TOP_EXPRESSION_DOUBLE) && (nValue == (quint8)'"'))) {
                pScanner->state = JS_TOP_EXPRESSION;
            }
            return 0;

        case JS_NESTED_TEMPLATE:
            if (nValue == (quint8)'\\') {
                pScanner->bSkipNext = true;
            } else if (nValue == (quint8)'`') {
                if (!pScanner->nNestedTemplateDepth) {
                    return -1;
                }
                pScanner->nNestedTemplateDepth--;
                pScanner->state = pScanner->nNestedTemplateDepth ? JS_NESTED_EXPRESSION : JS_TOP_EXPRESSION;
            } else if (nValue == (quint8)'$') {
                pScanner->bTemplateDollar = true;
            }
            return 0;

        case JS_NESTED_EXPRESSION:
            if (nValue == (quint8)'\\') {
                pScanner->bSkipNext = true;
            } else if (nValue == (quint8)'\'') {
                pScanner->state = JS_NESTED_EXPRESSION_SINGLE;
            } else if (nValue == (quint8)'"') {
                pScanner->state = JS_NESTED_EXPRESSION_DOUBLE;
            } else if (nValue == (quint8)'`') {
                if (pScanner->nNestedTemplateDepth == (std::numeric_limits<quint64>::max)()) {
                    return -1;
                }
                pScanner->nNestedTemplateDepth++;
                pScanner->state = JS_NESTED_TEMPLATE;
            } else if (nValue == (quint8)'}') {
                pScanner->state = JS_NESTED_TEMPLATE;
            }
            return 0;

        case JS_NESTED_EXPRESSION_SINGLE:
        case JS_NESTED_EXPRESSION_DOUBLE:
            if (nValue == (quint8)'\\') {
                pScanner->bSkipNext = true;
            } else if (((pScanner->state == JS_NESTED_EXPRESSION_SINGLE) && (nValue == (quint8)'\'')) ||
                       ((pScanner->state == JS_NESTED_EXPRESSION_DOUBLE) && (nValue == (quint8)'"'))) {
                pScanner->state = JS_NESTED_EXPRESSION;
            }
            return 0;
    }

    return -1;
}

bool javascriptIsMinified(XBinary *pBinary, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct, quint64 nExpectedDeviceGeneration)
{
    if (!pBinary || (nOffset < 0)) {
        return false;
    }

    const qint64 nTotalSize = pBinary->getSize();
    if ((nTotalSize < 0) || (nOffset >= nTotalSize)) {
        return false;
    }
    if ((nSize < 0) || (nSize > (nTotalSize - nOffset))) {
        nSize = nTotalSize - nOffset;
    }
    if (nSize <= 0) {
        return false;
    }

    const XBinary::PDSTRUCTLIFETIME progressLifetime = pPdStruct ? XBinary::retainPdStructLifetime(pPdStruct) : XBinary::PDSTRUCTLIFETIME();
    const auto isOperationAlive = [&]() {
        return (!pPdStruct || XBinary::isPdStructLifetimeAlive(progressLifetime)) && XBinary::isPdStructNotCanceled(pPdStruct) &&
               (pBinary->getDeviceGeneration() == nExpectedDeviceGeneration);
    };
    if (!isOperationAlive()) {
        return false;
    }

    const qint32 nRequestedBufferSize = XBinary::getBufferSize(pPdStruct);
    if (nRequestedBufferSize <= 0) {
        return false;
    }
    const qint32 nBufferSize = qBound((qint32)0x1000, nRequestedBufferSize, (qint32)0x100000);

    QByteArray baBuffer;
    baBuffer.resize((qint32)qMin<qint64>(nSize, nBufferSize));
    if (baBuffer.isEmpty()) {
        return false;
    }

    JAVASCRIPT_SCANNER scanner;
    qint64 nDone = 0;
    while (nDone < nSize) {
        if (!isOperationAlive()) {
            return false;
        }

        const qint32 nChunkSize = (qint32)qMin<qint64>(nSize - nDone, baBuffer.size());
        const qint64 nRead = pBinary->read_array_process(nOffset + nDone, baBuffer.data(), nChunkSize, pPdStruct);
        if ((nRead != nChunkSize) || !isOperationAlive()) {
            return false;
        }

        const quint8 *pBytes = reinterpret_cast<const quint8 *>(baBuffer.constData());
        for (qint32 i = 0; i < nChunkSize; i++) {
            if (((i & 0xffff) == 0) && !isOperationAlive()) {
                return false;
            }
            if (!pBytes[i]) {
                const bool bResult = javascriptSegmentFinish(&scanner.segment);
                return bResult && isOperationAlive();
            }

            const int nStatus = javascriptScanByte(&scanner, pBytes[i]);
            if (nStatus > 0) {
                return isOperationAlive();
            }
            if (nStatus < 0) {
                return false;
            }
        }

        nDone += nChunkSize;
    }

    const bool bResult = javascriptSegmentFinish(&scanner.segment);
    return bResult && isOperationAlive();
}
}  // namespace

Binary_Script::Binary_Script(XBinary *pBinary, XBinary::FILEPART filePart, const OPTIONS &scanOptions, XBinary::PDSTRUCT *pPdStruct)
{
    this->m_pBinary = pBinary;
    this->m_filePart = filePart;
    this->m_pPdStruct = pPdStruct;
    this->m_scanOptions = scanOptions;

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
    m_sOperationSystemInfoString = XBinary::getOperationSystemInfoString(&m_fileFormatInfo);
    m_sFileFormatInfoString = XBinary::getFileFormatInfoString(&m_fileFormatInfo);

    m_bIsFmtChecking = false;
    m_bIsFmtCheckingDeep = false;

    m_disasmOptions = {};
    m_disasmOptions.bIsUppercase = true;
    m_disasmCore.setMode(XBinary::getDisasmMode(&m_memoryMap));
    m_disasmInfoCache.setMaxCost(256);
    m_disasmInfoMode = m_disasmCore.getDisasmMode();
    m_nPrimitiveDeviceGeneration = m_pBinary->getDeviceGeneration();
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
        bResult = m_pBinary->compareSignatureStrings(m_sHeaderSignature.mid((int)((quint64)nOffset * 2), (int)((quint64)nSignatureSize * 2)), _sSignature);
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

QVariantList Binary_Script::findSignatures(double offset, double size, const QStringList &signatures)
{
    QVariantList result;
    const double maxSafe = 9007199254740991.0;
    if (!(offset >= -maxSafe && offset <= maxSafe && size >= -maxSafe && size <= maxSafe)) return result;
    qint64 nOffset = (qint64)offset, nSize = (qint64)size;
    if ((double)nOffset != offset || (double)nSize != size) return result;
    _fixOffsetAndSize(&nOffset, &nSize);
    const QList<qint64> offsets = m_pBinary->find_signatures(&m_memoryMap, nOffset, nSize, signatures, m_pPdStruct);
    for (qint64 found : offsets) {
        if (found > Q_INT64_C(9007199254740991)) return QVariantList();
        result.append(QVariant((double)found));
    }
    return result;
}

QVariant Binary_Script::findAnyBytes(const QVariant &offset, const QVariant &size, const QVariant &sourcePatterns)
{
    qint64 start, length;
    const QVariant patternInput = XScanNative::plainValue(sourcePatterns);
    QVector<QByteArray> patterns;
    if (m_pBinary->getDeviceGeneration() != m_nPrimitiveDeviceGeneration || !XScanNative::strictRange(offset, size, m_nSize, &start, &length) ||
        patternInput.type() != QVariant::List || !XScanNative::bytePatterns(patternInput.toList(), &patterns) || patterns.isEmpty() || !length)
        return XScanNative::nullResult();
    const XBinary::PDSTRUCTLIFETIME lifetime = XBinary::retainPdStructLifetime(m_pPdStruct);
    const auto alive = [&]() {
        return (!m_pPdStruct || XBinary::isPdStructLifetimeAlive(lifetime)) && XBinary::isPdStructNotCanceled(m_pPdStruct) &&
               m_pBinary->getDeviceGeneration() == m_nPrimitiveDeviceGeneration;
    };
    int overlap = 0;
    for (const QByteArray &pattern : patterns) overlap = qMax(overlap, pattern.size() - 1);
    for (qint64 cursor = 0; cursor < length;) {
        if (!alive()) return XScanNative::nullResult();
        const int candidates = (int)qMin(Q_INT64_C(65536), length - cursor);
        const int readSize = (int)qMin((qint64)candidates + overlap, length - cursor);
        const QByteArray data = m_pBinary->read_array_process(start + cursor, readSize, m_pPdStruct);
        if (!alive() || data.size() != readSize) return XScanNative::nullResult();
        const XScanNative::ByteHit found = XScanNative::findAny(data, candidates, patterns);
        if (found.offset >= 0) {
            const qint64 absolute = start + cursor + found.offset;
            if ((quint64)absolute > XScanNative::MaxSafeInteger) return XScanNative::nullResult();
            QVariantMap result;
            result.insert(QStringLiteral("offset"), (double)absolute);
            result.insert(QStringLiteral("patternIndex"), found.patternIndex);
            return result;
        }
        cursor += candidates;
    }
    return XScanNative::nullResult();
}

bool Binary_Script::_findByteRelationCandidates(const QVariant &offset, const QVariant &size, const QVariant &sourceGroups, const QVariant &tail,
                                                QVector<quint32> *result)
{
    qint64 start, length;
    quint64 tailBytes;
    if (m_pBinary->getDeviceGeneration() != m_nPrimitiveDeviceGeneration || !XScanNative::strictRange(offset, size, m_nSize, &start, &length) ||
        (quint64)length > XScanNative::MaxRelationBytes || !XScanNative::unsignedValue(tail, &tailBytes, 0xffffffffu))
        return false;
    const QVariant groupInput = XScanNative::plainValue(sourceGroups);
    QVector<XScanNative::RelationGroup> groups;
    if (groupInput.type() != QVariant::List || !XScanNative::relationGroups(groupInput.toList(), (quint32)tailBytes, &groups)) return false;
    const XBinary::PDSTRUCTLIFETIME lifetime = XBinary::retainPdStructLifetime(m_pPdStruct);
    const auto alive = [&]() {
        return (!m_pPdStruct || XBinary::isPdStructLifetimeAlive(lifetime)) && XBinary::isPdStructNotCanceled(m_pPdStruct) &&
               m_pBinary->getDeviceGeneration() == m_nPrimitiveDeviceGeneration;
    };
    if (!alive()) return false;
    if (groups.isEmpty() || tailBytes >= (quint64)length) return true;
    const QByteArray data = m_pBinary->read_array_process(start, length, m_pPdStruct);
    if (!alive() || data.size() != length) return false;
    bool completed = false;
    *result = XScanNative::relations(data, groups, (quint32)tailBytes, &completed, alive);
    return completed && alive();
}

#if defined(QT_QML_LIB) && !defined(QT_SCRIPT_LIB)
QJSValue Binary_Script::findByteRelationCandidates(const QVariant &offset, const QVariant &size, const QVariant &groups, const QVariant &tailBytes)
{
    QJSEngine *engine = qjsEngine(this);
    QVector<quint32> values;
    if (!engine || !_findByteRelationCandidates(offset, size, groups, tailBytes, &values)) return QJSValue(QJSValue::NullValue);
    QJSValue result = engine->globalObject().property(QStringLiteral("Uint32Array")).callAsConstructor({QJSValue(static_cast<double>(values.size()))});
    if (result.isError() || result.property(QStringLiteral("length")).toUInt() != (uint)values.size()) return QJSValue(QJSValue::NullValue);
    for (int i = 0; i < values.size(); ++i) result.setProperty((quint32)i, QJSValue((double)values[i]));
    return result;
}
#else
QVariant Binary_Script::findByteRelationCandidates(const QVariant &offset, const QVariant &size, const QVariant &groups, const QVariant &tailBytes)
{
    QVector<quint32> values;
    if (!_findByteRelationCandidates(offset, size, groups, tailBytes, &values)) return XScanNative::nullResult();
    // QtScript implements ES3 and has no typed arrays. Keep the same flat uint32 sequence.
    QVariantList result;
    result.reserve(values.size());
    for (quint32 value : values) result.append((double)value);
    return result;
}
#endif

qint64 Binary_Script::findSignature(qint64 nOffset, qint64 nSize, const QString &sSignature)
{
    qint64 nResult = -1;

    QElapsedTimer *pTimer = _startProfiling();

    qint64 nResultSize = 0;

    _fixOffsetAndSize(&nOffset, &nSize);

    // qDebug() << "findSignature START - Signature:" << sSignature << "Offset:" << XBinary::valueToHexEx(nOffset) << "Size:" << XBinary::valueToHexEx(nSize);

    // QElapsedTimer timer;
    // timer.start();

    nResult = m_pBinary->find_signature(&m_memoryMap, nOffset, nSize, sSignature, &nResultSize, m_pPdStruct);

    // qint64 nElapsed = timer.elapsed();
    // qDebug() << "findSignature END - Signature:" << sSignature << "Result:" << XBinary::valueToHexEx(nResult) << "Time:" << nElapsed << "ms";

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

bool Binary_Script::isJavaScriptMinified()
{
    QElapsedTimer *pTimer = _startProfiling();
    const bool bResult = javascriptIsMinified(m_pBinary, 0, m_nSize, m_pPdStruct, m_nPrimitiveDeviceGeneration);

    if (pTimer) {
        _finishProfiling(pTimer, QStringLiteral("isJavaScriptMinified"));
    }

    return bResult;
}

bool Binary_Script::isZeroFilled(qint64 nOffset, qint64 nSize)
{
    if (nSize <= 0) {
        return false;
    }

    return m_pBinary->isZeroFilled(nOffset, nSize, m_pPdStruct);
}

QString Binary_Script::scanBufferForEncryptedPe(const QVariant &varData, qint64 nSize)
{
    if (varData.type() == QVariant::ByteArray) {
        QByteArray ba = varData.toByteArray();
        qint64 sz = (nSize >= 0 && nSize <= ba.size()) ? nSize : ba.size();
        return XBinary::scanBufferForEncryptedPe(ba.constData(), sz);
    } else if (varData.canConvert<QVariantList>()) {
        QVariantList list = varData.toList();
        qint32 count = (nSize >= 0 && nSize <= list.size()) ? (qint32)nSize : list.size();
        QByteArray ba;
        ba.resize(count);
        char *pData = ba.data();
        for (qint32 i = 0; i < count; i++) {
            pData[i] = (char)(list.at(i).toUInt() & 0xFF);
        }
        return XBinary::scanBufferForEncryptedPe(ba.constData(), count);
    } else if (varData.canConvert<qint64>() && (nSize > 0)) {
        qint64 nOffset = varData.toLongLong();
        return scanBufferForEncryptedPe(nOffset, nSize);
    }

    return QString();
}

QString Binary_Script::scanBufferForEncryptedPe(qint64 nOffset, qint64 nSize)
{
    if (nSize <= 0) {
        return QString();
    }

    return m_pBinary->scanBufferForEncryptedPe(nOffset, nSize, m_pPdStruct);
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

#if defined(QT_SCRIPT_LIB)
bool Binary_Script::isAnySignatureInSectionPresent(quint32 nNumber, const QScriptValue &sourceSignatures)
#elif defined(QT_QML_LIB)
bool Binary_Script::isAnySignatureInSectionPresent(quint32 nNumber, const QJSValue &sourceSignatures)
#else
bool Binary_Script::isAnySignatureInSectionPresent(quint32 nNumber, const QVariantList &sourceSignatures)
#endif
{
    QStringList signatures;
#if defined(QT_SCRIPT_LIB) || defined(QT_QML_LIB)
    if (!sourceSignatures.isArray()) return false;
    const quint32 nCount = (quint32)sourceSignatures.property(QStringLiteral("length")).toNumber();
    if (!nCount || nCount > 0x7fffffffu) return false;
    signatures.reserve((int)nCount);
    for (quint32 i = 0; i < nCount; ++i) {
        const auto signature = sourceSignatures.property(i);
        if (!signature.isString()) return false;
        signatures.append(signature.toString());
    }
#else
    if (sourceSignatures.isEmpty() || sourceSignatures.size() > 0x7fffffff) return false;
    signatures.reserve(sourceSignatures.size());
    for (const QVariant &signature : sourceSignatures) {
        if (signature.type() != QVariant::String) return false;
        signatures.append(signature.toString());
    }
#endif
    return _isAnySignatureInSectionPresent(nNumber, signatures);
}

bool Binary_Script::_isAnySignatureInSectionPresent(quint32 nNumber, const QStringList &signatures)
{
    if (m_pBinary->getDeviceGeneration() != m_nPrimitiveDeviceGeneration) return false;
    qint64 nFilePartNumber = nNumber;
    if (QString::fromLatin1(metaObject()->className()) == QLatin1String("PE_Script")) ++nFilePartNumber;
    if (nFilePartNumber > 0x7fffffff) return false;

    QElapsedTimer *pTimer = _startProfiling();
    const bool bResult = m_pBinary->isAnySignatureInFilePartPresent(&m_memoryMap, (qint32)nFilePartNumber, signatures, m_pPdStruct);
    if (pTimer) {
        _finishProfiling(pTimer, QString("isAnySignatureInSectionPresent[%1 patterns]: %2").arg(signatures.size()).arg(nNumber));
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

QVariant Binary_Script::getDisasmInfo(const QVariant &address)
{
    quint64 va;
    if (!XScanNative::unsignedValue(address, &va, XScanNative::MaxSafeInteger) || !XBinary::isPdStructNotCanceled(m_pPdStruct) ||
        m_pBinary->getDeviceGeneration() != m_nPrimitiveDeviceGeneration) {
        m_disasmInfoCache.clear();
        return XScanNative::nullResult();
    }
    const XBinary::DM mode = XBinary::getDisasmMode(&m_memoryMap);
    if (mode != m_disasmInfoMode) {
        m_disasmInfoCache.clear();
        m_disasmCore.setMode(mode);
        m_disasmInfoMode = mode;
    }
    if (mode != XBinary::DM_8086 && mode != XBinary::DM_X86_32 && mode != XBinary::DM_X86_64) return XScanNative::nullResult();
    const qint64 offset = XBinary::addressToOffset(&m_memoryMap, (qint64)va);
    if (offset < 0 || offset >= m_nSize) return XScanNative::nullResult();
    if (QVariantMap *cached = m_disasmInfoCache.object((qint64)va)) return *cached;
    const XDisasmAbstract::DISASM_RESULT decoded = m_disasmCore.disAsm(m_pBinary->getDevice(), offset, va, m_disasmOptions);
    if (!decoded.bIsValid || decoded.bMemError || decoded.nSize < 1 || decoded.nSize > 15 || decoded.nSize > m_nSize - offset ||
        decoded.nNextAddress > XScanNative::MaxSafeInteger || m_pBinary->getDeviceGeneration() != m_nPrimitiveDeviceGeneration)
        return XScanNative::nullResult();
    QString text = decoded.sMnemonic;
    if (!decoded.sOperands.isEmpty()) text += " " + decoded.sOperands;
    QVariantMap result;
    result.insert(QStringLiteral("text"), text);
    result.insert(QStringLiteral("length"), decoded.nSize);
    result.insert(QStringLiteral("nextAddress"), (double)decoded.nNextAddress);
    m_disasmInfoCache.insert((qint64)va, new QVariantMap(result));
    return result;
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

bool Binary_Script::is8()
{
    return XBinary::is8(&m_memoryMap);
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
    return m_scanOptions.bIsDeepScan;
}

bool Binary_Script::isHeuristicScan()
{
    return m_scanOptions.bIsHeuristicScan;
}

bool Binary_Script::isFirstWrapperScan()
{
    return m_scanOptions.bIsFirstWrapperScan;
}

bool Binary_Script::isAggressiveScan()
{
    return m_scanOptions.bIsAggressiveScan;
}

bool Binary_Script::isRecursiveScan()
{
    return m_scanOptions.bIsRecursiveScan;
}

bool Binary_Script::isOverlayScan()
{
    return m_scanOptions.bIsOverlayScan;
}

bool Binary_Script::isVerbose()
{
    return m_scanOptions.bIsVerbose;
}

bool Binary_Script::isProfiling()
{
    return m_scanOptions.bIsProfiling;
}

QString Binary_Script::getScanID()
{
    return m_scanOptions.sScanID;
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
    return m_sOperationSystemInfoString;
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

    if (m_scanOptions.bIsProfiling) {
        pResult = new QElapsedTimer;
        pResult->start();
    }

    return pResult;
}

void Binary_Script::_finishProfiling(QElapsedTimer *pElapsedTimer, const QString &sInfo)
{
    if (m_scanOptions.bIsProfiling) {
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
        emit errorMessage(QString("%1: %2").arg(tr("Invalid handle")).arg(QString::number(nHandle)));
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
        emit errorMessage(QString("%1: %2").arg(tr("Unknown compression method")).arg(sCompressionMethod));
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
        emit errorMessage(QString("%1: %2").arg(tr("Unknown compression method")).arg(sCompressionMethod));
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
