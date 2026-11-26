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
#include "dex_script.h"

#include <QVector>
#include <cstring>

namespace {
// APKiD DEX: the walk of YARA 3.11's libyara/modules/dex.c that APKiD's rules see
// (xxfclib xx_dex_legacy_analyze, same quirks): a string value is the utf16_size
// bytes after the first byte of its string_data_item, and a member that cannot be
// resolved stops the current member list but not the class. Only the counts of
// field/method names that have a byte outside 0x00-0x7F are kept.
struct DexLegacyState {
    const quint8 *pData;
    quint64 nSize;
    QVector<qint64> listStringOffset;
    QVector<quint32> listStringValueSize;
    QVector<quint8> listStringUnicode;  // 0 unknown, 1 ASCII, 2 non-ASCII
    quint32 nStringCount;
    quint32 nFieldIdsSize;
    quint32 nFieldIdsOffset;
    quint32 nMethodIdsSize;
    quint32 nMethodIdsOffset;
};

const quint32 DEX_LEGACY_MAX_INDEX = 0x80000;

quint32 dexLegacyU32(const DexLegacyState *pDex, quint64 nOffset)
{
    const quint8 *p = pDex->pData + nOffset;
    return (quint32)p[0] | ((quint32)p[1] << 8) | ((quint32)p[2] << 16) | ((quint32)p[3] << 24);
}

bool dexLegacyFits(const DexLegacyState *pDex, quint64 nOffset, quint64 nSize)
{
    return (nSize <= pDex->nSize) && (nOffset <= pDex->nSize - nSize);
}

quint8 dexLegacyByte(const DexLegacyState *pDex, quint64 nOffset)
{
    return (nOffset < pDex->nSize) ? pDex->pData[nOffset] : 0;
}

// read_uleb128() of YARA 3.11: at most five bytes, no range checks.
quint32 dexLegacyUleb128(const DexLegacyState *pDex, quint64 nOffset, quint32 *pnSize)
{
    quint32 nResult = dexLegacyByte(pDex, nOffset++);
    ++*pnSize;
    if (nResult > 0x7f) {
        quint32 nCur = dexLegacyByte(pDex, nOffset++);
        ++*pnSize;
        nResult = (nResult & 0x7f) | ((nCur & 0x7f) << 7);
        if (nCur > 0x7f) {
            nCur = dexLegacyByte(pDex, nOffset++);
            ++*pnSize;
            nResult |= (nCur & 0x7f) << 14;
            if (nCur > 0x7f) {
                nCur = dexLegacyByte(pDex, nOffset++);
                ++*pnSize;
                nResult |= (nCur & 0x7f) << 21;
                if (nCur > 0x7f) {
                    nCur = dexLegacyByte(pDex, nOffset++);
                    ++*pnSize;
                    nResult |= nCur << 28;
                }
            }
        }
    }
    return nResult;
}

bool dexLegacyStringUnicode(DexLegacyState *pDex, quint32 nIndex, bool *pbDefined)
{
    *pbDefined = false;
    if ((nIndex > DEX_LEGACY_MAX_INDEX) || (nIndex >= pDex->nStringCount) || (pDex->listStringOffset[(qint32)nIndex] < 0)) return false;
    *pbDefined = true;
    if (pDex->listStringUnicode[(qint32)nIndex]) return pDex->listStringUnicode[(qint32)nIndex] == 2;
    quint64 nStart = (quint64)pDex->listStringOffset[(qint32)nIndex] + 1;
    quint64 nLength = pDex->listStringValueSize[(qint32)nIndex];
    quint64 nEnd = (nStart < pDex->nSize) ? ((nLength < pDex->nSize - nStart) ? (nStart + nLength) : pDex->nSize) : nStart;
    bool bUnicode = false;
    for (quint64 i = nStart; (i < nEnd) && !bUnicode; i++) bUnicode = (pDex->pData[i] & 0x80) != 0;
    pDex->listStringUnicode[(qint32)nIndex] = bUnicode ? 2 : 1;
    return bUnicode;
}

// load_encoded_field() / load_encoded_method(): the bytes consumed, 0 when the
// member cannot be loaded.
quint32 dexLegacyMember(DexLegacyState *pDex, quint64 nStart, quint32 *pnPrevious, bool bMethod, bool *pbNameUnicode)
{
    quint32 nUsed = 0;
    bool bDefined = false;
    *pbNameUnicode = false;
    if (!dexLegacyFits(pDex, nStart, bMethod ? 12 : 8)) return 0;
    quint32 nDiff = dexLegacyUleb128(pDex, nStart, &nUsed);
    (void)dexLegacyUleb128(pDex, nStart + nUsed, &nUsed);               // access_flags
    if (bMethod) (void)dexLegacyUleb128(pDex, nStart + nUsed, &nUsed);  // code_off
    *pnPrevious += nDiff;
    quint32 nCount = bMethod ? pDex->nMethodIdsSize : pDex->nFieldIdsSize;
    if ((*pnPrevious >= nCount) || (*pnPrevious > DEX_LEGACY_MAX_INDEX)) return 0;
    quint64 nItem = (quint64)(bMethod ? pDex->nMethodIdsOffset : pDex->nFieldIdsOffset) + (quint64)*pnPrevious * 8;
    quint32 nNameIdx = dexLegacyU32(pDex, nItem + 4);
    *pbNameUnicode = dexLegacyStringUnicode(pDex, nNameIdx, &bDefined) && bDefined;
    return nUsed;
}

void dexLegacyAnalyze(const quint8 *pData, quint64 nSize, qint64 *pnUnicodeFieldNames, qint64 *pnUnicodeMethodNames, bool *pbUnsortedStringPool)
{
    *pnUnicodeFieldNames = 0;
    *pnUnicodeMethodNames = 0;
    *pbUnsortedStringPool = false;
    if (nSize < 0x70) return;
    bool bParsed = false;
    const char *pszMagics[] = {"dex\n035", "dex\n036", "dex\n037", "dex\n038"};
    for (qint32 i = 0; (i < 4) && !bParsed; i++) bParsed = (memcmp(pData, pszMagics[i], 8) == 0);  // includes the NUL
    if (!bParsed) return;

    DexLegacyState dex;
    dex.pData = pData;
    dex.nSize = nSize;
    quint32 nStringIdsSize = dexLegacyU32(&dex, 0x38);
    quint32 nStringIdsOffset = dexLegacyU32(&dex, 0x3C);
    quint32 nTypeIdsSize = dexLegacyU32(&dex, 0x40);
    quint32 nTypeIdsOffset = dexLegacyU32(&dex, 0x44);
    quint32 nProtoIdsSize = dexLegacyU32(&dex, 0x48);
    quint32 nProtoIdsOffset = dexLegacyU32(&dex, 0x4C);
    quint32 nMapOffset = dexLegacyU32(&dex, 0x34);
    quint32 nClassDefsSize = dexLegacyU32(&dex, 0x60);
    quint32 nClassDefsOffset = dexLegacyU32(&dex, 0x64);
    dex.nFieldIdsSize = dexLegacyU32(&dex, 0x50);
    dex.nFieldIdsOffset = dexLegacyU32(&dex, 0x54);
    dex.nMethodIdsSize = dexLegacyU32(&dex, 0x58);
    dex.nMethodIdsOffset = dexLegacyU32(&dex, 0x5C);
    dex.nStringCount = 0;

    if (!dexLegacyFits(&dex, nStringIdsOffset, (quint64)nStringIdsSize * 4)) return;
    if (nStringIdsSize > 0x7FFFFFFF / 4) return;  // cannot fit in a file below 2 GiB
    dex.nStringCount = nStringIdsSize;
    dex.listStringOffset.resize((qint32)nStringIdsSize);
    dex.listStringValueSize.resize((qint32)nStringIdsSize);
    dex.listStringUnicode.fill(0, (qint32)nStringIdsSize);

    // unsorted_string_pool: a valid string_ids entry whose data offset is below the previous
    // valid entry's; an invalid entry resets the comparison.
    qint64 nPreviousOffset = -1;
    for (quint32 i = 0; i < nStringIdsSize; i++) {
        quint32 nOffset = dexLegacyU32(&dex, (quint64)nStringIdsOffset + (quint64)i * 4);
        quint32 nUnused = 0;
        dex.listStringOffset[(qint32)i] = -1;
        dex.listStringValueSize[(qint32)i] = 0;
        if (!dexLegacyFits(&dex, nOffset, 4)) {
            nPreviousOffset = -1;
            continue;
        }
        quint32 nValue = dexLegacyUleb128(&dex, nOffset, &nUnused);
        if (!dexLegacyFits(&dex, nOffset, nValue)) {
            nPreviousOffset = -1;
            continue;
        }
        dex.listStringOffset[(qint32)i] = nOffset;
        dex.listStringValueSize[(qint32)i] = nValue;
        if ((nPreviousOffset >= 0) && ((qint64)nOffset < nPreviousOffset)) *pbUnsortedStringPool = true;
        nPreviousOffset = nOffset;
    }

    // The remaining ID tables only gate the class data walk.
    if (!dexLegacyFits(&dex, nTypeIdsOffset, (quint64)nTypeIdsSize * 4) || !dexLegacyFits(&dex, nProtoIdsOffset, (quint64)nProtoIdsSize * 12) ||
        !dexLegacyFits(&dex, dex.nFieldIdsOffset, (quint64)dex.nFieldIdsSize * 8) || !dexLegacyFits(&dex, dex.nMethodIdsOffset, (quint64)dex.nMethodIdsSize * 8))
        return;
    if ((nMapOffset != 0) && dexLegacyFits(&dex, nMapOffset, 4) && !dexLegacyFits(&dex, nMapOffset, 4 + (quint64)dexLegacyU32(&dex, nMapOffset) * 12)) return;
    if (!dexLegacyFits(&dex, nClassDefsOffset, (quint64)nClassDefsSize * 32)) return;

    // Class data: dex.field[] and dex.method[] in YARA 3.11's order.
    quint64 nFieldIndex = 0;
    quint64 nMethodIndex = 0;
    for (quint32 i = 0; i < nClassDefsSize; i++) {
        quint32 nClassData = dexLegacyU32(&dex, (quint64)nClassDefsOffset + (quint64)i * 32 + 24);
        if (!nClassData) continue;
        if (!dexLegacyFits(&dex, nClassData, 16)) break;
        quint32 nUsed = 0;
        quint32 lists[4];
        for (qint32 k = 0; k < 4; k++) lists[k] = dexLegacyUleb128(&dex, (quint64)nClassData + nUsed, &nUsed);
        for (qint32 k = 0; k < 4; k++) {
            bool bMethod = (k >= 2);
            quint32 nPrevious = 0;
            for (quint32 j = 0; j < lists[k]; j++) {
                bool bUnicode = false;
                quint32 nConsumed = dexLegacyMember(&dex, (quint64)nClassData + nUsed, &nPrevious, bMethod, &bUnicode);
                if (!nConsumed) break;
                nUsed += nConsumed;
                if (bMethod) {
                    if (bUnicode && (nMethodIndex <= dex.nMethodIdsSize)) ++*pnUnicodeMethodNames;
                    ++nMethodIndex;
                } else {
                    if (bUnicode && (nFieldIndex <= dex.nFieldIdsSize)) ++*pnUnicodeFieldNames;
                    ++nFieldIndex;
                }
            }
        }
    }
}
}  // namespace

DEX_Script::DEX_Script(XDEX *pDex, XBinary::FILEPART filePart, const OPTIONS &scanOptions, XBinary::PDSTRUCT *pPdStruct)
    : Binary_Script(pDex, filePart, scanOptions, pPdStruct)
{
    this->m_pDex = pDex;
    m_MapItemsHash = 0;
    m_bLegacyDone = false;
    m_nLegacyUnicodeFieldNames = 0;
    m_nLegacyUnicodeMethodNames = 0;
    m_bLegacyUnsortedStringPool = false;

    m_listItems = pDex->getMapItems(pPdStruct);
    m_bIsStringPoolSorted = pDex->isStringPoolSorted(&m_listItems, pPdStruct);
    m_listStrings = pDex->getStrings(&m_listItems, pPdStruct);
    m_listItemStrings = pDex->getTypeItemStrings(&m_listItems, &m_listStrings, pPdStruct);
}

DEX_Script::~DEX_Script()
{
}

bool DEX_Script::isStringPoolSorted()
{
    return m_bIsStringPoolSorted;
}

bool DEX_Script::isDexStringPresent(const QString &sString)
{
    return m_pDex->isStringInListPresent(&m_listStrings, sString, getPdStruct());
}

bool DEX_Script::isDexItemStringPresent(const QString &sItemString)
{
    return m_pDex->isStringInListPresent(&m_listItemStrings, sItemString, getPdStruct());
}

quint32 DEX_Script::getMapItemsHash()
{
    if (m_MapItemsHash == 0) {
        m_MapItemsHash = XDEX::getMapItemsHash(&m_listItems, getPdStruct());
    }

    return m_MapItemsHash;
}

void DEX_Script::_analyzeLegacy()
{
    if (!m_bLegacyDone) {
        m_bLegacyDone = true;

        // Files above 2 GiB - 1 are not analysed (as in the C engine); the values stay 0/false.
        if ((m_pDex->getSize() > 0) && (m_pDex->getSize() <= 0x7FFFFFFF)) {
            QByteArray baData = m_pDex->read_array(0, m_pDex->getSize());

            if (baData.size() == m_pDex->getSize()) {
                dexLegacyAnalyze((const quint8 *)baData.constData(), (quint64)baData.size(), &m_nLegacyUnicodeFieldNames, &m_nLegacyUnicodeMethodNames,
                                 &m_bLegacyUnsortedStringPool);
            }
        }
    }
}

qint64 DEX_Script::getUnicodeMemberNameCount(const QString &sKind)
{
    _analyzeLegacy();

    qint64 nResult = 0;

    if (sKind == "field") {
        nResult = m_nLegacyUnicodeFieldNames;
    } else if (sKind == "method") {
        nResult = m_nLegacyUnicodeMethodNames;
    }

    return nResult;
}

bool DEX_Script::isDexStringPresentExp(const QString &sPattern)
{
    return XBinary::isStringInListPresentExp(&m_listStrings, sPattern, getPdStruct());
}

// False only when YARA 3.11's dex module parses the file (magic dex 035..038, whole header) and a
// valid string_ids entry of the header's table has a lower data offset than the previous valid one
// (CXAPKiD's unsorted_string_pool, APKiD dexlib 1.x). Unlike isStringPoolSorted() it does not go
// through the map list.
bool DEX_Script::isStringPoolSortedByHeader()
{
    _analyzeLegacy();

    return !m_bLegacyUnsortedStringPool;
}
