/* Copyright (c) 2019-2025 hors<horsicq@gmail.com>
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
#include "msdos_script.h"

MSDOS_Script::MSDOS_Script(XMSDOS *pMSDOS, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : Binary_Script(pMSDOS, filePart, pOptions, pPdStruct)
{
    this->m_pMSDOS = pMSDOS;

    m_bIsLE = pMSDOS->isLE();
    m_bIsLX = pMSDOS->isLX();
    m_bIsNE = pMSDOS->isNE();
    m_bIsPE = pMSDOS->isPE();

    m_nNumberOfRichIDs = 0;
    m_bIisRichSignaturePresent = false;

    if (m_bIsLE || m_bIsPE) {
        m_bIisRichSignaturePresent = pMSDOS->isRichSignaturePresent();

        if (m_bIisRichSignaturePresent) {
            m_listRich = pMSDOS->getRichSignatureRecords();

            m_nNumberOfRichIDs = m_listRich.count();
        }
    }

    m_nDosStubOffset = 0;
    m_nDosStubSize = 0;
    m_bIsDosStubPresent = false;

    if (m_bIsLE || m_bIsLX || m_bIsNE || m_bIsPE) {
        m_bIsDosStubPresent = pMSDOS->isDosStubPresent();

        if (m_bIsDosStubPresent) {
            m_nDosStubOffset = pMSDOS->getDosStubOffset();
            m_nDosStubSize = pMSDOS->getDosStubSize();
        }
    }
}

MSDOS_Script::~MSDOS_Script()
{
}

bool MSDOS_Script::isLE()
{
    return m_bIsLE;
}

bool MSDOS_Script::isLX()
{
    return m_bIsLX;
}

bool MSDOS_Script::isNE()
{
    return m_bIsNE;
}

bool MSDOS_Script::isPE()
{
    return m_bIsPE;
}

qint64 MSDOS_Script::getDosStubOffset()
{
    return m_nDosStubOffset;
}

qint64 MSDOS_Script::getDosStubSize()
{
    return m_nDosStubSize;
}

bool MSDOS_Script::isDosStubPresent()
{
    return m_bIsDosStubPresent;
}

qint32 MSDOS_Script::getNumberOfRichIDs()
{
    return m_nNumberOfRichIDs;
}

bool MSDOS_Script::isRichVersionPresent(quint32 nVersion)
{
    return m_pMSDOS->isRichVersionPresent(nVersion, &m_listRich);
}

quint32 MSDOS_Script::getRichVersion(qint32 nPosition)
{
    return m_pMSDOS->getRichVersion(&m_listRich, nPosition);
}

quint32 MSDOS_Script::getRichID(qint32 nPosition)
{
    return m_pMSDOS->getRichID(&m_listRich, nPosition);
}

quint32 MSDOS_Script::getRichCount(qint32 nPosition)
{
    return m_pMSDOS->getRichCount(&m_listRich, nPosition);
}

bool MSDOS_Script::isRichSignaturePresent()
{
    return m_bIisRichSignaturePresent;
}
