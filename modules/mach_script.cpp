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
#include "mach_script.h"

MACH_Script::MACH_Script(XMACH *pMACH, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : Binary_Script(pMACH, filePart, pOptions, pPdStruct)
{
    this->m_pMACH = pMACH;

    m_listLibraryRecords = pMACH->getLibraryRecords(XMACH_DEF::S_LC_LOAD_DYLIB);
    m_listSectionRecords = pMACH->getSectionRecords();
    m_listCommandRecords = pMACH->getCommandRecords();
    m_listSectionNameStrings = pMACH->getSectionNames(&m_listSectionRecords);

    m_nNumberOfSections = m_listSectionRecords.count();
    m_nNumberOfSegments = m_listSegmentRecords.count();
    m_nNumberOfCommands = m_listCommandRecords.count();

    bool bIs64 = pMACH->is64(getMemoryMap());

    m_sGeneralOptions = QString("%1%2").arg(XMACH::getHeaderFileTypesS().value(pMACH->getHeader_filetype())).arg(bIs64 ? ("64") : ("32"));
}

MACH_Script::~MACH_Script()
{
}

bool MACH_Script::isLibraryPresent(const QString &sLibraryName)
{
    return m_pMACH->isLibraryRecordNamePresent(sLibraryName, &m_listLibraryRecords);
}

quint32 MACH_Script::getNumberOfSections()
{
    return m_nNumberOfSections;
}

quint32 MACH_Script::getNumberOfSegments()
{
    return m_nNumberOfSegments;
}

qint32 MACH_Script::getSectionNumber(const QString &sSectionName)
{
    return m_pMACH->getSectionNumber(sSectionName, &m_listSectionRecords);
}

QString MACH_Script::getGeneralOptions()
{
    return m_sGeneralOptions;
}

quint32 MACH_Script::getLibraryCurrentVersion(const QString &sLibraryName)
{
    return m_pMACH->getLibraryCurrentVersion(sLibraryName, &m_listLibraryRecords);
}

quint64 MACH_Script::getSectionFileOffset(quint32 nNumber)
{
    return m_pMACH->getSectionFileOffset(nNumber, &m_listSectionRecords);
}

quint64 MACH_Script::getSectionFileSize(quint32 nNumber)
{
    return m_pMACH->getSectionFileSize(nNumber, &m_listSectionRecords);
}

bool MACH_Script::isSectionNamePresent(const QString &sSectionName)
{
    return XBinary::isStringInListPresent(&m_listSectionNameStrings, sSectionName);
}

quint32 MACH_Script::getNumberOfCommands()
{
    return m_nNumberOfCommands;
}

quint32 MACH_Script::getCommandId(quint32 nNumber)
{
    return m_pMACH->getCommandId(nNumber, &m_listCommandRecords);
}

bool MACH_Script::isCommandPresent(quint32 nNumber)
{
    return m_pMACH->isCommandPresent(nNumber, &m_listCommandRecords);
}
