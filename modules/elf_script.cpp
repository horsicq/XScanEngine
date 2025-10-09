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
#include "elf_script.h"

ELF_Script::ELF_Script(XELF *pELF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : Binary_Script(pELF, filePart, pOptions, pPdStruct)
{
    this->m_pELF = pELF;

    bool bIs64 = pELF->is64(getMemoryMap());

    m_elfHeader = pELF->getHdr();

    m_nStringTableSection = pELF->getSectionStringTable(bIs64);
    m_baStringTable = pELF->getSection(m_nStringTableSection);
    m_listSectionHeaders = pELF->getElf_ShdrList(100);  // TODO pdStruct
    m_listProgramHeaders = pELF->getElf_PhdrList(100);  // TODO pdStruct

    m_listNotes = pELF->getNotes(&m_listProgramHeaders);

    if (m_listNotes.count() == 0) {
        m_listNotes = pELF->getNotes(&m_listSectionHeaders);
    }

    m_listSectionRecords = pELF->getSectionRecords(&m_listSectionHeaders, bIs64, &m_baStringTable);
    m_listTagStruct = pELF->getTagStructs(&m_listProgramHeaders, getMemoryMap());
    m_listLibraryNames = pELF->getLibraries(getMemoryMap(), &m_listTagStruct);

    m_sRunPath = pELF->getRunPath(getMemoryMap(), &m_listTagStruct).sString;

    m_sGeneralOptions = QString("%1 %2-%3")
                            .arg(XELF::getTypesS().value(m_elfHeader.e_type))
                            .arg(XELF::getMachinesS().value(m_elfHeader.e_machine))
                            .arg(bIs64 ? ("64") : ("32"));  // TODO Check
}

ELF_Script::~ELF_Script()
{
}

bool ELF_Script::isSectionNamePresent(const QString &sSectionName)
{
    return m_pELF->isSectionNamePresent(sSectionName, &m_listSectionRecords);  // TODO get pdStruct
}

quint32 ELF_Script::getNumberOfSections()
{
    return m_elfHeader.e_shnum;
}

quint32 ELF_Script::getNumberOfPrograms()
{
    return m_elfHeader.e_phnum;
}

QString ELF_Script::getGeneralOptions()
{
    return m_sGeneralOptions;
}

qint32 ELF_Script::getSectionNumber(const QString &sSectionName)
{
    return m_pELF->getSectionNumber(sSectionName, &m_listSectionRecords);  // TODO get pdStruct
}

quint16 ELF_Script::getElfHeader_type()
{
    return m_elfHeader.e_type;
}

quint16 ELF_Script::getElfHeader_machine()
{
    return m_elfHeader.e_machine;
}

quint32 ELF_Script::getElfHeader_version()
{
    return m_elfHeader.e_version;
}

quint64 ELF_Script::getElfHeader_entry()
{
    return m_elfHeader.e_entry;
}

quint64 ELF_Script::getElfHeader_phoff()
{
    return m_elfHeader.e_phoff;
}

quint64 ELF_Script::getElfHeader_shoff()
{
    return m_elfHeader.e_shoff;
}

quint32 ELF_Script::getElfHeader_flags()
{
    return m_elfHeader.e_flags;
}

quint16 ELF_Script::getElfHeader_ehsize()
{
    return m_elfHeader.e_ehsize;
}

quint16 ELF_Script::getElfHeader_phentsize()
{
    return m_elfHeader.e_phentsize;
}

quint16 ELF_Script::getElfHeader_phnum()
{
    return m_elfHeader.e_phnum;
}

quint16 ELF_Script::getElfHeader_shentsize()
{
    return m_elfHeader.e_shentsize;
}

quint16 ELF_Script::getElfHeader_shnum()
{
    return m_elfHeader.e_shnum;
}

quint16 ELF_Script::getElfHeader_shstrndx()
{
    return m_elfHeader.e_shstrndx;
}

quint64 ELF_Script::getProgramFileSize(quint32 nNumber)
{
    return m_pELF->getElf_Phdr_filesz(nNumber, &m_listProgramHeaders);
}

quint64 ELF_Script::getProgramFileOffset(quint32 nNumber)
{
    return m_pELF->getElf_Phdr_offset(nNumber, &m_listProgramHeaders);
}

quint64 ELF_Script::getSectionFileOffset(quint32 nNumber)
{
    return m_pELF->getElf_Shdr_offset(nNumber, &m_listSectionHeaders);
}

quint64 ELF_Script::getSectionFileSize(quint32 nNumber)
{
    return m_pELF->getElf_Shdr_size(nNumber, &m_listSectionHeaders);
}

bool ELF_Script::isStringInTablePresent(const QString &sSectionName, const QString &sString)
{
    bool bResult = false;

    qint32 nSection = m_pELF->getSectionNumber(sSectionName, &m_listSectionRecords);

    if (nSection != -1) {
        bResult = (m_pELF->getStringsFromSection(nSection).key(sString, -1) != (quint32)-1);
    }

    return bResult;
}

bool ELF_Script::isNotePresent(const QString &sNote)
{
    return m_pELF->isNotePresent(&m_listNotes, sNote);
}

bool ELF_Script::isLibraryPresent(const QString &sLibraryName)
{
    return m_pELF->isStringInListPresent(&m_listLibraryNames, sLibraryName, getPdStruct());
}

QString ELF_Script::getRunPath()
{
    return m_sRunPath;
}
