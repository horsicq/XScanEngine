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
#ifndef MACH_SCRIPT_H
#define MACH_SCRIPT_H

#include "binary_script.h"
#include "xmach.h"

class MACH_Script : public Binary_Script {
    Q_OBJECT

public:
    MACH_Script(XMACH *pMACH, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
    ~MACH_Script();

public slots:
    bool isLibraryPresent(const QString &sLibraryName);
    quint32 getNumberOfSections();
    quint32 getNumberOfSegments();
    qint32 getSectionNumber(const QString &sSectionName);
    virtual QString getGeneralOptions();
    quint32 getLibraryCurrentVersion(const QString &sLibraryName);
    quint64 getSectionFileOffset(quint32 nNumber);
    quint64 getSectionFileSize(quint32 nNumber);
    bool isSectionNamePresent(const QString &sSectionName);
    quint32 getNumberOfCommands();
    quint32 getCommandId(quint32 nNumber);
    bool isCommandPresent(quint32 nNumber);

private:
    XMACH *m_pMACH;
    QString m_sGeneralOptions;
    QList<XMACH::LIBRARY_RECORD> m_listLibraryRecords;
    QList<XMACH::SECTION_RECORD> m_listSectionRecords;
    QList<XMACH::COMMAND_RECORD> m_listCommandRecords;
    QList<XMACH::SEGMENT_RECORD> m_listSegmentRecords;
    QList<QString> m_listSectionNameStrings;
    qint32 m_nNumberOfSections;
    qint32 m_nNumberOfSegments;
    qint32 m_nNumberOfCommands;
};

#endif  // MACH_SCRIPT_H
