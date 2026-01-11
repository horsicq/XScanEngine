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
#ifndef PE_SCRIPT_H
#define PE_SCRIPT_H

#include "msdos_script.h"
#include "xpe.h"

class PE_Script : public MSDOS_Script {
    Q_OBJECT

public:
    explicit PE_Script(XPE *pPE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
    ~PE_Script();

public slots:
    quint16 getNumberOfSections();
    QString getSectionName(quint32 nNumber);
    quint32 getSectionVirtualSize(quint32 nNumber);
    quint32 getSectionVirtualAddress(quint32 nNumber);
    quint32 getSectionFileSize(quint32 nNumber);
    quint32 getSectionFileOffset(quint32 nNumber);
    quint32 getSectionCharacteristics(quint32 nNumber);
    quint32 getNumberOfResources();
    bool isSectionNamePresent(const QString &sSectionName);
    bool _isSectionNamePresentExp(const QString &sSectionName);
    bool isNET();
    bool isNet();
    bool isPEPlus();
    virtual QString getGeneralOptions();
    quint32 getResourceIdByNumber(quint32 nNumber);
    QString getResourceNameByNumber(quint32 nNumber);
    qint64 getResourceOffsetByNumber(quint32 nNumber);
    qint64 getResourceSizeByNumber(quint32 nNumber);
    quint32 getResourceTypeByNumber(quint32 nNumber);
    bool isNETStringPresent(const QString &sString);
    bool isNetObjectPresent(const QString &sString);
    bool isNETUnicodeStringPresent(const QString &sString);
    bool isNetUStringPresent(const QString &sString);
    qint64 findSignatureInBlob_NET(const QString &sSignature);
    bool isSignatureInBlobPresent_NET(const QString &sSignature);
    bool isNetGlobalCctorPresent();
    bool isNetTypePresent(const QString &sTypeNamespace, const QString &sTypeName);
    bool isNetMethodPresent(const QString &sTypeNamespace, const QString &sTypeName, const QString &sMethodName);
    bool isNetFieldPresent(const QString &sTypeNamespace, const QString &sTypeName, const QString &sFieldName);
    QString getNetModuleName();
    QString getNetAssemblyName();
    qint32 getNumberOfImports();
    QString getImportLibraryName(quint32 nNumber);
    bool isLibraryPresent(const QString &sLibraryName, bool bCheckCase = false);
    bool isLibraryFunctionPresent(const QString &sLibraryName, const QString &sFunctionName);
    bool isFunctionPresent(const QString &sFunctionName);
    QString getImportFunctionName(quint32 nImport, quint32 nFunctionNumber);
    qint32 getImportSection();
    qint32 getExportSection();
    qint32 getResourceSection();
    qint32 getEntryPointSection();
    qint32 getRelocsSection();
    qint32 getTLSSection();
    quint8 getMajorLinkerVersion();
    quint8 getMinorLinkerVersion();
    QString getManifest();
    QString getVersionStringInfo(const QString &sKey);
    qint32 getNumberOfImportThunks(quint32 nNumber);
    qint64 getResourceNameOffset(const QString &sName);
    bool isResourceNamePresent(const QString &sName);
    bool isResourceGroupNamePresent(const QString &sName);
    bool isResourceGroupIdPresent(quint32 nID);
    QString getCompilerVersion();
    bool isConsole();
    bool isSignedFile();
    QString getSectionNameCollision(const QString &sString1, const QString &sString2);
    qint32 getSectionNumber(const QString &sSectionName);
    qint32 getSectionNumberExp(const QString &sSectionName);
    bool isDll();
    bool isDriver();
    QString getNETVersion();
    bool compareEP_NET(const QString &sSignature, qint64 nOffset = 0);
    quint32 getSizeOfCode();
    quint32 getSizeOfUninitializedData();
    QString getPEFileVersion(const QString &sFileName);
    QString getFileVersion();
    QString getFileVersionMS();
    qint64 calculateSizeOfHeaders();
    bool isExportFunctionPresent(const QString &sFunctionName);
    // bool isExportFunctionPresentExp(const QString &sFunctionName);
    qint32 getNumberOfExportFunctions();
    qint32 getNumberOfExports();
    QString getExportFunctionName(quint32 nNumber);
    QString getExportNameByNumber(quint32 nNumber);
    bool isExportPresent();
    bool isTLSPresent();
    bool isImportPresent();
    bool isResourcesPresent();
    quint32 getImportHash32();
    quint64 getImportHash64();
    bool isImportPositionHashPresent(qint32 nIndex, quint32 nHash);

    quint64 getImageFileHeader(const QString &sString);
    quint64 getImageOptionalHeader(const QString &sString);

private:
    XPE *m_pPE;
    qint32 m_nNumberOfSections;
    XPE::CLI_INFO m_cliInfo;
    bool m_bNetGlobalCctorPresent;
    QList<QString> m_listNetAnsiStrings;
    QList<QString> m_listNetUnicodeStrings;
    QList<XPE::RESOURCE_RECORD> m_listResourceRecords;
    qint32 m_nNumberOfResources;
    QList<XPE_DEF::IMAGE_SECTION_HEADER> m_listSectionHeaders;
    QList<XPE::SECTION_RECORD> m_listSectionRecords;
    QList<QString> m_listSectionNameStrings;
    QList<XPE::IMPORT_HEADER> m_listImportHeaders;
    QList<XPE::IMPORT_RECORD> m_listImportRecords;
    qint32 m_nNumberOfImports;
    qint32 m_nNumberOfExportFunctions;
    XPE::RESOURCES_VERSION m_resourcesVersion;
    bool m_bIsNETPresent;
    bool m_bIs64;
    bool m_bIsDll;
    bool m_bIsDriver;
    bool m_bIsConsole;
    bool m_bIsSignPresent;
    bool m_bIsExportPresent;
    bool m_bIsTLSPresent;
    bool m_bIsImportPresent;
    bool m_bIsResourcesPresent;
    QString m_sGeneralOptions;
    qint32 m_nImportSection;
    qint32 m_nExportSection;
    qint32 m_nResourcesSection;
    qint32 m_nEntryPointSection;
    qint32 m_nRelocsSection;
    qint32 m_nTLSSection;
    quint8 m_nMajorLinkerVersion;
    quint8 m_nMinorLinkerVersion;
    quint32 m_nSizeOfCode;
    quint32 m_nSizeOfUninitializedData;
    QString m_sCompilerVersion;
    QString m_sFileVersion;
    QString m_sFileVersionMS;
    qint32 m_nCalculateSizeOfHeaders;
    XPE::EXPORT_HEADER m_exportHeader;
    QList<QString> m_listExportFunctionNameStrings;
    quint64 m_nImportHash64;
    quint64 m_nImportHash32;
    QList<quint32> m_listImportPositionHashes;
    XPE_DEF::IMAGE_FILE_HEADER m_imageFileHeader;
    XPE_DEF::IMAGE_OPTIONAL_HEADER32 m_imageOptionalHeader32;
    XPE_DEF::IMAGE_OPTIONAL_HEADER64 m_imageOptionalHeader64;
    QString m_sNetModuleName;
    QString m_sNetAssemblyName;
};

#endif  // PE_SCRIPT_H
