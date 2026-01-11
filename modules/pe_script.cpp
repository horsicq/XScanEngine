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
#include "pe_script.h"

PE_Script::PE_Script(XPE *pPE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : MSDOS_Script(pPE, filePart, pOptions, pPdStruct)
{
    m_pPE = pPE;

    m_nNumberOfSections = m_pPE->getFileHeader_NumberOfSections();
    m_listSectionHeaders = m_pPE->getSectionHeaders(getPdStruct());
    m_listSectionRecords = m_pPE->getSectionRecords(&m_listSectionHeaders, getPdStruct());
    m_listSectionNameStrings = m_pPE->getSectionNames(&m_listSectionRecords, getPdStruct());
    m_cliInfo = m_pPE->getCliInfo(true, getMemoryMap(), getPdStruct());
    m_bNetGlobalCctorPresent = m_pPE->isNetGlobalCctorPresent(&m_cliInfo, getPdStruct());

    if (m_cliInfo.bValid) {
        m_listNetAnsiStrings = m_pPE->getAnsiStrings(&m_cliInfo, getPdStruct());
        m_listNetUnicodeStrings = m_pPE->getUnicodeStrings(&m_cliInfo, getPdStruct());
        m_sNetModuleName = m_pPE->getMetadataModuleName(&m_cliInfo, 0);
        m_sNetAssemblyName = m_pPE->getMetadataAssemblyName(&m_cliInfo, 0);
    }

    m_listResourceRecords = m_pPE->getResources(getMemoryMap(), 10000, getPdStruct());
    m_resourcesVersion = m_pPE->getResourcesVersion(&m_listResourceRecords, getPdStruct());
    m_nNumberOfResources = m_listResourceRecords.count();
    m_listImportHeaders = m_pPE->getImports(getMemoryMap(), getPdStruct());
    m_listImportRecords = m_pPE->getImportRecords(getMemoryMap(), getPdStruct());

    m_nNumberOfImports = m_listImportHeaders.count();

    m_bIsNETPresent = (m_pPE->isNETPresent()) && (m_cliInfo.bValid);
    m_bIs64 = m_pPE->is64(getMemoryMap());
    m_bIsDll = m_pPE->isDll();
    m_bIsDriver = m_pPE->isDriver();
    m_bIsConsole = m_pPE->isConsole();
    m_bIsSignPresent = m_pPE->isSignPresent();
    m_bIsExportPresent = m_pPE->isExportPresent();
    m_bIsTLSPresent = m_pPE->isTLSPresent();
    m_bIsImportPresent = m_pPE->isImportPresent();
    m_bIsResourcesPresent = m_pPE->isResourcesPresent();

    m_nImportSection = m_pPE->getImageDirectoryEntrySection(getMemoryMap(), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT);
    m_nExportSection = m_pPE->getImageDirectoryEntrySection(getMemoryMap(), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT);
    m_nResourcesSection = m_pPE->getImageDirectoryEntrySection(getMemoryMap(), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE);
    m_nEntryPointSection = m_pPE->getEntryPointSection(getMemoryMap());
    m_nRelocsSection = m_pPE->getImageDirectoryEntrySection(getMemoryMap(), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC);
    m_nTLSSection = m_pPE->getImageDirectoryEntrySection(getMemoryMap(), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_TLS);

    m_nMajorLinkerVersion = m_pPE->getOptionalHeader_MajorLinkerVersion();
    m_nMinorLinkerVersion = m_pPE->getOptionalHeader_MinorLinkerVersion();
    m_nSizeOfCode = m_pPE->getOptionalHeader_SizeOfCode();
    m_nSizeOfUninitializedData = m_pPE->getOptionalHeader_SizeOfUninitializedData();

    m_sCompilerVersion = QString("%1.%2").arg(QString::number(m_nMajorLinkerVersion), QString::number(m_nMinorLinkerVersion));
    m_sGeneralOptions = QString("%1%2").arg(m_pPE->getTypeAsString(), m_bIs64 ? ("64") : ("32"));

    m_sFileVersion = m_pPE->getFileVersion(&m_resourcesVersion);
    m_sFileVersionMS = m_pPE->getFileVersionMS(&m_resourcesVersion);

    m_nCalculateSizeOfHeaders = m_pPE->calculateHeadersSize();

    m_exportHeader = m_pPE->getExport(false, getPdStruct());
    m_nNumberOfExportFunctions = m_exportHeader.listPositions.count();

    m_listExportFunctionNameStrings = m_pPE->getExportFunctionsList(&m_exportHeader, getPdStruct());

    m_nImportHash64 = m_pPE->getImportHash64(&m_listImportRecords, getPdStruct());
    m_nImportHash32 = m_pPE->getImportHash32(&m_listImportRecords, getPdStruct());
    m_listImportPositionHashes = m_pPE->getImportPositionHashes(&m_listImportHeaders);

    m_imageFileHeader = m_pPE->getFileHeader();
    m_imageOptionalHeader32 = {};
    m_imageOptionalHeader64 = {};

    if (!m_bIs64) {
        m_imageOptionalHeader32 = m_pPE->getOptionalHeader32();
    } else {
        m_imageOptionalHeader64 = m_pPE->getOptionalHeader64();
    }
}

PE_Script::~PE_Script()
{
}

quint16 PE_Script::getNumberOfSections()
{
    return m_nNumberOfSections;
}

QString PE_Script::getSectionName(quint32 nNumber)
{
    return m_pPE->getSection_NameAsString(nNumber, &m_listSectionNameStrings);
}

quint32 PE_Script::getSectionVirtualSize(quint32 nNumber)
{
    return m_pPE->getSection_VirtualSize(nNumber, &m_listSectionHeaders);
}

quint32 PE_Script::getSectionVirtualAddress(quint32 nNumber)
{
    return m_pPE->getSection_VirtualAddress(nNumber, &m_listSectionHeaders);
}

quint32 PE_Script::getSectionFileSize(quint32 nNumber)
{
    return m_pPE->getSection_SizeOfRawData(nNumber, &m_listSectionHeaders);
}

quint32 PE_Script::getSectionFileOffset(quint32 nNumber)
{
    return m_pPE->getSection_PointerToRawData(nNumber, &m_listSectionHeaders);
}

quint32 PE_Script::getSectionCharacteristics(quint32 nNumber)
{
    return m_pPE->getSection_Characteristics(nNumber, &m_listSectionHeaders);
}

quint32 PE_Script::getNumberOfResources()
{
    return m_nNumberOfResources;
}

bool PE_Script::isSectionNamePresent(const QString &sSectionName)
{
    return XBinary::isStringInListPresent(&m_listSectionNameStrings, sSectionName, getPdStruct());
}

bool PE_Script::_isSectionNamePresentExp(const QString &sSectionName)
{
    return XBinary::isStringInListPresentExp(&m_listSectionNameStrings, sSectionName, getPdStruct());
}

bool PE_Script::isNET()
{
    return m_bIsNETPresent;
}

bool PE_Script::isNet()
{
    return m_bIsNETPresent;
}

bool PE_Script::isPEPlus()
{
    return is64();
}

QString PE_Script::getGeneralOptions()
{
    return m_sGeneralOptions;
}

quint32 PE_Script::getResourceIdByNumber(quint32 nNumber)
{
    return m_pPE->getResourceIdByNumber(nNumber, &m_listResourceRecords);
}

QString PE_Script::getResourceNameByNumber(quint32 nNumber)
{
    return m_pPE->getResourceNameByNumber(nNumber, &m_listResourceRecords);
}

qint64 PE_Script::getResourceOffsetByNumber(quint32 nNumber)
{
    return m_pPE->getResourceOffsetByNumber(nNumber, &m_listResourceRecords);
}

qint64 PE_Script::getResourceSizeByNumber(quint32 nNumber)
{
    return m_pPE->getResourceSizeByNumber(nNumber, &m_listResourceRecords);
}

quint32 PE_Script::getResourceTypeByNumber(quint32 nNumber)
{
    return m_pPE->getResourceTypeByNumber(nNumber, &m_listResourceRecords);
}

bool PE_Script::isNETStringPresent(const QString &sString)
{
    return m_pPE->isStringInListPresent(&m_listNetAnsiStrings, sString, getPdStruct());
}

bool PE_Script::isNetObjectPresent(const QString &sString)
{
    return m_pPE->isStringInListPresent(&m_listNetAnsiStrings, sString, getPdStruct());
}

bool PE_Script::isNETUnicodeStringPresent(const QString &sString)
{
    return m_pPE->isStringInListPresent(&m_listNetUnicodeStrings, sString, getPdStruct());
}

bool PE_Script::isNetUStringPresent(const QString &sString)
{
    return m_pPE->isStringInListPresent(&m_listNetUnicodeStrings, sString, getPdStruct());
}

qint64 PE_Script::findSignatureInBlob_NET(const QString &sSignature)
{
    return m_pPE->findSignatureInBlob_NET(sSignature, getMemoryMap(), getPdStruct());
}

bool PE_Script::isSignatureInBlobPresent_NET(const QString &sSignature)
{
    return m_pPE->isSignatureInBlobPresent_NET(sSignature, getMemoryMap(), getPdStruct());
}

bool PE_Script::isNetGlobalCctorPresent()
{
    return m_bNetGlobalCctorPresent;
}

bool PE_Script::isNetTypePresent(const QString &sTypeNamespace, const QString &sTypeName)
{
    return m_pPE->isNetTypePresent(&m_cliInfo, sTypeNamespace, sTypeName, getPdStruct());
}

bool PE_Script::isNetMethodPresent(const QString &sTypeNamespace, const QString &sTypeName, const QString &sMethodName)
{
    return m_pPE->isNetMethodPresent(&m_cliInfo, sTypeNamespace, sTypeName, sMethodName, getPdStruct());
}

bool PE_Script::isNetFieldPresent(const QString &sTypeNamespace, const QString &sTypeName, const QString &sFieldName)
{
    return m_pPE->isNetFieldPresent(&m_cliInfo, sTypeNamespace, sTypeName, sFieldName, getPdStruct());
}

QString PE_Script::getNetModuleName()
{
    return m_sNetModuleName;
}

QString PE_Script::getNetAssemblyName()
{
    return m_sNetAssemblyName;
}

qint32 PE_Script::getNumberOfImports()
{
    return m_nNumberOfImports;
}

QString PE_Script::getImportLibraryName(quint32 nNumber)
{
    return m_pPE->getImportLibraryName(nNumber, &m_listImportHeaders);
}

bool PE_Script::isLibraryPresent(const QString &sLibraryName, bool bCheckCase)
{
    bool bResult = false;

    if (bCheckCase) {
        bResult = m_pPE->isImportLibraryPresent(sLibraryName, &m_listImportHeaders, getPdStruct());
    } else {
        bResult = m_pPE->isImportLibraryPresentI(sLibraryName, &m_listImportHeaders, getPdStruct());
    }

    return bResult;
}

bool PE_Script::isLibraryFunctionPresent(const QString &sLibraryName, const QString &sFunctionName)
{
    return m_pPE->isImportFunctionPresentI(sLibraryName, sFunctionName, &m_listImportHeaders, getPdStruct());
}

bool PE_Script::isFunctionPresent(const QString &sFunctionName)
{
    return m_pPE->isFunctionPresent(sFunctionName, &m_listImportHeaders, getPdStruct());
}

QString PE_Script::getImportFunctionName(quint32 nImport, quint32 nFunctionNumber)
{
    return m_pPE->getImportFunctionName(nImport, nFunctionNumber, &m_listImportHeaders);
}

qint32 PE_Script::getImportSection()
{
    return m_nImportSection;
}

qint32 PE_Script::getExportSection()
{
    return m_nExportSection;
}

qint32 PE_Script::getResourceSection()
{
    return m_nResourcesSection;
}

qint32 PE_Script::getEntryPointSection()
{
    return m_nEntryPointSection;
}

qint32 PE_Script::getRelocsSection()
{
    return m_nRelocsSection;
}

qint32 PE_Script::getTLSSection()
{
    return m_nTLSSection;
}

quint8 PE_Script::getMajorLinkerVersion()
{
    return m_nMajorLinkerVersion;
}

quint8 PE_Script::getMinorLinkerVersion()
{
    return m_nMinorLinkerVersion;
}

QString PE_Script::getManifest()
{
    return m_pPE->getResourceManifest(&m_listResourceRecords);
}

QString PE_Script::getVersionStringInfo(const QString &sKey)
{
    return m_pPE->getResourcesVersionValue(sKey, &m_resourcesVersion);
}

qint32 PE_Script::getNumberOfImportThunks(quint32 nNumber)
{
    return m_pPE->getNumberOfImportThunks(nNumber, &m_listImportHeaders);
}

qint64 PE_Script::getResourceNameOffset(const QString &sName)
{
    return m_pPE->getResourceNameOffset(sName, &m_listResourceRecords);
}

bool PE_Script::isResourceNamePresent(const QString &sName)
{
    return m_pPE->isResourceNamePresent(sName, &m_listResourceRecords);
}

bool PE_Script::isResourceGroupNamePresent(const QString &sName)
{
    return m_pPE->isResourceGroupNamePresent(sName, &m_listResourceRecords);
}

bool PE_Script::isResourceGroupIdPresent(quint32 nID)
{
    return m_pPE->isResourceGroupIdPresent(nID, &m_listResourceRecords);
}

QString PE_Script::getCompilerVersion()
{
    return m_sCompilerVersion;
}

bool PE_Script::isConsole()
{
    return m_bIsConsole;
}

bool PE_Script::isSignedFile()
{
    return m_bIsSignPresent;
}

QString PE_Script::getSectionNameCollision(const QString &sString1, const QString &sString2)
{
    return m_pPE->getStringCollision(&m_listSectionNameStrings, sString1, sString2);
}

qint32 PE_Script::getSectionNumber(const QString &sSectionName)
{
    return XBinary::getStringNumberFromList(&m_listSectionNameStrings, sSectionName, getPdStruct());
}

qint32 PE_Script::getSectionNumberExp(const QString &sSectionName)
{
    return XBinary::getStringNumberFromListExp(&m_listSectionNameStrings, sSectionName, getPdStruct());
}

bool PE_Script::isDll()
{
    return m_bIsDll;
}

bool PE_Script::isDriver()
{
    return m_bIsDriver;
}

QString PE_Script::getNETVersion()
{
    return m_cliInfo.metaData.header.sVersion;
}

bool PE_Script::compareEP_NET(const QString &sSignature, qint64 nOffset)
{
    return m_pPE->compareSignatureOnAddress(getMemoryMap(), sSignature, getBaseAddress() + m_cliInfo.metaData.nEntryPoint + nOffset);
}

quint32 PE_Script::getSizeOfCode()
{
    return m_nSizeOfCode;
}

quint32 PE_Script::getSizeOfUninitializedData()
{
    return m_nSizeOfUninitializedData;
}

QString PE_Script::getPEFileVersion(const QString &sFileName)
{
    QString sResult;

    QFile file;
    file.setFileName(sFileName);

    if (file.open(QIODevice::ReadOnly)) {
        XPE pe(&file);
        sResult = pe.getFileVersion();
        file.close();
    }

    return sResult;
}

QString PE_Script::getFileVersion()
{
    return m_sFileVersion;
}

QString PE_Script::getFileVersionMS()
{
    return m_sFileVersionMS;
}

qint64 PE_Script::calculateSizeOfHeaders()
{
    return m_nCalculateSizeOfHeaders;
}

bool PE_Script::isExportFunctionPresent(const QString &sFunctionName)
{
    return XBinary::isStringInListPresent(&m_listExportFunctionNameStrings, sFunctionName, getPdStruct());
}

// bool PE_Script::isExportFunctionPresentExp(const QString &sFunctionName)
// {
//     return XBinary::isStringInListPresentExp(&m_listExportFunctionNameStrings, sFunctionName, getPdStruct());
// }

qint32 PE_Script::getNumberOfExportFunctions()
{
    return m_nNumberOfExportFunctions;
}

qint32 PE_Script::getNumberOfExports()
{
    return getNumberOfExportFunctions();
}

QString PE_Script::getExportFunctionName(quint32 nNumber)
{
    return m_pPE->getStringByIndex(&m_listExportFunctionNameStrings, nNumber, -1);
}

QString PE_Script::getExportNameByNumber(quint32 nNumber)
{
    return getExportFunctionName(nNumber);
}

bool PE_Script::isExportPresent()
{
    return m_bIsExportPresent;
}

bool PE_Script::isTLSPresent()
{
    return m_bIsTLSPresent;
}

bool PE_Script::isImportPresent()
{
    return m_bIsImportPresent;
}

bool PE_Script::isResourcesPresent()
{
    return m_bIsResourcesPresent;
}

quint32 PE_Script::getImportHash32()
{
    return m_nImportHash32;
}

quint64 PE_Script::getImportHash64()
{
    return m_nImportHash64;
}

bool PE_Script::isImportPositionHashPresent(qint32 nIndex, quint32 nHash)
{
    return XPE::isImportPositionHashPresent(&m_listImportPositionHashes, nIndex, nHash, getPdStruct());
}

quint64 PE_Script::getImageFileHeader(const QString &sString)
{
    return m_pPE->getImageFileHeader(&m_imageFileHeader, sString);
}

quint64 PE_Script::getImageOptionalHeader(const QString &sString)
{
    if (!m_bIs64) {
        return m_pPE->getImageOptionalHeader32(&m_imageOptionalHeader32, sString);
    } else {
        return m_pPE->getImageOptionalHeader64(&m_imageOptionalHeader64, sString);
    }
}
