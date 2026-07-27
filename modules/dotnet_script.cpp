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
#include "dotnet_script.h"

DOTNET_Script::DOTNET_Script(XCLIAssembly *pCliAssembly, XBinary::FILEPART filePart, const OPTIONS &scanOptions, XBinary::PDSTRUCT *pPdStruct)
    : Binary_Script(pCliAssembly, filePart, scanOptions, pPdStruct)
{
    m_pCliAssembly = pCliAssembly;

    m_cliInfo = m_pCliAssembly->getCliInfo(false, getPdStruct());
    m_bNetGlobalCctorPresent = m_pCliAssembly->isNetGlobalCctorPresent(&m_cliInfo, getPdStruct());

    if (m_cliInfo.bValid) {
        m_listNetAnsiStrings = m_pCliAssembly->getAnsiStrings(&m_cliInfo, getPdStruct());
        m_listNetUnicodeStrings = m_pCliAssembly->getUnicodeStrings(&m_cliInfo, getPdStruct());
        m_sNetModuleName = m_pCliAssembly->getMetadataModuleName(&m_cliInfo, 0);
        m_sNetAssemblyName = m_pCliAssembly->getMetadataAssemblyName(&m_cliInfo, 0);
    }
}

DOTNET_Script::~DOTNET_Script()
{
}

QString DOTNET_Script::getNetVersion()
{
    return m_cliInfo.metaData.header.sVersion;
}

QString DOTNET_Script::getNetModuleName()
{
    return m_sNetModuleName;
}

QString DOTNET_Script::getNetAssemblyName()
{
    return m_sNetAssemblyName;
}

bool DOTNET_Script::isNetStringPresent(const QString &sString)
{
    return XBinary::isStringInListPresent(&m_listNetAnsiStrings, sString, getPdStruct());
}

bool DOTNET_Script::isNetObjectPresent(const QString &sString)
{
    return isNetStringPresent(sString);
}

bool DOTNET_Script::isNetUStringPresent(const QString &sString)
{
    return XBinary::isStringInListPresent(&m_listNetUnicodeStrings, sString, getPdStruct());
}

bool DOTNET_Script::isNetUnicodeStringPresent(const QString &sString)
{
    return isNetUStringPresent(sString);
}

bool DOTNET_Script::isNetGlobalCctorPresent()
{
    return m_bNetGlobalCctorPresent;
}

bool DOTNET_Script::isNetTypePresent(const QString &sTypeNamespace, const QString &sTypeName)
{
    return m_pCliAssembly->isNetTypePresent(&m_cliInfo, sTypeNamespace, sTypeName, getPdStruct());
}

bool DOTNET_Script::isNetMethodPresent(const QString &sTypeNamespace, const QString &sTypeName, const QString &sMethodName)
{
    return m_pCliAssembly->isNetMethodPresent(&m_cliInfo, sTypeNamespace, sTypeName, sMethodName, getPdStruct());
}

bool DOTNET_Script::isNetFieldPresent(const QString &sTypeNamespace, const QString &sTypeName, const QString &sFieldName)
{
    return m_pCliAssembly->isNetFieldPresent(&m_cliInfo, sTypeNamespace, sTypeName, sFieldName, getPdStruct());
}

qint64 DOTNET_Script::findSignatureInBlob_NET(const QString &sSignature)
{
    return m_pCliAssembly->findSignatureInBlob_NET(sSignature, getPdStruct());
}

bool DOTNET_Script::isSignatureInBlobPresent_NET(const QString &sSignature)
{
    return m_pCliAssembly->isSignatureInBlobPresent_NET(sSignature, getPdStruct());
}
