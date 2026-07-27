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
#ifndef DOTNET_SCRIPT_H
#define DOTNET_SCRIPT_H

#include "binary_script.h"
#include "xcliassembly.h"

class DOTNET_Script : public Binary_Script {
    Q_OBJECT

public:
    explicit DOTNET_Script(XCLIAssembly *pCliAssembly, XBinary::FILEPART filePart, const OPTIONS &scanOptions, XBinary::PDSTRUCT *pPdStruct);
    ~DOTNET_Script();

public slots:
    QString getNetVersion();
    QString getNetModuleName();
    QString getNetAssemblyName();

    bool isNetStringPresent(const QString &sString);
    bool isNetObjectPresent(const QString &sString);
    bool isNetUStringPresent(const QString &sString);
    bool isNetUnicodeStringPresent(const QString &sString);

    bool isNetGlobalCctorPresent();
    bool isNetTypePresent(const QString &sTypeNamespace, const QString &sTypeName);
    bool isNetMethodPresent(const QString &sTypeNamespace, const QString &sTypeName, const QString &sMethodName);
    bool isNetFieldPresent(const QString &sTypeNamespace, const QString &sTypeName, const QString &sFieldName);

    qint64 findSignatureInBlob_NET(const QString &sSignature);
    bool isSignatureInBlobPresent_NET(const QString &sSignature);

private:
    XCLIAssembly *m_pCliAssembly;
    XCLIAssembly::CLI_INFO m_cliInfo;
    QList<QString> m_listNetAnsiStrings;
    QList<QString> m_listNetUnicodeStrings;
    bool m_bNetGlobalCctorPresent;
    QString m_sNetModuleName;
    QString m_sNetAssemblyName;

protected:
    XCLIAssembly *getCLIAssembly() const
    {
        return m_pCliAssembly;
    }
};

#endif  // DOTNET_SCRIPT_H
