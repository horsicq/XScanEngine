/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef XSCANENGINEPROCESS_H
#define XSCANENGINEPROCESS_H

#include "xthreadobject.h"
#include "xscanengine.h"

class XScanEngineProcess : public XThreadObject {
    Q_OBJECT

    enum SCAN_TYPE {
        SCAN_TYPE_UNKNOWN = 0,
        SCAN_TYPE_DEVICE,
        SCAN_TYPE_DIRECTORY,
        SCAN_TYPE_FILE,
        SCAN_TYPE_MEMORY
    };

public:
    explicit XScanEngineProcess(XScanEngine *pScanEngine, QObject *pParent = nullptr);

    void setData(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct);
    void setData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct);
    void setData(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct);
    void setData(const QString &sDirectoryName, XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct);

    virtual void process() override;

signals:
    void scanFileStarted(const QString &sFileName);
    void scanResult(const XScanEngine::SCAN_RESULT &scanResult);
    void scanStarted();
    void scanFinished(qint64 nMsec);

private:
    XScanEngine *m_pScanEngine;
    QString m_sFileName;
    QString m_sDirectoryName;
    QIODevice *m_pDevice;
    char *m_pData;
    qint32 m_nDataSize;
    XScanEngine::SCAN_OPTIONS *m_pScanOptions;
    XScanEngine::SCAN_RESULT *m_pScanResult;
    SCAN_TYPE m_scanType;
    XBinary::PDSTRUCT *m_pPdStruct;
};

#endif  // XSCANENGINEPROCESS_H
