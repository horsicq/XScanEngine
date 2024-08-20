/* Copyright (c) 2024 hors<horsicq@gmail.com>
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
#ifndef XSCANENGINE_H
#define XSCANENGINE_H

#include "xformats.h"
#include "xextractor.h"
#include "xoptions.h"
#include <QFutureWatcher>

// TODO pOptions -> pScanOptions
class XScanEngine : public QObject {
    Q_OBJECT

    enum SCAN_TYPE {
        SCAN_TYPE_UNKNOWN = 0,
        SCAN_TYPE_DEVICE,
        SCAN_TYPE_DIRECTORY,
        SCAN_TYPE_FILE,
        SCAN_TYPE_MEMORY
    };

public:
    struct SCANID {
        bool bVirtual;
        QString sUuid;
        XBinary::FT fileType;
        XBinary::FILEPART filePart;
        QString sArch;
        QString sVersion;
        QString sInfo;

        XBinary::MODE mode;
        XBinary::ENDIAN endian;
        QString sType;
        qint64 nSize;
        qint64 nOffset;
    };

    struct SCANSTRUCT {
        bool bIsHeuristic;
        bool bIsUnknown;
        SCANID id;
        SCANID parentId;
        quint32 nType;
        quint32 nName;
        QString sType;
        QString sName;
        QString sVersion;
        QString sInfo;
        QString varInfo;   // Signature in die scripts
        QString varInfo2;  // Signature File in die scripts
        // QString sResult;   // TODO Check
        Qt::GlobalColor globalColor;
        qint32 nPrio;
        bool bIsProtection;
    };

    struct ERROR_RECORD {
        QString sScript;
        QString sErrorString;
    };

    struct DEBUG_RECORD {
        QString sScript;
        QString sType;
        QString sName;
        QString sValue;
        qint64 nElapsedTime;
    };

    struct SCAN_RESULT {
        qint64 nScanTime;
        QString sFileName;
        qint64 nSize;
        QList<SCANSTRUCT> listRecords;
        QList<ERROR_RECORD> listErrors;
        QList<DEBUG_RECORD> listDebugRecords;
    };

    enum SCANFLAG {
        SCANFLAG_RECURSIVESCAN = 1,
        SCANFLAG_DEEPSCAN = 2,
        SCANFLAG_HEURISTICSCAN = 4,
        SCANFLAG_VERBOSE = 8,
        SCANFLAG_ALLTYPESSCAN = 16,
    };

    enum DATABASE {
        DATABASE_MAIN = 1,
        DATABASE_EXTRA = 2,
        DATABASE_CUSTOM = 4,
    };

    struct SCAN_OPTIONS {
        //        bool bEmulate; // TODO Check
        bool bIsDeepScan;
        bool bIsHeuristicScan;
        bool bIsVerbose;
        bool bIsRecursiveScan;
        bool bIsAggressiveScan;
        bool bIsAllTypesScan;
        qint64 nBufferSize;
        bool bShowInternalDetects;
        bool bResultAsXML;
        bool bResultAsJSON;
        bool bResultAsCSV;
        bool bResultAsTSV;
        bool bResultAsPlainText;
        bool bSubdirectories;
        bool bIsImage;
        bool bIsTest;
        bool bHandleInfo;
        XBinary::FT fileType;            // Optional
        XBinary::FILEPART initFilePart;  // Optional
        QVariant varInfo;                // Optional
        bool bLogErrors;                 // TODO options
        bool bLogAll;                    // TODO options
        bool bLogProfiling;
        bool bShowScanTime;
        bool bShowType;
        bool bShowVersion;
        bool bShowInfo;
        bool bShowUnknown;  // TODO options
        bool bShowEntropy;
        bool bShowFileInfo;
        QString sSpecial;        // Special info
        QString sSignatureName;  // Optional
        QString sDetectFunction;
        bool bIsHighlight;
        bool bUseExtraDatabase;
        bool bUseCustomDatabase;
    };

    struct SCAN_DATA {
        QString sSignaturePath;
    };

    XScanEngine(QObject *pParent = nullptr);

    void setData(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct);
    void setData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct);
    void setData(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct);
    void setData(const QString &sDirectoryName, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    static QString createTypeString(const SCANSTRUCT *pScanStruct);
    static SCANSTRUCT createHeaderScanStruct(const SCANSTRUCT *pScanStruct);
    static QString createResultStringEx(XScanEngine::SCAN_OPTIONS *pOptions, const SCANSTRUCT *pScanStruct);
    static QString createShortResultString(XScanEngine::SCAN_OPTIONS *pOptions, const SCAN_RESULT &scanResult);
    static Qt::GlobalColor typeToColor(const QString &sType);
    static qint32 typeToPrio(const QString &sType);
    static QString translateType(const QString &sType);
    static QString _translate(const QString &sString);
    static void sortRecords(QList<SCANSTRUCT> *pListRecords);
    static QString getProtection(XScanEngine::SCAN_OPTIONS *pScanOptions, QList<SCANSTRUCT> *pListRecords);
    static bool isProtection(const QString &sType);
    static bool isScanable(const QSet<XBinary::FT> &stFT);

    XScanEngine::SCAN_RESULT scanDevice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct = nullptr);
    XScanEngine::SCAN_RESULT scanFile(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct = nullptr);
    XScanEngine::SCAN_RESULT scanMemory(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct = nullptr);
    XScanEngine::SCAN_RESULT scanSubdevice(QIODevice *pDevice, qint64 nOffset, qint64 nSize, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct = nullptr);

    void scanProcess(QIODevice *pDevice, XScanEngine::SCAN_RESULT *pScanResult, qint64 nOffset, qint64 nSize, XScanEngine::SCANID parentId,
                     XScanEngine::SCAN_OPTIONS *pOptions, bool bInit, XBinary::PDSTRUCT *pPdStruct);

    static QMap<quint64, QString> getScanFlags();
    static quint64 getScanFlags(SCAN_OPTIONS *pScanOptions);
    static void setScanFlags(SCAN_OPTIONS *pScanOptions, quint64 nFlags);
    static quint64 getScanFlagsFromGlobalOptions(XOptions *pGlobalOptions);
    static void setScanFlagsToGlobalOptions(XOptions *pGlobalOptions, quint64 nFlags);

    static QMap<quint64, QString> getDatabases();
    static quint64 getDatabases(SCAN_OPTIONS *pScanOptions);
    static void setDatabases(SCAN_OPTIONS *pScanOptions, quint64 nDatabases);
    static quint64 getDatabasesFromGlobalOptions(XOptions *pGlobalOptions);
    static void setDatabasesToGlobalOptions(XOptions *pGlobalOptions, quint64 nDatabases);

public slots:
    void process();

protected:
    virtual void _processDetect(SCANID *pScanID, SCAN_RESULT *pScanResult, QIODevice *pDevice, const SCANID &parentId, XBinary::FT fileType, SCAN_OPTIONS *pOptions,
                                bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct) = 0;
    void _errorMessage(SCAN_OPTIONS *pOptions, const QString &sErrorMessage);
    void _warningMessage(SCAN_OPTIONS *pOptions, const QString &sWarningMessage);
    void _infoMessage(SCAN_OPTIONS *pOptions, const QString &sInfoMessage);

signals:
    // TODO error and info signals !!!
    void scanFileStarted(const QString &sFileName);
    void completed(qint64 nElapsedTime);
    void scanResult(const XScanEngine::SCAN_RESULT &scanResult);
    void errorMessage(const QString &sErrorMessage);
    void warningMessage(const QString &sWarningMessage);
    void infoMessage(const QString &sInfoMessage);

private:
    QString g_sFileName;
    QString g_sDirectoryName;
    QIODevice *g_pDevice;
    char *g_pData;
    qint32 g_nDataSize;
    XScanEngine::SCAN_OPTIONS *g_pOptions;
    XScanEngine::SCAN_RESULT *g_pScanResult;
    SCAN_TYPE g_scanType;
    XBinary::PDSTRUCT *g_pPdStruct;
};

#endif  // XSCANENGINE_H
