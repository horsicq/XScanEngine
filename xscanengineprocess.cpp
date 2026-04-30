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
#include "xscanengineprocess.h"

XScanEngineProcess::XScanEngineProcess(XScanEngine *pScanEngine, QObject *pParent) : XThreadObject(pParent)
{
    m_pScanEngine = pScanEngine;
    m_pDevice = nullptr;
    m_pData = nullptr;
    m_nDataSize = 0;
    m_pScanOptions = nullptr;
    m_pScanResult = nullptr;
    m_scanType = SCAN_TYPE_UNKNOWN;
    m_pPdStruct = nullptr;

    if (m_pScanEngine) {
        connect(m_pScanEngine, SIGNAL(errorMessage(QString)), this, SIGNAL(errorMessage(QString)));
        connect(m_pScanEngine, SIGNAL(warningMessage(QString)), this, SIGNAL(warningMessage(QString)));
        connect(m_pScanEngine, SIGNAL(infoMessage(QString)), this, SIGNAL(infoMessage(QString)));
    }
}

void XScanEngineProcess::setData(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct)
{
    this->m_sFileName = sFileName;
    this->m_pScanOptions = pScanOptions;
    this->m_pScanResult = pScanResult;
    this->m_scanType = SCAN_TYPE_FILE;
    this->m_pPdStruct = pPdStruct;
}

void XScanEngineProcess::setData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct)
{
    this->m_pDevice = pDevice;
    this->m_pScanOptions = pScanOptions;
    this->m_pScanResult = pScanResult;
    this->m_scanType = SCAN_TYPE_DEVICE;
    this->m_pPdStruct = pPdStruct;
}

void XScanEngineProcess::setData(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine::SCAN_RESULT *pScanResult,
                                 XBinary::PDSTRUCT *pPdStruct)
{
    this->m_pData = pData;
    this->m_nDataSize = nDataSize;
    this->m_pScanOptions = pScanOptions;
    this->m_pScanResult = pScanResult;
    this->m_scanType = SCAN_TYPE_MEMORY;
    this->m_pPdStruct = pPdStruct;
}

void XScanEngineProcess::setData(const QString &sDirectoryName, XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct)
{
    this->m_sDirectoryName = sDirectoryName;
    this->m_pScanOptions = pScanOptions;
    this->m_scanType = SCAN_TYPE_DIRECTORY;
    this->m_pPdStruct = pPdStruct;
}

void XScanEngineProcess::process()
{
    emit scanStarted();
    QElapsedTimer elapsedTimer;
    elapsedTimer.start();

    if (m_pScanEngine) {
        XBinary::PDSTRUCT _pdStruct = {};
        XBinary::PDSTRUCT *pPdStruct = m_pPdStruct;

        if (!pPdStruct) {
            pPdStruct = &_pdStruct;
        }

        qint32 nFreeIndex = XBinary::getFreeIndex(pPdStruct);
        XBinary::setPdStructInit(pPdStruct, nFreeIndex, 0);

        if (m_scanType == SCAN_TYPE_FILE) {
            if ((m_pScanResult) && (m_pScanOptions) && (m_sFileName != "")) {
                XBinary::setPdStructStatus(pPdStruct, nFreeIndex, tr("File scan"));

                emit scanFileStarted(m_sFileName);

                *m_pScanResult = m_pScanEngine->scanFile(m_sFileName, m_pScanOptions, pPdStruct);

                emit scanResult(*m_pScanResult);
            }
        } else if (m_scanType == SCAN_TYPE_DEVICE) {
            if ((m_pDevice) && (m_pScanResult) && (m_pScanOptions)) {
                XBinary::setPdStructStatus(pPdStruct, nFreeIndex, tr("Device scan"));

                *m_pScanResult = m_pScanEngine->scanDevice(m_pDevice, m_pScanOptions, pPdStruct);

                emit scanResult(*m_pScanResult);
            }
        } else if (m_scanType == SCAN_TYPE_MEMORY) {
            if ((m_pData) && (m_nDataSize > 0) && (m_pScanResult) && (m_pScanOptions)) {
                XBinary::setPdStructStatus(pPdStruct, nFreeIndex, tr("Memory scan"));

                *m_pScanResult = m_pScanEngine->scanMemory(m_pData, m_nDataSize, m_pScanOptions, pPdStruct);

                emit scanResult(*m_pScanResult);
            }
        } else if (m_scanType == SCAN_TYPE_DIRECTORY) {
            if ((m_sDirectoryName != "") && (m_pScanOptions)) {
                XBinary::setPdStructStatus(pPdStruct, nFreeIndex, tr("Directory scan"));
                QList<QString> listFileNames;

                XBinary::findFiles(m_sDirectoryName, &listFileNames, m_pScanOptions->bSubdirectories, 0, pPdStruct);

                qint32 nTotal = listFileNames.count();

                XBinary::setPdStructTotal(pPdStruct, nFreeIndex, nTotal);

                for (qint32 i = 0; (i < nTotal) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
                    QString sFileName = listFileNames.at(i);

                    XBinary::setPdStructCurrent(pPdStruct, nFreeIndex, i);
                    XBinary::setPdStructStatus(pPdStruct, nFreeIndex, sFileName);

                    emit scanFileStarted(sFileName);

                    if (sFileName != "") {
                        QFile file;
                        file.setFileName(sFileName);

                        if (file.open(QIODevice::ReadOnly)) {
                            _scanDevice(&file, m_pScanOptions, pPdStruct);

                            file.close();

                            if (m_pScanOptions->bCollection && (m_pScanOptions->bCollectionCopyRemove || m_pScanOptions->bCollectionCopyMoveToFirst) &&
                                file.property("CollectionSourceCopied").toBool()) {
                                QFile::remove(sFileName);
                            }
                        }
                    }
                }
            }
        }

        XBinary::setPdStructFinished(pPdStruct, nFreeIndex);
    }

    emit scanFinished(elapsedTimer.elapsed());
}

void XScanEngineProcess::_scanDevice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT _scanResult = m_pScanEngine->scanDevice(pDevice, m_pScanOptions, pPdStruct);
    emit scanResult(_scanResult);

    if (m_pScanOptions->bCollection) {
        QSet<XBinary::FT> stFT = XFormats::getFileTypes(pDevice, true, pPdStruct);

        if (m_pScanOptions->bIsArchivesScan) {
            bool bScanableArchive = false;

            if (stFT.contains(XBinary::FT_ZIP) || stFT.contains(XBinary::FT_7Z) || stFT.contains(XBinary::FT_RAR) || stFT.contains(XBinary::FT_CAB) ||
                stFT.contains(XBinary::FT_ISO9660)) {
                bScanableArchive = true;
            }

            if (bScanableArchive) {
                XBinary::FT _fileType = XBinary::_getPrefFileType(&stFT);

                XBinary *pArchive = XFormats::getClass(_fileType, pDevice, false, -1);

                XBinary::UNPACK_STATE state = {};
                QMap<XBinary::UNPACK_PROP, QVariant> mapProperties;

                QString sError;

                if (pArchive->initUnpack(&state, mapProperties, pPdStruct)) {
                    qint32 nFreeIndex = XBinary::getFreeIndex(pPdStruct);
                    XBinary::setPdStructInit(pPdStruct, nFreeIndex, state.nNumberOfRecords);

                    qint32 nCurrentIndex = 0;
                    for (qint32 i = 0; (i < 100000) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
                        XBinary::ARCHIVERECORD archiveRecord = pArchive->infoCurrent(&state, pPdStruct);

                        if (!(archiveRecord.mapProperties.value(XBinary::FPART_PROP_ISFOLDER, false).toBool())) {
                            QIODevice *pArchiveRecord =
                                XBinary::createFileBuffer(archiveRecord.mapProperties.value(XBinary::FPART_PROP_UNCOMPRESSEDSIZE).toLongLong(), pPdStruct);

                            if (pArchiveRecord) {
                                if (pArchive->unpackCurrent(&state, pArchiveRecord, pPdStruct)) {
                                    QString sOriginalName = archiveRecord.mapProperties.value(XBinary::FPART_PROP_ORIGINALNAME).toString();

                                    XBinary::setPdStructStatus(pPdStruct, nFreeIndex, sOriginalName);

                                    pArchiveRecord->setProperty("FileName", XBinary::getDeviceDirectory(pDevice) + QDir::separator() +
                                                                                XBinary::getDeviceFileBaseName(pDevice) + "_ARCHIVE_RECORD_" + sOriginalName);

                                    _scanDevice(pArchiveRecord, pScanOptions, pPdStruct);

                                    nCurrentIndex++;
                                } else {
                                    sError = "Cannot unpack the current record";
                                }
                            }

                            XBinary::freeFileBuffer(&pArchiveRecord);
                        }

                        if (!pArchive->moveToNext(&state, pPdStruct)) {
                            break;
                        }

                        XBinary::setPdStructCurrentIncrement(pPdStruct, nFreeIndex);
                    }

                    pArchive->finishUnpack(&state, pPdStruct);

                    XBinary::setPdStructFinished(pPdStruct, nFreeIndex);
                } else {
                    sError = "Cannot open archive";
                }

                if (pArchive) {
                    delete pArchive;
                }

                if (sError != "") {
                    QString sLogFile = pScanOptions->sCollectionResultDirectory + QDir::separator() + "error.log";
                    XBinary::appendToFile(sLogFile, XBinary::getDeviceFileName(pDevice));
                    XBinary::appendToFile(sLogFile, sError.toUtf8());
                }
            }
        }
    }
}
