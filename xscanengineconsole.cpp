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
#include "xscanengineconsole.h"
#include "xconsoloutput.h"
#include "xarchives.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QXmlStreamWriter>

XScanEngineConsole::XScanEngineConsole(QCoreApplication &app, XScanEngine &scanEngine, const QString &sDescription, QObject *pParent)
    : QObject(pParent), m_app(app), m_scanEngine(scanEngine), m_sDescription(sDescription)
{
}

int XScanEngineConsole::process()
{
    qint32 nResult = XOptions::CR_SUCCESS;

    XBinary::PDSTRUCT pdStruct = XBinary::createPdStruct();

    QCommandLineParser parser;
    parser.setApplicationDescription(m_sDescription);
    parser.addHelpOption();
    parser.addVersionOption();

    parser.addPositionalArgument("target", "The file or directory to open.");

    XScanEngine::SCANENGINETYPE engineType = m_scanEngine.getEngineType();
    bool bHasMainDb = (engineType != XScanEngine::SCANENGINETYPE_NFD);
    bool bIsDatabaseUsing = m_scanEngine.isDatabaseUsing();
    bool bHasExtraCustomDb = (engineType == XScanEngine::SCANENGINETYPE_DIE);

    QCommandLineOption clRecursiveScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_RECURSIVESCAN);
    QCommandLineOption clDeepScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_DEEPSCAN);
    QCommandLineOption clHeuristicScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_HEURISTICSCAN);
    QCommandLineOption clVerbose = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_VERBOSE);
    QCommandLineOption clAggresiveScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_AGGRESSIVESCAN);
    QCommandLineOption clResourcesScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_RESOURCESSCAN);
    QCommandLineOption clArchivesScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_ARCHIVESSCAN);
    QCommandLineOption clOverlayScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_OVERLAYSCAN);
    QCommandLineOption clAllTypesScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_ALLTYPES);

    QCommandLineOption clProfiling = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_PROFILING);
    QCommandLineOption clMessages = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_MESSAGES);
    QCommandLineOption clHideUnknown = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_HIDEUNKNOWN);

    QCommandLineOption clEntropy = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_ENTROPY);
    QCommandLineOption clInfo = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_INFO);

    QCommandLineOption clResultAsXml = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_XML);
    QCommandLineOption clResultAsJson = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_JSON);
    QCommandLineOption clResultAsCSV = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_CSV);
    QCommandLineOption clResultAsTSV = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_TSV);
    QCommandLineOption clResultAsPlainText = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_PLAINTEXT);

    QCommandLineOption clDatabaseMain = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_DATABASE);
    QCommandLineOption clDatabaseExtra = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_EXTRADATABASE);
    QCommandLineOption clDatabaseCustom = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_CUSTOMDATABASE);
    QCommandLineOption clShowDatabase = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_SHOWDATABASE);

    QCommandLineOption clStruct = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_STRUCT);
    QCommandLineOption clShowStructs = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_SHOWSTRUCTS);
    QCommandLineOption clListArchive = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_LISTARCHIVE);
    QCommandLineOption clExtractArchive = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_EXTRACTARCHIVE);

    QCommandLineOption clFileType = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_FILETYPE);
    QCommandLineOption clFirstWrapperOnly = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_FIRSTWRAPPERONLY);
    QCommandLineOption clNoColor = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_NOCOLOR);

    parser.addOption(clRecursiveScan);
    parser.addOption(clDeepScan);
    parser.addOption(clHeuristicScan);
    parser.addOption(clVerbose);
    parser.addOption(clAggresiveScan);
    parser.addOption(clAllTypesScan);
    parser.addOption(clProfiling);
    parser.addOption(clMessages);
    parser.addOption(clHideUnknown);
    parser.addOption(clEntropy);
    parser.addOption(clInfo);
    parser.addOption(clStruct);
    parser.addOption(clResultAsXml);
    parser.addOption(clResultAsJson);
    parser.addOption(clResultAsCSV);
    parser.addOption(clResultAsTSV);
    parser.addOption(clResultAsPlainText);
    if (bHasMainDb) {
        parser.addOption(clDatabaseMain);
        parser.addOption(clShowDatabase);
    }
    if (bHasExtraCustomDb) {
        parser.addOption(clDatabaseExtra);
        parser.addOption(clDatabaseCustom);
    }
    parser.addOption(clOverlayScan);
    parser.addOption(clResourcesScan);
    parser.addOption(clArchivesScan);
    parser.addOption(clFileType);
    parser.addOption(clFirstWrapperOnly);
    parser.addOption(clShowStructs);
    parser.addOption(clListArchive);
    parser.addOption(clExtractArchive);
    parser.addOption(clNoColor);

    parser.process(m_app);

    QStringList listArgs = parser.positionalArguments();

    qint32 nNumberOfResultFormats = 0;
    nNumberOfResultFormats += parser.isSet(clResultAsXml);
    nNumberOfResultFormats += parser.isSet(clResultAsJson);
    nNumberOfResultFormats += parser.isSet(clResultAsCSV);
    nNumberOfResultFormats += parser.isSet(clResultAsTSV);
    nNumberOfResultFormats += parser.isSet(clResultAsPlainText);

    if (nNumberOfResultFormats > 1) {
        printf("Error: select only one result format\n");
        return XOptions::CR_INVALIDPARAMETER;
    }

    XScanEngine::SCAN_OPTIONS scanOptions = {};

    scanOptions.bUseExtraDatabase = (engineType == XScanEngine::SCANENGINETYPE_DIE);
    scanOptions.bUseCustomDatabase = (engineType == XScanEngine::SCANENGINETYPE_DIE);
    scanOptions.bShowType = true;
    scanOptions.bShowInfo = true;
    scanOptions.bShowVersion = true;
    scanOptions.bFormatResult = true;
    scanOptions.bIsRecursiveScan = parser.isSet(clRecursiveScan);
    scanOptions.bIsDeepScan = parser.isSet(clDeepScan);
    scanOptions.bIsHeuristicScan = parser.isSet(clHeuristicScan);
    scanOptions.bIsVerbose = parser.isSet(clVerbose);
    scanOptions.bIsAggressiveScan = parser.isSet(clAggresiveScan);
    scanOptions.bIsOverlayScan = parser.isSet(clOverlayScan);
    scanOptions.bIsResourcesScan = parser.isSet(clResourcesScan);
    scanOptions.bIsArchivesScan = parser.isSet(clArchivesScan);
    scanOptions.bIsAllTypesScan = parser.isSet(clAllTypesScan);
    scanOptions.bIsFirstWrapperScan = parser.isSet(clFirstWrapperOnly);
    scanOptions.bHideUnknown = parser.isSet(clHideUnknown);
    scanOptions.bLogProfiling = parser.isSet(clProfiling);
    scanOptions.bShowEntropy = parser.isSet(clEntropy);
    scanOptions.bShowFileInfo = parser.isSet(clInfo);
    scanOptions.bResultAsXML = parser.isSet(clResultAsXml);
    scanOptions.bResultAsJSON = parser.isSet(clResultAsJson);
    scanOptions.bResultAsCSV = parser.isSet(clResultAsCSV);
    scanOptions.bResultAsTSV = parser.isSet(clResultAsTSV);
    scanOptions.bResultAsPlainText = parser.isSet(clResultAsPlainText);
    scanOptions.bIsSort = true;
    scanOptions.fileType = parser.isSet(clFileType) ? XBinary::ftStringToFileTypeId(parser.value(clFileType)) : XBinary::FT_UNKNOWN;

    if (parser.isSet(clNoColor)) {
        XOptions::setNoColor(true);
    }

    scanOptions.sStruct = parser.value(clStruct);

    if (bHasMainDb) {
        scanOptions.sMainDatabasePath = parser.value(clDatabaseMain);
    }
    if (bHasExtraCustomDb) {
        scanOptions.sExtraDatabasePath = parser.value(clDatabaseExtra);
        scanOptions.sCustomDatabasePath = parser.value(clDatabaseCustom);
    }

    if (scanOptions.sMainDatabasePath.isEmpty()) {
        if (engineType == XScanEngine::SCANENGINETYPE_PEID) {
            scanOptions.sMainDatabasePath = "$data/peid";
        } else if (engineType == XScanEngine::SCANENGINETYPE_YARA) {
            scanOptions.sMainDatabasePath = "$data/yara";
        } else {
            scanOptions.sMainDatabasePath = "$data/db";
        }
    }

    if (bHasExtraCustomDb) {
        if (scanOptions.sExtraDatabasePath.isEmpty()) {
            scanOptions.sExtraDatabasePath = "$data/db_extra";
        }

        if (scanOptions.sCustomDatabasePath.isEmpty()) {
            scanOptions.sCustomDatabasePath = "$data/db_custom";
        }
    }

    XConsoleOutput consoleOutput;

    if (parser.isSet(clMessages)) {
        QObject::connect(&m_scanEngine, SIGNAL(errorMessage(QString)), &consoleOutput, SLOT(errorMessage(QString)));
        QObject::connect(&m_scanEngine, SIGNAL(warningMessage(QString)), &consoleOutput, SLOT(warningMessage(QString)));
        QObject::connect(&m_scanEngine, SIGNAL(infoMessage(QString)), &consoleOutput, SLOT(infoMessage(QString)));
    }

    bool bIsDbUsed = false;
    bool bDbLoaded = false;
    bool bProcessed = false;

    if (bHasMainDb && parser.isSet(clShowDatabase)) {
        if (!bIsDbUsed) {
            bDbLoaded = m_scanEngine.loadDatabase(&scanOptions, &pdStruct);
            bIsDbUsed = true;
        }

        XScanEngine::DATABASE_STATE dataBaseState = m_scanEngine.getDatabaseState(&scanOptions);

        QString sResult;

        if (scanOptions.bResultAsJSON) {
            sResult = XScanEngine::databaseStateToJson(dataBaseState);
        } else if (scanOptions.bResultAsXML) {
            sResult = XScanEngine::databaseStateToXml(dataBaseState);
        } else if (scanOptions.bResultAsCSV) {
            sResult = XScanEngine::databaseStateToCSV(dataBaseState);
        } else if (scanOptions.bResultAsTSV) {
            sResult = XScanEngine::databaseStateToTSV(dataBaseState);
        } else {
            sResult = XScanEngine::databaseStateToText(dataBaseState);
        }

        printf("%s", sResult.toUtf8().data());
        bProcessed = true;
    }

    if (parser.isSet(clListArchive)) {
        if (!listArgs.isEmpty()) {
            bool bShowFileName = (listArgs.count() > 1);

            for (const QString &sFileName : listArgs) {

                if (!QFileInfo::exists(sFileName)) {
                    printf("Cannot find: %s\n", sFileName.toUtf8().data());
                    nResult = XOptions::CR_CANNOTFINDFILE;
                    continue;
                }

                if (bShowFileName) {
                    printf("%s:\n", QDir().toNativeSeparators(sFileName).toUtf8().data());
                }

                QFile file;
                file.setFileName(sFileName);

                if (!file.open(QIODevice::ReadOnly)) {
                    printf("Cannot open: %s\n", sFileName.toUtf8().data());
                    nResult = XOptions::CR_CANNOTOPENFILE;
                    continue;
                }

                XBinary::FT fileType = scanOptions.fileType;

                if (fileType == XBinary::FT_UNKNOWN) {
                    fileType = XFormats::getPrefFileType(&file, true, &pdStruct);
                }

                if (!XFormats::isArchive(fileType)) {
                    printf("Cannot open archive: %s\n", sFileName.toUtf8().data());
                    file.close();
                    nResult = XOptions::CR_CANNOTOPENFILE;
                    continue;
                }

                QList<XArchive::RECORD> listRecords = XArchives::getRecords(&file, fileType, -1, &pdStruct);

                file.close();

                printf("Name\tSize\tPacked\tCRC32\n");

                for (const XArchive::RECORD &record : listRecords) {
                    QString sLine = QString("%1\t%2\t%3\t%4\n")
                                        .arg(record.spInfo.sRecordName)
                                        .arg(record.spInfo.nUncompressedSize)
                                        .arg(record.nDataSize)
                                        .arg(QString("%1").arg(static_cast<qulonglong>(record.spInfo.nCRC32), 8, 16, QChar('0')).toUpper());

                    printf("%s", sLine.toUtf8().data());
                }
            }
        } else {
            printf("Error: --showarchive requires <target>\n");
            nResult = XOptions::CR_INVALIDPARAMETER;
        }

        bProcessed = true;
    }

    if (parser.isSet(clExtractArchive)) {
        QString sResultDirectory = parser.value(clExtractArchive);

        if (sResultDirectory.isEmpty() || listArgs.isEmpty()) {
            printf("Error: --extractarchive requires <directory> <target>\n");
            nResult = XOptions::CR_INVALIDPARAMETER;
        } else if (!QDir().mkpath(sResultDirectory)) {
            printf("Cannot create directory: %s\n", sResultDirectory.toUtf8().data());
            nResult = XOptions::CR_INVALIDPARAMETER;
        } else {
            for (const QString &sFileName : listArgs) {
                if (!QFileInfo::exists(sFileName)) {
                    printf("Cannot find: %s\n", sFileName.toUtf8().data());
                    nResult = XOptions::CR_CANNOTFINDFILE;
                    continue;
                }

                QFile file;
                file.setFileName(sFileName);

                if (!file.open(QIODevice::ReadOnly)) {
                    printf("Cannot open: %s\n", sFileName.toUtf8().data());
                    nResult = XOptions::CR_CANNOTOPENFILE;
                    continue;
                }

                XBinary::FT fileType = scanOptions.fileType;

                if (fileType == XBinary::FT_UNKNOWN) {
                    fileType = XFormats::getPrefFileType(&file, true, &pdStruct);
                }

                if (!XFormats::isArchive(fileType)) {
                    printf("Cannot open archive: %s\n", sFileName.toUtf8().data());
                    file.close();
                    nResult = XOptions::CR_CANNOTOPENFILE;
                    continue;
                }

                XArchive *pArchive = static_cast<XArchive *>(XFormats::getClass(fileType, &file));
                bool bExtracted = false;

                if (pArchive) {
                    QList<XArchive::RECORD> listRecords = pArchive->getRecords(-1, &pdStruct);
                    bExtracted = pArchive->decompressToPath(&listRecords, "", sResultDirectory, &pdStruct);
                }

                delete pArchive;
                file.close();

                if (bExtracted) {
                    printf("Extracted: %s -> %s\n", QDir().toNativeSeparators(sFileName).toUtf8().data(), QDir().toNativeSeparators(sResultDirectory).toUtf8().data());
                } else {
                    printf("Cannot extract: %s\n", sFileName.toUtf8().data());
                    nResult = XOptions::CR_CANNOTOPENFILE;
                }
            }
        }

        bProcessed = true;
    }

    if (parser.isSet(clShowStructs)) {
        if (!listArgs.isEmpty()) {
            XBinary::FT fileType = scanOptions.fileType;

            QFile file;

            file.setFileName(listArgs.at(0));

            if (file.open(QIODevice::ReadOnly)) {
                if (fileType == XBinary::FT_UNKNOWN) {
                    fileType = XFormats::getPrefFileType(&file, true, &pdStruct);
                }

                XBinary *pBinary = XFormats::getClass(fileType, &file);

                if (pBinary) {
                    QList<XBinary::XFHEADER> listHeaders = pBinary->_getXFHeaders(&pdStruct);

                    XFTreeModel treeModel(nullptr);
                    treeModel.setData(pBinary, listHeaders);

                    QString sStructs;

                    if (scanOptions.bResultAsJSON) {
                        sStructs = treeModel.toJSON();
                    } else if (scanOptions.bResultAsXML) {
                        sStructs = treeModel.toXML();
                    } else if (scanOptions.bResultAsCSV) {
                        sStructs = treeModel.toCSV();
                    } else if (scanOptions.bResultAsTSV) {
                        sStructs = treeModel.toTSV();
                    } else {
                        sStructs = treeModel.toFormattedString();
                    }

                    printf("%s", sStructs.toUtf8().data());

                    delete pBinary;
                } else {
                    printf("Cannot read structures: %s\n", listArgs.at(0).toUtf8().data());
                    nResult = XOptions::CR_CANNOTOPENFILE;
                }

                file.close();
            } else {
                printf("Cannot open: %s\n", listArgs.at(0).toUtf8().data());
                nResult = XOptions::CR_CANNOTOPENFILE;
            }
        } else {
            printf("Error: --showstructs requires <target>\n");
            nResult = XOptions::CR_INVALIDPARAMETER;
        }

        bProcessed = true;
    }

    if (!bProcessed && !scanOptions.sStruct.isEmpty() && listArgs.isEmpty()) {
        printf("Error: --struct requires <target>\n");
        nResult = XOptions::CR_INVALIDPARAMETER;
        bProcessed = true;
    }

    if (!bProcessed && listArgs.count()) {
        if (bIsDatabaseUsing && !bIsDbUsed) {
            bDbLoaded = m_scanEngine.loadDatabase(&scanOptions, &pdStruct);
            bIsDbUsed = true;
        }

        if (!bIsDatabaseUsing || bDbLoaded) {
            nResult = handleFiles(listArgs, &scanOptions, m_scanEngine, &pdStruct);
        }

        bProcessed = true;
    }

    if (!bProcessed) {
        parser.showHelp();
        Q_UNREACHABLE();
    }

    if (bIsDbUsed && (!bDbLoaded)) {
        nResult = XOptions::CR_CANNOTFINDDATABASE;
    }

    return nResult;
}

XOptions::CR XScanEngineConsole::handleFiles(const QStringList &listArgs, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine &scanEngine, XBinary::PDSTRUCT *pPdStruct)
{
    XOptions::CR result = XOptions::CR_SUCCESS;

    QStringList listFileNames;

    for (const QString &sFileName : listArgs) {
        if (QFileInfo::exists(sFileName)) {
            XBinary::findFiles(sFileName, &listFileNames, pPdStruct);
        } else {
            printf("Cannot find: %s\n", sFileName.toUtf8().data());

            result = XOptions::CR_CANNOTFINDFILE;
        }
    }

    bool bShowFileName = listFileNames.count() > 1;

    qint32 nNumberOfFiles = listFileNames.count();

    for (qint32 i = 0; i < nNumberOfFiles; i++) {
        QString sFileName = listFileNames.at(i);

        if (bShowFileName) {
            printf("%s:\n", QDir().toNativeSeparators(sFileName).toUtf8().data());
        }

        if (pScanOptions->bShowEntropy) {
            QFile file;
            file.setFileName(sFileName);

            if (file.open(QIODevice::ReadOnly)) {
                QVector<XBinary::KeyValueItem> listItems = XFormats::getEntropy(&file, false, -1, pPdStruct);

                QString sResult;
                if (pScanOptions->bResultAsJSON) sResult = XFormats::toJSON(listItems);
                else if (pScanOptions->bResultAsXML) sResult = XFormats::toXML(listItems);
                else if (pScanOptions->bResultAsCSV) sResult = XFormats::toCSV(listItems);
                else if (pScanOptions->bResultAsTSV) sResult = XFormats::toTSV(listItems);
                else sResult = XFormats::toFormattedString(listItems);

                printf("%s", sResult.toUtf8().data());
                file.close();
            } else {
                printf("Cannot open: %s\n", sFileName.toUtf8().data());
                result = XOptions::CR_CANNOTOPENFILE;
            }
        } else if (pScanOptions->bShowFileInfo) {
            QFile file;
            file.setFileName(sFileName);

            if (file.open(QIODevice::ReadOnly)) {
                QVector<XBinary::KeyValueItem> listItems = XFormats::getFileInfo(&file, false, -1, pPdStruct);

                QString sResult;
                if (pScanOptions->bResultAsJSON) sResult = XFormats::toJSON(listItems);
                else if (pScanOptions->bResultAsXML) sResult = XFormats::toXML(listItems);
                else if (pScanOptions->bResultAsCSV) sResult = XFormats::toCSV(listItems);
                else if (pScanOptions->bResultAsTSV) sResult = XFormats::toTSV(listItems);
                else sResult = XFormats::toFormattedString(listItems);

                printf("%s", sResult.toUtf8().data());
                file.close();
            } else {
                printf("Cannot open: %s\n", sFileName.toUtf8().data());
                result = XOptions::CR_CANNOTOPENFILE;
            }
        } else if (pScanOptions->sStruct != "") {
            QFile file;

            file.setFileName(sFileName);

            if (file.open(QIODevice::ReadOnly)) {
                XBinary::XFHEADER xFHeader = XFormats::getXFHeaderFromStructName(&file, pScanOptions->sStruct, false, -1, pPdStruct);

                if (xFHeader.xfType != XBinary::XFTYPE_UNKNOWN) {
                    XBinary *pBinary = XFormats::getClass(xFHeader.fileType, &file);

                    if (pBinary) {
                        QString sStructInfo;

                        if (xFHeader.xfType == XBinary::XFTYPE_HEADER) {
                            XFModel_header modelHeader(nullptr);
                            modelHeader.setData(pBinary, xFHeader);

                            if (pScanOptions->bResultAsJSON) {
                                sStructInfo = modelHeader.toJSON();
                            } else if (pScanOptions->bResultAsXML) {
                                sStructInfo = modelHeader.toXML();
                            } else if (pScanOptions->bResultAsCSV) {
                                sStructInfo = XFModel::exportToString(&modelHeader, XFModel::EXPORT_CSV);
                            } else if (pScanOptions->bResultAsTSV) {
                                sStructInfo = XFModel::exportToString(&modelHeader, XFModel::EXPORT_TSV);
                            } else {
                                XOptions::printModel(&modelHeader);
                            }
	                        } else if (xFHeader.xfType == XBinary::XFTYPE_TABLE) {
	                            XFModel_table modelTable;
	                            modelTable.setData(pBinary, xFHeader);
	                            modelTable.setShowPresentation(true);

	                            if (pScanOptions->bResultAsJSON) {
	                                sStructInfo = modelTable.toJSON();
                            } else if (pScanOptions->bResultAsXML) {
                                sStructInfo = modelTable.toXML();
                            } else if (pScanOptions->bResultAsCSV) {
                                sStructInfo = XFModel::exportToString(&modelTable, XFModel::EXPORT_CSV);
                            } else if (pScanOptions->bResultAsTSV) {
                                sStructInfo = XFModel::exportToString(&modelTable, XFModel::EXPORT_TSV);
                            } else {
                                XOptions::printModel(&modelTable);
                            }
                        }

                        if (!sStructInfo.isEmpty()) {
                            printf("%s", sStructInfo.toUtf8().data());
                        }

                        delete pBinary;
                    } else {
                        printf("Cannot read structure: %s\n", sFileName.toUtf8().data());
                        result = XOptions::CR_CANNOTOPENFILE;
                    }
                } else {
                    printf("Cannot find struct '%s': %s\n", pScanOptions->sStruct.toUtf8().data(), sFileName.toUtf8().data());
                    result = XOptions::CR_INVALIDPARAMETER;
                }

                file.close();
            } else {
                printf("Cannot open: %s\n", sFileName.toUtf8().data());
                result = XOptions::CR_CANNOTOPENFILE;
            }
        } else {
            XScanEngine::SCAN_RESULT scanResult = scanEngine.scanFile(sFileName, pScanOptions, pPdStruct);

            ScanItemModel model(pScanOptions, &(scanResult.listRecords), 1, nullptr);

            XBinary::FORMATTYPE formatType = XBinary::FORMATTYPE_TEXT;

            if (pScanOptions->bResultAsCSV) formatType = XBinary::FORMATTYPE_CSV;
            else if (pScanOptions->bResultAsJSON) formatType = XBinary::FORMATTYPE_JSON;
            else if (pScanOptions->bResultAsTSV) formatType = XBinary::FORMATTYPE_TSV;
            else if (pScanOptions->bResultAsXML) formatType = XBinary::FORMATTYPE_XML;
            else if (pScanOptions->bResultAsPlainText) formatType = XBinary::FORMATTYPE_PLAINTEXT;

            if (formatType != XBinary::FORMATTYPE_TEXT) {
                printf("%s\n", model.toString(formatType).toUtf8().data());
            } else {
                model.coloredOutput();
            }

            if (scanResult.listErrors.count()) {
                printf("%s", XScanEngine::getErrorsString(&scanResult).toUtf8().data());
                result = XOptions::CR_CANNOTOPENFILE;
            }
            printf("\n");
        }
    }

    return result;
}
