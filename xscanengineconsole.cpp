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

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QXmlStreamWriter>

XScanEngineConsole::XScanEngineConsole(QCoreApplication *pApp, XScanEngine *pScanEngine, const QString &sDescription, QObject *pParent)
    : QObject(pParent), m_pApp(pApp), m_pScanEngine(pScanEngine), m_sDescription(sDescription)
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

    XScanEngine::SCANENGINETYPE engineType = m_pScanEngine->getEngineType();
    bool bHasMainDb = (engineType != XScanEngine::SCANENGINETYPE_NFD);
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
    // QCommandLineOption clTest = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_TEST);
    // QCommandLineOption clAddTest = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_ADDTEST);

    QCommandLineOption clFileType = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_FILETYPE);

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
    parser.addOption(clShowStructs);
    // parser.addOption(clTest);
    // parser.addOption(clAddTest);

    parser.process(*m_pApp);

    QList<QString> listArgs = parser.positionalArguments();

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

    scanOptions.sStruct = parser.value(clStruct);

    //scanOptions.sSpecial = parser.value(clStruct);

    if (bHasMainDb) {
        scanOptions.sMainDatabasePath = parser.value(clDatabaseMain);
    }
    if (bHasExtraCustomDb) {
        scanOptions.sExtraDatabasePath = parser.value(clDatabaseExtra);
        scanOptions.sCustomDatabasePath = parser.value(clDatabaseCustom);
    }
    // QString sTestDirectory = parser.value(clTest);
    // QString sAddTestFilename = parser.value(clAddTest);

    if (scanOptions.sMainDatabasePath == "") {
        if (engineType == XScanEngine::SCANENGINETYPE_PEID) {
            scanOptions.sMainDatabasePath = "$data/peid";
        } else if (engineType == XScanEngine::SCANENGINETYPE_YARA) {
            scanOptions.sMainDatabasePath = "$data/yara";
        } else {
            scanOptions.sMainDatabasePath = "$data/db";
        }
    }

    if (bHasExtraCustomDb) {
        if (scanOptions.sExtraDatabasePath == "") {
            scanOptions.sExtraDatabasePath = "$data/db_extra";
        }

        if (scanOptions.sCustomDatabasePath == "") {
            scanOptions.sCustomDatabasePath = "$data/db_custom";
        }
    }

    XConsoleOutput consoleOutput;

    if (parser.isSet(clMessages)) {
        QObject::connect(m_pScanEngine, SIGNAL(errorMessage(QString)), &consoleOutput, SLOT(errorMessage(QString)));
        QObject::connect(m_pScanEngine, SIGNAL(warningMessage(QString)), &consoleOutput, SLOT(warningMessage(QString)));
        QObject::connect(m_pScanEngine, SIGNAL(infoMessage(QString)), &consoleOutput, SLOT(infoMessage(QString)));
    }

    bool bIsDbUsed = false;
    bool bDbLoaded = false;
    bool bProcessed = false;

    if (parser.isSet(clShowDatabase)) {
        if (!bIsDbUsed) {
            bDbLoaded = m_pScanEngine->loadDatabase(&scanOptions, &pdStruct);
            bIsDbUsed = true;
        }

        XScanEngine::DATABASE_STATE dataBaseState = m_pScanEngine->getDatabaseState(&scanOptions);

        QString sResullt;

        if (scanOptions.bResultAsJSON) {
            sResullt = XScanEngine::databaseStateToJson(dataBaseState);
        } else if (scanOptions.bResultAsXML) {
            sResullt = XScanEngine::databaseStateToXml(dataBaseState);
        } else if (scanOptions.bResultAsCSV) {
            sResullt = XScanEngine::databaseStateToCSV(dataBaseState);
        } else if (scanOptions.bResultAsTSV) {
            sResullt = XScanEngine::databaseStateToTSV(dataBaseState);
        } else {
            sResullt = XScanEngine::databaseStateToText(dataBaseState);
        }

        printf("%s", sResullt.toUtf8().data());
        bProcessed = true;
    }

    if (parser.isSet(clShowStructs)) {
        if (listArgs.count() > 0) {
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
                }

                file.close();
            }
        }

        bProcessed = true;
    }

    // if (parser.isSet(clTest)) {
    //     if (!bIsDbUsed) {
    //         bDbLoaded = m_pScanEngine->loadDatabase(&scanOptions, &pdStruct);
    //         bIsDbUsed = true;
    //     }

    //     // TODO
    // } else if (parser.isSet(clAddTest)) {
    //     if (!bIsDbUsed) {
    //         bDbLoaded = m_pScanEngine->loadDatabase(&scanOptions, &pdStruct);
    //         bIsDbUsed = true;
    //     }

    //     if (listArgs.count() >= 2) {
    //         QString sDetectString = listArgs.at(0);
    //         QString sDirectory = listArgs.at(1);
    //         printf("Adding test for file '%s' with detect string '%s' in directory '%s'\n", sAddTestFilename.toUtf8().data(), sDetectString.toUtf8().data(),
    //                sDirectory.toUtf8().data());

    //         // TODO
    //     } else {
    //         printf("Error: --addtest requires <filename> <detect_string> <directory>\n");
    //         nResult = XOptions::CR_INVALIDPARAMETER;
    //     }
    // }

    if (listArgs.count()) {
        if (!bIsDbUsed) {
            bDbLoaded = m_pScanEngine->loadDatabase(&scanOptions, &pdStruct);
            bIsDbUsed = true;
        }

        if (bDbLoaded) {
            nResult = handleFiles(&listArgs, &scanOptions, m_pScanEngine, &pdStruct);
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

XOptions::CR XScanEngineConsole::handleFiles(QList<QString> *pListArgs, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine *pScanEngine, XBinary::PDSTRUCT *pPdStruct)
{
    XOptions::CR result = XOptions::CR_SUCCESS;

    QList<QString> listFileNames;

    for (qint32 i = 0; i < pListArgs->count(); i++) {
        QString sFileName = pListArgs->at(i);

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
                if (pScanOptions->bResultAsJSON)           sResult = XFormats::toJSON(listItems);
                else if (pScanOptions->bResultAsXML)       sResult = XFormats::toXML(listItems);
                else if (pScanOptions->bResultAsCSV)       sResult = XFormats::toCSV(listItems);
                else if (pScanOptions->bResultAsTSV)       sResult = XFormats::toTSV(listItems);
                else                                       sResult = XFormats::toFormattedString(listItems);

                printf("%s", sResult.toUtf8().data());
                file.close();
            }
        } else if (pScanOptions->bShowFileInfo) {
            QFile file;
            file.setFileName(sFileName);

            if (file.open(QIODevice::ReadOnly)) {
                QVector<XBinary::KeyValueItem> listItems = XFormats::getFileInfo(&file, false, -1, pPdStruct);

                QString sResult;
                if (pScanOptions->bResultAsJSON)           sResult = XFormats::toJSON(listItems);
                else if (pScanOptions->bResultAsXML)       sResult = XFormats::toXML(listItems);
                else if (pScanOptions->bResultAsCSV)       sResult = XFormats::toCSV(listItems);
                else if (pScanOptions->bResultAsTSV)       sResult = XFormats::toTSV(listItems);
                else                                       sResult = XFormats::toFormattedString(listItems);

                printf("%s", sResult.toUtf8().data());
                file.close();
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

                        if (sStructInfo != "") {
                            printf("%s", sStructInfo.toUtf8().data());
                        }

                        delete pBinary;
                    }
                }

                file.close();
            }
        } else {
            XBinary::PDSTRUCT pdStruct = XBinary::createPdStruct();
            // pdStruct.pCallback = progressCallback;
            pdStruct.pCallbackUserData = nullptr;

            XScanEngine::SCAN_RESULT scanResult = pScanEngine->scanFile(sFileName, pScanOptions, &pdStruct);

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
                // Colored text
                model.coloredOutput();
            }

            //            QList<XBinary::SCANSTRUCT> listResult=DiE_Script::convert(&(scanResult.listRecords));

            //            ScanItemModel model(&listResult);

            //            printf("%s",model.toFormattedString().toUtf8().data());

            if (scanResult.listErrors.count()) {
                printf("%s", XScanEngine::getErrorsString(&scanResult).toUtf8().data());
            }
            printf("\n");
        }
    }

    return result;
}
