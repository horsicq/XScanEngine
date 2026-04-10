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
    QCommandLineOption clSpecial = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_SPECIAL);
    QCommandLineOption clShowMethods = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_SHOWMETHODS);
    QCommandLineOption clTest = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_TEST);
    QCommandLineOption clAddTest = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_ADDTEST);
    QCommandLineOption clOverlayScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_OVERLAYSCAN);
    QCommandLineOption clResourcesScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_RESOURCESSCAN);
    QCommandLineOption clArchivesScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_ARCHIVESSCAN);
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
    parser.addOption(clSpecial);
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
    parser.addOption(clShowMethods);
    parser.addOption(clTest);
    parser.addOption(clAddTest);

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
    scanOptions.bIsOverlayScan = parser.isSet(clOverlayScan);
    scanOptions.bIsResourcesScan = parser.isSet(clResourcesScan);
    scanOptions.bIsArchivesScan = parser.isSet(clArchivesScan);
    scanOptions.fileType = parser.isSet(clFileType) ? XBinary::ftStringToFileTypeId(parser.value(clFileType)) : XBinary::FT_UNKNOWN;

    scanOptions.sSpecial = parser.value(clSpecial);

    if (bHasMainDb) {
        scanOptions.sMainDatabasePath = parser.value(clDatabaseMain);
    }
    if (bHasExtraCustomDb) {
        scanOptions.sExtraDatabasePath = parser.value(clDatabaseExtra);
        scanOptions.sCustomDatabasePath = parser.value(clDatabaseCustom);
    }
    QString sTestDirectory = parser.value(clTest);
    QString sAddTestFilename = parser.value(clAddTest);

    if (scanOptions.sMainDatabasePath == "") {
        if (engineType == XScanEngine::SCANENGINETYPE_PEID) {
            scanOptions.sMainDatabasePath = XOptions().getApplicationDataPath() + QDir::separator() + "peid";
        } else if (engineType == XScanEngine::SCANENGINETYPE_YARA) {
            scanOptions.sMainDatabasePath = XOptions().getApplicationDataPath() + QDir::separator() + "yara";
        } else {
            scanOptions.sMainDatabasePath = XOptions().getApplicationDataPath() + QDir::separator() + "db";
        }
    }

    if (bHasExtraCustomDb) {
        if (scanOptions.sExtraDatabasePath == "") {
            scanOptions.sExtraDatabasePath = XOptions().getApplicationDataPath() + QDir::separator() + "db_extra";
        }

        if (scanOptions.sCustomDatabasePath == "") {
            scanOptions.sCustomDatabasePath = XOptions().getApplicationDataPath() + QDir::separator() + "db_custom";
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
        } else {
            sResullt = XScanEngine::databaseStateToText(dataBaseState);
        }

        printf("%s", sResullt.toUtf8().data());
    }

    if (parser.isSet(clShowMethods)) {
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

                    QString sMethods;

                    if (scanOptions.bResultAsJSON) {
                        sMethods = treeModel.toJSON();
                    } else if (scanOptions.bResultAsXML) {
                        sMethods = treeModel.toXML();
                    } else {
                        sMethods = treeModel.toFormattedString();
                    }

                    printf("%s", sMethods.toUtf8().data());
                }

                file.close();
            }
        }

        // QList<QString> listMethods = XFileInfo::getMethodNames(fileType);

        // qint32 nNumberOfMethods = listMethods.count();

        // for (qint32 i = 0; i < nNumberOfMethods; i++) {
        //     printf("\t%s\n", listMethods.at(i).toUtf8().data());
        // }
    } else if (parser.isSet(clTest)) {
        if (!bIsDbUsed) {
            bDbLoaded = m_pScanEngine->loadDatabase(&scanOptions, &pdStruct);
            bIsDbUsed = true;
        }

        // TODO
    } else if (parser.isSet(clAddTest)) {
        if (!bIsDbUsed) {
            bDbLoaded = m_pScanEngine->loadDatabase(&scanOptions, &pdStruct);
            bIsDbUsed = true;
        }

        if (listArgs.count() >= 2) {
            QString sDetectString = listArgs.at(0);
            QString sDirectory = listArgs.at(1);
            printf("Adding test for file '%s' with detect string '%s' in directory '%s'\n", sAddTestFilename.toUtf8().data(), sDetectString.toUtf8().data(),
                   sDirectory.toUtf8().data());

            // TODO
        } else {
            printf("Error: --addtest requires <filename> <detect_string> <directory>\n");
            nResult = XOptions::CR_INVALIDPARAMETER;
        }
    } else if (listArgs.count()) {
        if (!bIsDbUsed) {
            bDbLoaded = m_pScanEngine->loadDatabase(&scanOptions, &pdStruct);
            bIsDbUsed = true;
        }

        if (bDbLoaded) {
            qint32 nFiles = listArgs.count();

            for (qint32 i = 0; i < nFiles; i++) {
                const QString &sFile = listArgs.at(i);

                XScanEngine::SCAN_RESULT scanResult = m_pScanEngine->scanFile(sFile, &scanOptions, &pdStruct);

                QString sResult;

                if (scanOptions.bResultAsJSON) {
                    sResult = XScanEngine::scanResultToJson(scanResult);
                } else if (scanOptions.bResultAsXML) {
                    sResult = XScanEngine::scanResultToXml(scanResult);
                } else {
                    sResult = XScanEngine::createResultString(&scanOptions, scanResult);
                }

                if (nFiles > 1) {
                    printf("%s:\n", sFile.toUtf8().data());
                }

                printf("%s", sResult.toUtf8().data());
            }
        }
    } else if (!parser.isSet(clShowDatabase)) {
        parser.showHelp();
        Q_UNREACHABLE();
    }

    if (bIsDbUsed && (!bDbLoaded)) {
        nResult = XOptions::CR_CANNOTFINDDATABASE;
    }

    return nResult;
}
