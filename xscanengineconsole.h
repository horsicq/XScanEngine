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
#ifndef XSCANENGINECONSOLE_H
#define XSCANENGINECONSOLE_H

#include "xscanengine.h"
#include "scanitemmodel.h"
#include "xarchiveconsole.h"
#include "xformats.h"
#include "xftree_model.h"
#include "xfmodel_header.h"
#include "xfmodel_table.h"

#include <QStringList>

class QCommandLineParser;

class XScanEngineConsole : public QObject {
    Q_OBJECT

public:
    // pArchiveConsole (optional): the archive front end that implements
    // --listarchive / --extractarchive.  Applications that are archive tools in
    // their own right compose one and pass it here; when it is nullptr this
    // object owns a default instance, so every existing front end is unchanged.
    explicit XScanEngineConsole(QCoreApplication &app, XScanEngine &scanEngine, const QString &sDescription, XArchiveConsole *pArchiveConsole = nullptr,
                                QObject *pParent = nullptr);

public slots:
    int process();
    XOptions::CR handleFiles(const QStringList &listArgs, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine &scanEngine, XBinary::PDSTRUCT *pPdStruct);

protected:
    // Engine-specific extension points. The default implementations below use
    // the XFormats-based viewers; engines with their own viewers (die_script's
    // EntropyProcess/XFileInfo) override them to keep their established output.
    virtual void addEngineOptions(QCommandLineParser *pParser);
    virtual void applyEngineOptions(const QCommandLineParser *pParser, XScanEngine::SCAN_OPTIONS *pScanOptions);
    // Returns true when an engine-specific mode consumed the invocation.
    virtual bool processEngineModes(const QCommandLineParser *pParser, const QStringList &listArgs, XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct,
                                    qint32 *pnResult);
    // Called when a scan produced engine errors; the returned code (if not
    // CR_SUCCESS) becomes the process result. diec overrides this to keep its
    // historical exit code 0 for scans with script errors.
    virtual XOptions::CR reportScanErrors(XScanEngine::SCAN_RESULT *pScanResult);
    virtual XOptions::CR showDatabaseState(XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct);
    virtual XOptions::CR showStructsOverview(const QStringList &listArgs, XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct);
    virtual XOptions::CR showFileEntropy(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct);
    virtual XOptions::CR showFileInfo(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct);
    virtual XOptions::CR showFileStruct(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct);

    XScanEngine *scanEngine();
    XArchiveConsole *archiveConsole();

private:
    QCoreApplication &m_app;
    XScanEngine &m_scanEngine;
    QString m_sDescription;
    XArchiveConsole *m_pArchiveConsole;
};

#endif  // XSCANENGINECONSOLE_H
