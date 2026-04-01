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
#include "xscanenginewidget.h"
#include "ui_xscanenginewidget.h"

XScanEngineWidget::XScanEngineWidget(QWidget *pParent) : XShortcutsWidget(pParent), ui(new Ui::XScanEngineWidget)
{
    ui->setupUi(this);

    m_pdStruct = XBinary::createPdStruct();
    // m_pModel = nullptr;
    // m_bProcess = false;

    // connect(&m_watcher, SIGNAL(finished()), this, SLOT(onScanFinished()));

    // connect(&m_dieScript, SIGNAL(errorMessage(QString)), this, SLOT(handleErrorString(QString)));
    // connect(&m_dieScript, SIGNAL(warningMessage(QString)), this, SLOT(handleWarningString(QString)));

    // ui->pushButtonDieLog->setEnabled(false);

    m_pTimer = new QTimer(this);
    connect(m_pTimer, SIGNAL(timeout()), this, SLOT(timerSlot()));

    clear();

    m_bInitDatabase = false;

    ui->comboBoxFlags->setData(XScanEngine::getScanFlags(), XComboBoxEx::CBTYPE_FLAGS, 0, tr("Flags"));
    ui->comboBoxDatabases->setData(XScanEngine::getDatabases(), XComboBoxEx::CBTYPE_FLAGS, 0, tr("Database"));

    // ui->comboBoxDatabases->setItemEnabled(1, false);

    // ui->stackedWidgetDieScan->setCurrentIndex(0);

    // ui->toolButtonElapsedTime->setText(QString("%1 %2").arg(0).arg(tr("msec")));  // TODO Function
}

XScanEngineWidget::~XScanEngineWidget()
{
    if (m_bProcess) {
        stop();
        m_watcher.waitForFinished();
    }

    delete ui;
}

void XScanEngineWidget::setData(const QString &sFileName, bool bScan, XBinary::FT fileType)
{
    clear();

    this->m_sFileName = sFileName;
    this->m_fileType = fileType;
    m_scanType = ST_FILE;

    if (bScan) {
        process();
    }
}

void XScanEngineWidget::adjustView()
{
    this->m_sInfoPath = getGlobalOptions()->getInfoPath();
    m_bInitDatabase = false;

    // quint64 nFlags = XScanEngine::getScanFlagsFromGlobalOptions(getGlobalOptions());
    // ui->comboBoxFlags->setValue(nFlags);

    // quint64 nDatabases = XScanEngine::getDatabasesFromGlobalOptions(getGlobalOptions());
    // ui->comboBoxDatabases->setValue(nDatabases);
}

void XScanEngineWidget::setGlobal(XShortcuts *pShortcuts, XOptions *pXOptions)
{
    XShortcutsWidget::setGlobal(pShortcuts, pXOptions);
}

void XScanEngineWidget::reloadData(bool bSaveSelection)
{
    Q_UNUSED(bSaveSelection)
    process();
}

void XScanEngineWidget::clear()
{
    m_scanType = ST_UNKNOWN;
    m_scanOptions = {};
    m_scanResult = {};
    m_bProcess = false;

    ui->treeViewResult->setModel(0);
}

void XScanEngineWidget::process()
{
    if (!m_bProcess) {
        // enableControls(false);
        m_bProcess = true;

        m_scanOptions.bUseCustomDatabase = true;
        m_scanOptions.bUseExtraDatabase = true;
        m_scanOptions.bShowType = true;
        m_scanOptions.bShowVersion = true;
        m_scanOptions.bShowInfo = true;
        m_scanOptions.bLogProfiling = getGlobalOptions()->getValue(XOptions::ID_SCAN_LOG_PROFILING).toBool();
        m_scanOptions.fileType = m_fileType;
        m_scanOptions.bShowScanTime = true;
        m_scanOptions.bHideUnknown = getGlobalOptions()->getValue(XOptions::ID_SCAN_HIDEUNKNOWN).toBool();
        m_scanOptions.bIsSort = getGlobalOptions()->getValue(XOptions::ID_SCAN_SORT).toBool();

        // quint64 nFlags = ui->comboBoxFlags->getValue().toULongLong();
        // XScanEngine::setScanFlags(&m_scanOptions, nFlags);

        // quint64 nDatabases = ui->comboBoxDatabases->getValue().toULongLong();
        // XScanEngine::setDatabases(&m_scanOptions, nDatabases);

        // XScanEngine::setScanFlagsToGlobalOptions(getGlobalOptions(), nFlags);
        // XScanEngine::setDatabasesToGlobalOptions(getGlobalOptions(), nDatabases);

        // m_pTimer->start(200);

        // ui->progressBar0->hide();
        // ui->progressBar1->hide();
        // ui->progressBar2->hide();
        // ui->progressBar3->hide();
        // ui->progressBar4->hide();

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        QFuture<void> future = QtConcurrent::run(&XScanEngineWidget::scan, this);
#else
        QFuture<void> future = QtConcurrent::run(this, &XScanEngineWidget::scan);
#endif

        m_watcher.setFuture(future);
    } else {
        stop();
        m_watcher.waitForFinished();
        // enableControls(true);
    }
}

void XScanEngineWidget::scan()
{
    m_listErrorsAndWarnings.clear();

    if (m_scanType != ST_UNKNOWN) {
        if (m_scanType == ST_FILE) {
            emit scanStarted();

            m_scanOptions.sMainDatabasePath = getGlobalOptions()->getValue(XOptions::ID_SCAN_DIE_DATABASE_MAIN_PATH).toString();
            m_scanOptions.sExtraDatabasePath = getGlobalOptions()->getValue(XOptions::ID_SCAN_DIE_DATABASE_EXTRA_PATH).toString();
            m_scanOptions.sCustomDatabasePath = getGlobalOptions()->getValue(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH).toString();

            m_pdStruct = XBinary::createPdStruct();

            // if (!m_bInitDatabase) {
            //     m_bInitDatabase = m_dieScript.loadDatabase(&m_scanOptions, nullptr);
            // }

            // m_scanResult = m_dieScript.scanFile(m_sFileName, &m_scanOptions, &m_pdStruct);

            // if (m_scanResult.ftInit == XBinary::FT_COM) {
            //     emit currentFileType(m_scanResult.ftInit);
            // }

            emit scanFinished();
        }
    }
}

void XScanEngineWidget::stop()
{
    m_pdStruct.bIsStop = true;
}

void XScanEngineWidget::onScanFinished()
{
    m_bProcess = false;

    m_pTimer->stop();

    qint32 nNumberOfErrors = m_scanResult.listErrors.count() + m_listErrorsAndWarnings.count();

    QString sLogButtonText;

    if (nNumberOfErrors) {
        sLogButtonText = QString("%1(%2)").arg(tr("Log"), QString::number(nNumberOfErrors));
    } else {
        sLogButtonText = tr("Log");
    }

    // ui->pushButtonDieLog->setText(sLogButtonText);
    // ui->pushButtonDieLog->setEnabled(nNumberOfErrors);

    // ui->toolButtonElapsedTime->setText(QString("%1 %2").arg(m_scanResult.nScanTime).arg(tr("msec")));

    // ScanItemModel *pOldModel = m_pModel;

    // m_pModel = new ScanItemModel(&m_scanOptions, &(m_scanResult.listRecords), 3, getGlobalOptions());
    // ui->treeViewResult->setModel(m_pModel);
    // ui->treeViewResult->expandAll();

    // if (pOldModel) {
    //     delete pOldModel;
    // }
}

void XScanEngineWidget::registerShortcuts(bool bState)
{
    Q_UNUSED(bState)
}
