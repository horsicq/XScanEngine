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

    m_pScanEngine = nullptr;

    // m_pModel = nullptr;
    // m_bProcess = false;

    // connect(&m_watcher, SIGNAL(finished()), this, SLOT(onScanFinished()));

    // connect(&m_dieScript, SIGNAL(errorMessage(QString)), this, SLOT(handleErrorString(QString)));
    // connect(&m_dieScript, SIGNAL(warningMessage(QString)), this, SLOT(handleWarningString(QString)));

    // ui->pushButtonDieLog->setEnabled(false);

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
    delete ui;
}

void XScanEngineWidget::setEngine(XScanEngine *pScanEngine)
{
    m_pScanEngine = pScanEngine;
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

    quint64 nFlags = XScanEngine::getScanFlagsFromGlobalOptions(getGlobalOptions());
    ui->comboBoxFlags->setValue(nFlags);

    quint64 nDatabases = XScanEngine::getDatabasesFromGlobalOptions(getGlobalOptions());
    ui->comboBoxDatabases->setValue(nDatabases);
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

    ui->treeViewResult->setModel(0);
}

void XScanEngineWidget::process()
{
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

        quint64 nFlags = ui->comboBoxFlags->getValue().toULongLong();
        XScanEngine::setScanFlags(&m_scanOptions, nFlags);

        quint64 nDatabases = ui->comboBoxDatabases->getValue().toULongLong();
        XScanEngine::setDatabases(&m_scanOptions, nDatabases);

        XScanEngine::setScanFlagsToGlobalOptions(getGlobalOptions(), nFlags);
        XScanEngine::setDatabasesToGlobalOptions(getGlobalOptions(), nDatabases);

        m_listErrorsAndWarnings.clear();

        if (m_scanType != ST_UNKNOWN) {
            if (m_scanType == ST_FILE) {
                emit scanStarted();

                if (m_pScanEngine->isDatabaseUsing()) {
                    XScanEngine::SCANENGINETYPE type = m_pScanEngine->getEngineType();
                    if(type == XScanEngine::SCANENGINETYPE_DIE) {
                        m_scanOptions.sMainDatabasePath = getGlobalOptions()->getValue(XOptions::ID_SCAN_DIE_DATABASE_MAIN_PATH).toString();
                        m_scanOptions.sExtraDatabasePath = getGlobalOptions()->getValue(XOptions::ID_SCAN_DIE_DATABASE_EXTRA_PATH).toString();
                        m_scanOptions.sCustomDatabasePath = getGlobalOptions()->getValue(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH).toString();
                    } else if (type == XScanEngine::SCANENGINETYPE_PEID) {
                        m_scanOptions.sMainDatabasePath = getGlobalOptions()->getValue(XOptions::ID_SCAN_PEID_DATABASE_PATH).toString();
                    }else if (type == XScanEngine::SCANENGINETYPE_YARA) {
                        m_scanOptions.sMainDatabasePath = getGlobalOptions()->getValue(XOptions::ID_SCAN_YARA_DATABASE_PATH).toString();
                    }

                    if (!m_bInitDatabase) {
                        m_bInitDatabase = m_pScanEngine->loadDatabase(&m_scanOptions, nullptr);
                    }
                }

                XScanEngineProcess scanEngineProcess(m_pScanEngine);

                connect(&scanEngineProcess, SIGNAL(scanFinished(qint64)), this, SLOT(onScanFinished(qint64)));

                XDialogProcess ds(this, &scanEngineProcess);
                ds.setGlobal(getShortcuts(), getGlobalOptions());
                scanEngineProcess.setData(m_sFileName, &m_scanOptions, &m_scanResult, ds.getPdStruct());
                ds.start();
                ds.exec();

                emit scanFinished();
            }
        }
}

void XScanEngineWidget::onScanFinished(qint64 nMsec)
{
    qint32 nNumberOfErrors = m_scanResult.listErrors.count() + m_listErrorsAndWarnings.count();

    QString sLogButtonText;

    if (nNumberOfErrors) {
        sLogButtonText = QString("%1(%2)").arg(tr("Log"), QString::number(nNumberOfErrors));
    } else {
        sLogButtonText = tr("Log");
    }

    ui->pushButtonLog->setText(sLogButtonText);
    ui->pushButtonLog->setEnabled(nNumberOfErrors);

    ui->toolButtonElapsedTime->setText(QString("%1 %2").arg(nMsec).arg(tr("msec")));

    m_pModel = new ScanItemModel(&m_scanOptions, &(m_scanResult.listRecords), 3, getGlobalOptions());
    ui->treeViewResult->setModel(m_pModel);
    ui->treeViewResult->expandAll();

    ui->treeViewResult->header()->setSectionResizeMode(COLUMN_STRING, QHeaderView::Stretch);
    ui->treeViewResult->header()->setSectionResizeMode(COLUMN_SIGNATURE, QHeaderView::Fixed);
    ui->treeViewResult->header()->setSectionResizeMode(COLUMN_INFO, QHeaderView::Fixed);

    ui->treeViewResult->setColumnWidth(COLUMN_SIGNATURE, 20);
    ui->treeViewResult->setColumnWidth(COLUMN_INFO, 20);

    ui->treeViewResult->header()->setVisible(false);
}

void XScanEngineWidget::registerShortcuts(bool bState)
{
    Q_UNUSED(bState)
}

void XScanEngineWidget::on_pushButtonScanStart_clicked()
{
    process();
}

void XScanEngineWidget::on_pushButtonScanDirectory_clicked()
{
    QString sDirPath = getGlobalOptions()->getValue(XOptions::ID_SCAN_DIRECTORY_PATH).toString();

    if (sDirPath == "") {
        getGlobalOptions()->setValue(XOptions::ID_SCAN_DIRECTORY_PATH, QFileInfo(m_sFileName).absolutePath());
    }

    DialogXScanEngineDirectory dialogDirectory(this);
    dialogDirectory.setGlobal(getShortcuts(), getGlobalOptions());
    dialogDirectory.setEngine(m_pScanEngine);
    dialogDirectory.exec();
}

void XScanEngineWidget::on_pushButtonCollection_clicked()
{
    QString sDirPath = getGlobalOptions()->getValue(XOptions::ID_SCAN_DIRECTORY_PATH).toString();

    if (sDirPath == "") {
        getGlobalOptions()->setValue(XOptions::ID_SCAN_DIRECTORY_PATH, QFileInfo(m_sFileName).absolutePath());
    }

    DialogXScanSort dialogSort(this);
    dialogSort.setGlobal(getShortcuts(), getGlobalOptions());
    dialogSort.setEngine(m_pScanEngine);
    dialogSort.exec();
}

void XScanEngineWidget::on_pushButtonLog_clicked()
{

}

void XScanEngineWidget::on_pushButtonExtraInformation_clicked()
{

}

void XScanEngineWidget::on_toolButtonElapsedTime_clicked()
{

}

