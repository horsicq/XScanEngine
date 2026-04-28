/* Copyright (c) 2025 hors<horsicq@gmail.com>
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
#include "xscansortwidget.h"

#include "ui_xscansortwidget.h"

XScanSortWidget::XScanSortWidget(QWidget *pParent)
    : XShortcutsWidget(pParent), ui(new Ui::XScanSortWidget)
{
    ui->setupUi(this);

    m_pScanEngine = nullptr;
    m_scanOptions = {};
}

XScanSortWidget::~XScanSortWidget()
{
    XScanEngine::setScanFlagsToGlobalOptions(&m_sortOptions, ui->comboBoxFlags->getValue().toULongLong());
    m_sortOptions.setValue(XOptions::ID_SCAN_DIRECTORY_PATH, ui->lineEditDirectoryName->text());
    m_sortOptions.setValue(XOptions::ID_SCAN_SUBDIRECTORIES, ui->checkBoxScanSubdirectories->isChecked());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_ALLTYPES, ui->checkBoxAllTypes->isChecked());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_ALLFILETYPES, ui->checkBoxAllFileTypes->isChecked());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_CATALOG_ENABLED, ui->groupBoxCatalog->isChecked());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_COPY_ENABLED, ui->groupBoxCopy->isChecked());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_CATALOG_FORMAT, ui->lineEditCatalogFormat->text());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_COPY_FORMAT, ui->lineEditCopyFormat->text());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_RESULT_PATH, ui->lineEditResult->text());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_LOG, ui->checkBoxScanLog->isChecked());

    m_sortOptions.save();

    delete ui;
}

void XScanSortWidget::adjustView()
{

}

void XScanSortWidget::setGlobal(XShortcuts *pShortcuts, XOptions *pXOptions)
{
    if (pXOptions) {
        if (ui->lineEditDirectoryName->text().isEmpty()) {
            QString sDirPath = pXOptions->getValue(XOptions::ID_SCAN_DIRECTORY_PATH).toString();
            ui->lineEditDirectoryName->setText(QDir().toNativeSeparators(sDirPath));
        }
    }

    XShortcutsWidget::setGlobal(pShortcuts, pXOptions);
}

void XScanSortWidget::setEngine(XScanEngine *pScanEngine)
{
    m_pScanEngine = pScanEngine;

    m_sortOptions.setName(QString("collection_%1").arg(pScanEngine->getEngineName()));

    m_sortOptions.addID(XOptions::ID_SCAN_FLAG_AGGRESSIVE, false);
    m_sortOptions.addID(XOptions::ID_SCAN_FLAG_ALLTYPES, false);
    m_sortOptions.addID(XOptions::ID_SCAN_FLAG_ARCHIVES, false);
    m_sortOptions.addID(XOptions::ID_SCAN_FLAG_DEEP, true);
    m_sortOptions.addID(XOptions::ID_SCAN_FLAG_HEURISTIC, false);
    m_sortOptions.addID(XOptions::ID_SCAN_FLAG_OVERLAY, false);
    m_sortOptions.addID(XOptions::ID_SCAN_FLAG_RESOURCES, false);
    m_sortOptions.addID(XOptions::ID_SCAN_FLAG_RECURSIVE, false);
    m_sortOptions.addID(XOptions::ID_SCAN_FLAG_VERBOSE, false);

    m_sortOptions.addID(XOptions::ID_SCAN_DIRECTORY_PATH, "");
    m_sortOptions.addID(XOptions::ID_SCAN_SUBDIRECTORIES, true);
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_ALLFILETYPES, true);
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_ALLTYPES, true);
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_FILETYPES, XBinary::fileTypesToString(pScanEngine->getFileTypesSupported()));
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_TYPES, "");
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_CATALOG_ENABLED, false);
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_CATALOG_FORMAT, "{ft}.{type}.{name}.{version}.{info}.txt");
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_COPY_ENABLED, false);
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_COPY_FORMAT, "{ft}/{type}/{name}.{version}.{info}");
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_RESULT_PATH, "collection");
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_LOG, false);

    m_sortOptions.load();

    ui->comboBoxFlags->setData(XScanEngine::getScanFlags(), XComboBoxEx::CBTYPE_FLAGS, 0, tr("Flags"));

    ui->comboBoxFlags->setValue(XScanEngine::getScanFlagsFromGlobalOptions(&m_sortOptions));

    ui->lineEditDirectoryName->setText(m_sortOptions.getValue(XOptions::ID_SCAN_DIRECTORY_PATH).toString());
    ui->checkBoxScanSubdirectories->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_SUBDIRECTORIES).toBool());

    ui->checkBoxAllFileTypes->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_ALLFILETYPES).toBool());
    ui->checkBoxAllTypes->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_ALLTYPES).toBool());

    ui->groupBoxCatalog->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_CATALOG_ENABLED).toBool());
    ui->groupBoxCopy->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_COPY_ENABLED).toBool());
    ui->lineEditCatalogFormat->setText(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_CATALOG_FORMAT).toString());
    ui->lineEditCopyFormat->setText(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_COPY_FORMAT).toString());

    ui->lineEditResult->setText(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_RESULT_PATH).toString());
    ui->checkBoxScanLog->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_LOG).toBool());
}

void XScanSortWidget::on_pushButtonOpenDirectory_clicked()
{
    QString sDirectoryName = QFileDialog::getExistingDirectory(this, tr("Open Directory"), ui->lineEditDirectoryName->text());

    if (!sDirectoryName.isEmpty()) {
        ui->lineEditDirectoryName->setText(sDirectoryName);
    }
}

void XScanSortWidget::on_pushButtonScan_clicked()
{
    QString sDirectory = ui->lineEditDirectoryName->text().trimmed();

    m_scanOptions.bSubdirectories = ui->checkBoxScanSubdirectories->isChecked();
    m_scanOptions.bCollection = true;
    m_scanOptions.bCollectionAllFileTypes = ui->checkBoxAllFileTypes->isChecked();
    m_scanOptions.bCollectionAllTypes = ui->checkBoxAllTypes->isChecked();
    m_scanOptions.bCollectionCopyFiles = ui->groupBoxCopy->isChecked();
    m_scanOptions.sCollectionCopyFormat = ui->lineEditCopyFormat->text();
    m_scanOptions.bCollectionCreateCatalog = ui->groupBoxCatalog->isChecked();
    m_scanOptions.sCollectionCatalogFormat = ui->lineEditCatalogFormat->text();
    m_scanOptions.sCollectionResultDirectory = ui->lineEditResult->text();
    m_scanOptions.bCollectionLog = ui->checkBoxScanLog->isChecked();
    XScanEngine::setScanFlags(&m_scanOptions, ui->comboBoxFlags->getValue().toULongLong());

    XScanEngineProcess scanEngineProcess(m_pScanEngine);

    XDialogProcess ds(this, &scanEngineProcess);
    ds.setGlobal(getShortcuts(), getGlobalOptions());
    scanEngineProcess.setData(sDirectory, &m_scanOptions, ds.getPdStruct());
    ds.start();
    ds.exec();
}

void XScanSortWidget::on_checkBoxAllFileTypes_stateChanged(int nState)
{
    Q_UNUSED(nState)

    ui->comboBoxFileType->setEnabled(ui->checkBoxAllFileTypes->checkState() != Qt::Checked);
}

void XScanSortWidget::on_checkBoxAllTypes_stateChanged(int nState)
{
    Q_UNUSED(nState)

    ui->comboBoxType->setEnabled(ui->checkBoxAllTypes->checkState() != Qt::Checked);
}

void XScanSortWidget::on_toolButtonCatalogInfo_clicked()
{
    QMessageBox::information(this, tr("Format"), XScanEngine::getAvailablePathVariables());
}

void XScanSortWidget::on_toolButtonCopyInfo_clicked()
{
    QMessageBox::information(this, tr("Format"), XScanEngine::getAvailablePathVariables());
}

void XScanSortWidget::on_pushButtonResult_clicked()
{
    QString sDirectoryName = QFileDialog::getExistingDirectory(this, tr("Open Directory"), ui->lineEditResult->text());

    if (!sDirectoryName.isEmpty()) {
        ui->lineEditResult->setText(sDirectoryName);
    }
}

