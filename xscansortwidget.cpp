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
    : QWidget(pParent), ui(new Ui::XScanSortWidget), m_pScanOptions(nullptr), m_pModel(nullptr),
      m_pProxyModel(nullptr), m_pScanThread(nullptr), m_bIsScanning(false)
{
    ui->setupUi(this);

    // Create default options
    m_pScanOptions = new XScanEngine::SCAN_OPTIONS;
    *m_pScanOptions = XScanEngine::getDefaultOptions(0);

    // Setup model and proxy
    m_pModel = new ScanItemModel(m_pScanOptions, nullptr, 1);
    m_pProxyModel = new QSortFilterProxyModel(this);
    m_pProxyModel->setSourceModel(m_pModel);
    m_pProxyModel->setFilterKeyColumn(0);

    // Create and setup table view
    QTableView *pTableView = new QTableView;
    pTableView->setModel(m_pProxyModel);
    pTableView->setSortingEnabled(true);
    pTableView->resizeColumnsToContents();

    // Insert table view into the layout (after horizontalLayout_2)
    ui->horizontalLayout_2->addWidget(pTableView);

    // Populate combo boxes
    populateFlags();
    populateFileTypes();
    populateTypes();

    // Setup connections
    setupConnections();
}

XScanSortWidget::~XScanSortWidget()
{
    if (m_pScanOptions) {
        delete m_pScanOptions;
    }
    if (m_pModel) {
        delete m_pModel;
    }
    delete ui;
}

void XScanSortWidget::setupConnections()
{
    connect(ui->pushButtonOpenDirectory, SIGNAL(clicked()), this, SLOT(on_pushButtonOpenDirectory_clicked()));
    connect(ui->pushButtonScan, SIGNAL(clicked()), this, SLOT(on_pushButtonScan_clicked()));
    connect(ui->pushButtonResult, SIGNAL(clicked()), this, SLOT(on_pushButtonResult_clicked()));
    connect(ui->checkBoxAllFileTypes, SIGNAL(toggled(bool)), this, SLOT(on_checkBoxAllFileTypes_toggled(bool)));
    connect(ui->checkBoxAllTypes, SIGNAL(toggled(bool)), this, SLOT(on_checkBoxAllTypes_toggled(bool)));
    connect(ui->comboBoxFileType, SIGNAL(currentIndexChanged(int)), this, SLOT(on_comboBoxFileType_currentIndexChanged(int)));
    connect(ui->comboBoxType, SIGNAL(currentIndexChanged(int)), this, SLOT(on_comboBoxType_currentIndexChanged(int)));
    connect(ui->comboBoxFlags, SIGNAL(currentIndexChanged(int)), this, SLOT(on_comboBoxFlags_currentIndexChanged(int)));
    connect(ui->lineEditDirectoryName, SIGNAL(textChanged(QString)), this, SLOT(on_lineEditDirectoryName_textChanged(QString)));
}

void XScanSortWidget::populateFlags()
{
    ui->comboBoxFlags->addItem("All", 0);
    ui->comboBoxFlags->addItem("Deep Scan", 1);
    ui->comboBoxFlags->addItem("Heuristic Scan", 2);
    ui->comboBoxFlags->addItem("Recursive Scan", 4);
    ui->comboBoxFlags->addItem("Resources Scan", 8);
    ui->comboBoxFlags->addItem("Archives Scan", 16);
    ui->comboBoxFlags->addItem("Overlay Scan", 32);
    ui->comboBoxFlags->addItem("Aggressive Scan", 64);
}

void XScanSortWidget::populateFileTypes()
{
    ui->comboBoxFileType->addItem("All", -1);
    ui->comboBoxFileType->addItem("PE", 1);
    ui->comboBoxFileType->addItem("ELF", 2);
    ui->comboBoxFileType->addItem("MACH-O", 3);
    ui->comboBoxFileType->addItem("MS-DOS", 4);
    ui->comboBoxFileType->addItem("Binary", 5);
    ui->comboBoxFileType->addItem("Archive", 6);
    ui->comboBoxFileType->addItem("Image", 7);
    ui->comboBoxFileType->addItem("Document", 8);
}

void XScanSortWidget::populateTypes()
{
    ui->comboBoxType->addItem("All", -1);
    ui->comboBoxType->addItem("Compiler", 1);
    ui->comboBoxType->addItem("Packer", 2);
    ui->comboBoxType->addItem("Protector", 3);
    ui->comboBoxType->addItem("Library", 4);
    ui->comboBoxType->addItem("Driver", 5);
    ui->comboBoxType->addItem("Firmware", 6);
    ui->comboBoxType->addItem("Executable", 7);
    ui->comboBoxType->addItem("Script", 8);
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
    startScan();
}

void XScanSortWidget::on_pushButtonResult_clicked()
{
    QString sFileName = QFileDialog::getSaveFileName(this, tr("Save Result"), ui->lineEditResult->text(),
                                                      tr("All Files (*.*);;JSON (*.json);;XML (*.xml);;CSV (*.csv);;TSV (*.tsv)"));

    if (!sFileName.isEmpty()) {
        ui->lineEditResult->setText(sFileName);

        QString sResult;
        if (sFileName.endsWith(".json", Qt::CaseInsensitive)) {
            sResult = m_pModel->toJSON();
        } else if (sFileName.endsWith(".xml", Qt::CaseInsensitive)) {
            sResult = m_pModel->toXML();
        } else if (sFileName.endsWith(".csv", Qt::CaseInsensitive)) {
            sResult = m_pModel->toCSV();
        } else if (sFileName.endsWith(".tsv", Qt::CaseInsensitive)) {
            sResult = m_pModel->toTSV();
        } else {
            sResult = m_pModel->toFormattedString();
        }

        QFile file(sFileName);
        if (file.open(QIODevice::WriteOnly)) {
            file.write(sResult.toUtf8());
            file.close();
        }
    }
}

void XScanSortWidget::on_checkBoxAllFileTypes_toggled(bool bChecked)
{
    ui->comboBoxFileType->setEnabled(!bChecked);
    updateFilter();
}

void XScanSortWidget::on_checkBoxAllTypes_toggled(bool bChecked)
{
    ui->comboBoxType->setEnabled(!bChecked);
    updateFilter();
}

void XScanSortWidget::on_comboBoxFileType_currentIndexChanged(int nIndex)
{
    Q_UNUSED(nIndex)
    updateFilter();
}

void XScanSortWidget::on_comboBoxType_currentIndexChanged(int nIndex)
{
    Q_UNUSED(nIndex)
    updateFilter();
}

void XScanSortWidget::on_comboBoxFlags_currentIndexChanged(int nIndex)
{
    quint64 nFlags = ui->comboBoxFlags->itemData(nIndex).toULongLong();
    XScanEngine::setScanFlags(m_pScanOptions, nFlags);
}

void XScanSortWidget::on_lineEditDirectoryName_textChanged(const QString &sText)
{
    ui->pushButtonScan->setEnabled(!sText.isEmpty() && !m_bIsScanning);
}

void XScanSortWidget::updateFilter()
{
    m_pScanOptions->bFilterAllFileTypes = ui->checkBoxAllFileTypes->isChecked();
    m_pScanOptions->bFilterAllTypes = ui->checkBoxAllTypes->isChecked();

    m_pProxyModel->invalidate();
}

QString XScanSortWidget::_getCurrentFileType()
{
    int nIndex = ui->comboBoxFileType->currentIndex();
    if (nIndex >= 0) {
        return ui->comboBoxFileType->currentText();
    }
    return "All";
}

QString XScanSortWidget::_getCurrentType()
{
    int nIndex = ui->comboBoxType->currentIndex();
    if (nIndex >= 0) {
        return ui->comboBoxType->currentText();
    }
    return "All";
}

void XScanSortWidget::startScan()
{
    QString sDirectoryName = ui->lineEditDirectoryName->text();

    if (sDirectoryName.isEmpty()) {
        QMessageBox::warning(this, tr("Warning"), tr("Please select a directory."));
        return;
    }

    QDir dir(sDirectoryName);
    if (!dir.exists()) {
        QMessageBox::warning(this, tr("Warning"), tr("Directory does not exist."));
        return;
    }

    m_bIsScanning = true;
    ui->pushButtonScan->setEnabled(false);

    // Create PDSTRUCT for progress tracking
    XBinary::PDSTRUCT pdStruct = XBinary::createPdStruct();

    // Create SCAN_RESULT to hold scanning results
    XScanEngine::SCAN_RESULT scanResult = {};

    // Note: XScanEngine is abstract and cannot be instantiated directly.
    // You need to use a concrete implementation like SpecAbstract
    // For now, this is a placeholder that shows the proper structure.
    // TODO: Replace with actual scanning implementation using a concrete scan engine

    // If scanning results were obtained, populate the model
    if (scanResult.listRecords.count() > 0) {
        // Populate the model with results
        ScanItem *pRoot = m_pModel->rootItem();

        for (qint32 i = 0; i < scanResult.listRecords.count(); ++i) {
            const XScanEngine::SCANSTRUCT &scanStruct = scanResult.listRecords.at(i);
            ScanItem *pItem = new ScanItem(XScanEngine::createResultStringEx(m_pScanOptions, &scanStruct), pRoot, 1);
            pItem->setScanStruct(scanStruct);
            pRoot->appendChild(pItem);
        }
    }

    m_bIsScanning = false;
    ui->pushButtonScan->setEnabled(true);

    scanFinished();
}

void XScanSortWidget::scanFinished()
{
    // Update status or show completion message
}

void XScanSortWidget::setOptions(XScanEngine::SCAN_OPTIONS *pOptions)
{
    if (m_pScanOptions) {
        delete m_pScanOptions;
    }
    m_pScanOptions = pOptions;
}

XScanEngine::SCAN_OPTIONS *XScanSortWidget::getOptions()
{
    return m_pScanOptions;
}
