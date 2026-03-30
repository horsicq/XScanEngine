/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
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
#include "dialogxscanengineelapsed.h"
#include "ui_dialogxscanengineelapsed.h"

DialogXScanEngineElapsed::DialogXScanEngineElapsed(QWidget *pParent) : XShortcutsDialog(pParent, true), ui(new Ui::DialogXScanEngineElapsed)
{
    m_pScanResult = nullptr;
    ui->setupUi(this);
}

DialogXScanEngineElapsed::~DialogXScanEngineElapsed()
{
    delete ui;
}

void DialogXScanEngineElapsed::adjustView()
{
}

void DialogXScanEngineElapsed::setData(XScanEngine::SCAN_RESULT *pScanResult)
{
    m_pScanResult = pScanResult;

    qint32 nNumberOfRecords = pScanResult->listDebugRecords.count();

    ui->tableWidgetResult->setColumnCount(2);
    ui->tableWidgetResult->setRowCount(nNumberOfRecords);

    QStringList listHeaders;
    listHeaders.append(tr("Time"));
    listHeaders.append(tr("Script"));
    ui->tableWidgetResult->setHorizontalHeaderLabels(listHeaders);

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        QTableWidgetItem *pItemTime = new QTableWidgetItem;
        pItemTime->setData(Qt::DisplayRole, pScanResult->listDebugRecords.at(i).nElapsedTime);
        pItemTime->setTextAlignment(Qt::AlignRight);
        ui->tableWidgetResult->setItem(i, 0, pItemTime);

        QTableWidgetItem *pItemScript = new QTableWidgetItem;
        pItemScript->setText(pScanResult->listDebugRecords.at(i).sScript);
        pItemScript->setTextAlignment(Qt::AlignLeft);
        ui->tableWidgetResult->setItem(i, 1, pItemScript);
    }

    ui->tableWidgetResult->setColumnWidth(0, 60);
    ui->tableWidgetResult->setColumnWidth(1, 120);
    ui->tableWidgetResult->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tableWidgetResult->horizontalHeader()->setVisible(true);
}

void DialogXScanEngineElapsed::on_pushButtonOK_clicked()
{
    this->close();
}

void DialogXScanEngineElapsed::registerShortcuts(bool bState)
{
    Q_UNUSED(bState)
}
