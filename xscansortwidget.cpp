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

    m_sortOptions.setName("collections");
}

XScanSortWidget::~XScanSortWidget()
{
    delete ui;
}

void XScanSortWidget::adjustView()
{

}

void XScanSortWidget::setGlobal(XShortcuts *pShortcuts, XOptions *pXOptions)
{
    if (pXOptions) {
        QString sDirPath = pXOptions->getValue(XOptions::ID_SCAN_DIRECTORY_PATH).toString();
        ui->lineEditDirectoryName->setText(QDir().toNativeSeparators(sDirPath));
    }

    XShortcutsWidget::setGlobal(pShortcuts, pXOptions);
}

void XScanSortWidget::setEngine(XScanEngine *pScanEngine)
{
    m_pScanEngine = pScanEngine;
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
    //startScan();
}
