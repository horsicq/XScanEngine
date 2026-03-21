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
#ifndef XSCANSORTWIDGET_H
#define XSCANSORTWIDGET_H

#include <QWidget>
#include <QTableView>
#include <QSortFilterProxyModel>
#include <QFileDialog>
#include <QMessageBox>
#include <QStandardItemModel>
#include "xscanengine.h"
#include "scanitemmodel.h"

namespace Ui {
class XScanSortWidget;
}

class XScanSortWidget : public QWidget {
    Q_OBJECT

public:
    explicit XScanSortWidget(QWidget *pParent = nullptr);
    ~XScanSortWidget();

    void setOptions(XScanEngine::SCAN_OPTIONS *pOptions);
    XScanEngine::SCAN_OPTIONS *getOptions();

private slots:
    void on_pushButtonOpenDirectory_clicked();
    void on_pushButtonScan_clicked();
    void on_pushButtonResult_clicked();
    void on_checkBoxAllFileTypes_toggled(bool bChecked);
    void on_checkBoxAllTypes_toggled(bool bChecked);
    void on_comboBoxFileType_currentIndexChanged(int nIndex);
    void on_comboBoxType_currentIndexChanged(int nIndex);
    void on_comboBoxFlags_currentIndexChanged(int nIndex);
    void on_lineEditDirectoryName_textChanged(const QString &sText);
    void scanFinished();

private:
    void setupConnections();
    void populateFileTypes();
    void populateTypes();
    void populateFlags();
    void updateFilter();
    void startScan();
    QString _getCurrentFileType();
    QString _getCurrentType();

private:
    Ui::XScanSortWidget *ui;
    XScanEngine::SCAN_OPTIONS *m_pScanOptions;
    ScanItemModel *m_pModel;
    QSortFilterProxyModel *m_pProxyModel;
    QThread *m_pScanThread;
    bool m_bIsScanning;
};

#endif  // XSCANSORTWIDGET_H
