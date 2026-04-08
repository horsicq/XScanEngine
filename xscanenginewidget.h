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
#ifndef XSCANENGINEWIDGET_H
#define XSCANENGINEWIDGET_H

#include <QClipboard>
#include <QDesktopServices>
#include <QFutureWatcher>
#include <QMenu>
#include <QWidget>
#include <QtConcurrent>
#include "xscanengine.h"

#include "xshortcutswidget.h"

namespace Ui {
class XScanEngineWidget;
}

class XScanEngineWidget : public XShortcutsWidget {
    Q_OBJECT

public:
    enum ST {
        ST_UNKNOWN = 0,
        ST_FILE
    };

    enum COLUMN {
        COLUMN_STRING = 0,
        COLUMN_SIGNATURE,
        COLUMN_INFO
    };

    explicit XScanEngineWidget(QWidget *pParent = nullptr);
    ~XScanEngineWidget();

    void setData(const QString &sFileName, bool bScan = false, XBinary::FT fileType = XBinary::FT_UNKNOWN);
    virtual void adjustView();
    void setGlobal(XShortcuts *pShortcuts, XOptions *pXOptions);
    virtual void reloadData(bool bSaveSelection);

private slots:
    void clear();
    void process();
    void scan();
    void stop();
    void onScanFinished();
    // void on_pushButtonDieSignatures_clicked();
    // void on_pushButtonDieExtraInformation_clicked();
    // void on_pushButtonDieLog_clicked();
    // void showInfo(const QString &sName);
    // void showSignature(XBinary::FT fileType, const QString &sName);
    // void enableControls(bool bState);
    // QString getInfoFileName(const QString &sName);
    // void copyResult();
    // void on_pushButtonDieScanDirectory_clicked();
    // void on_toolButtonElapsedTime_clicked();
    // void on_treeViewResult_clicked(const QModelIndex &index);
    // void on_treeViewResult_customContextMenuRequested(const QPoint &pos);
    // void timerSlot();
    void timerSlot();
    // void on_pushButtonDieScanStart_clicked();
    // void on_pushButtonDieScanStop_clicked();
    // void handleErrorString(const QString &sErrorString);
    // void handleWarningString(const QString &sWarningString);

protected:
    virtual void registerShortcuts(bool bState);

signals:
    void scanStarted();
    void scanFinished();
    void currentFileType(qint32 nFT);
    void scanProgress(int value);

private:
    Ui::XScanEngineWidget *ui;
    ST m_scanType;
    // DiE_Script m_dieScript;
    XScanEngine::SCAN_OPTIONS m_scanOptions;
    XScanEngine::SCAN_RESULT m_scanResult;
    QFutureWatcher<void> m_watcher;
    QString m_sFileName;
    XBinary::FT m_fileType;
    bool m_bProcess;
    QString m_sInfoPath;
    XBinary::PDSTRUCT m_pdStruct;
    QTimer *m_pTimer;
    bool m_bInitDatabase;
    // ScanItemModel *m_pModel;
    QList<QString> m_listErrorsAndWarnings;
};

#endif  // XSCANENGINEWIDGET_H
