/* Copyright (c) 2018-2026 hors<horsicq@gmail.com>
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
#ifndef DIALOGXSCANENGINEDIRECTORY_H
#define DIALOGXSCANENGINEDIRECTORY_H

#include "xshortcutsdialog.h"
#include "xdialogprocess.h"
#include "scanitemmodel.h"
#include "die_script.h"

namespace Ui {
class DialogXScanEngineDirectory;
}

class DialogXScanEngineDirectory : public XShortcutsDialog {
    Q_OBJECT

public:
    explicit DialogXScanEngineDirectory(QWidget *pParent, const QString &sDirName);
    ~DialogXScanEngineDirectory();

    virtual void adjustView();

private slots:
    void on_pushButtonOpenDirectory_clicked();
    void on_pushButtonScan_clicked();
    void scanDirectory(const QString &sDirectoryName);
    void scanResult(const XScanEngine::SCAN_RESULT &scanResult);
    void appendResult(const QString &sResult);
    void on_pushButtonOK_clicked();
    void on_pushButtonClear_clicked();
    void on_pushButtonSave_clicked();

signals:
    void resultSignal(const QString &sText);

protected:
    virtual void registerShortcuts(bool bState);

private:
    Ui::DialogXScanEngineDirectory *ui;
    XScanEngine::SCAN_OPTIONS m_scanOptions;
};

#endif  // DIALOGXSCANENGINEDIRECTORY_H
