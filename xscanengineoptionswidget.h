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
#ifndef XSCANENGINEOPTIONSWIDGET_H
#define XSCANENGINEOPTIONSWIDGET_H

#include "xshortcutswidget.h"
#include "xbinary.h"
#include "dialogviewcolors.h"

namespace Ui {
class XScanEngineOptionsWidget;
}

class XScanEngineOptionsWidget : public XShortcutsWidget {
    Q_OBJECT

public:
    explicit XScanEngineOptionsWidget(QWidget *pParent = nullptr);
    ~XScanEngineOptionsWidget();

    virtual void adjustView();

    void setOptions(XOptions *pOptions);

    static void setDefaultValues(XOptions *pOptions);
    static QList<DialogViewColors::RECORD> getRecords();
    virtual void reloadData(bool bSaveSelection);

public slots:
    void save();
    void reload();

private slots:
    void on_toolButtonDIEDatabase_clicked();
    void on_toolButtonDIEDatabaseExtra_clicked();
    void on_toolButtonDIEDatabaseCustom_clicked();
    void on_toolButtonYaraRules_clicked();
    void on_toolButtonPeidDatabase_clicked();
    void on_pushButtonScanColors_clicked();

protected:
    virtual void registerShortcuts(bool bState);

private:
    Ui::XScanEngineOptionsWidget *ui;
    XOptions *m_pOptions;
    bool m_bIsNetPresent;
};

#endif  // XSCANENGINEOPTIONSWIDGET_H
