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

#include <QDir>
#include <QLineEdit>
#include <QVariant>

namespace {
QString getOptionString(XOptions *pOptions, XOptions::ID id, const QString &sDefaultValue)
{
    QString sResult = sDefaultValue;

    if (pOptions && pOptions->isIDPresent(id)) {
        QString sValue = pOptions->getValue(id).toString();

        if (!sValue.isEmpty()) {
            sResult = sValue;
        }
    }

    return sResult;
}

bool getOptionBool(XOptions *pOptions, XOptions::ID id, bool bDefaultValue)
{
    bool bResult = bDefaultValue;

    if (pOptions && pOptions->isIDPresent(id)) {
        bResult = pOptions->getValue(id).toBool();
    }

    return bResult;
}

QVariant getOptionValue(XOptions *pOptions, XOptions::ID id, const QVariant &varDefaultValue)
{
    QVariant result = varDefaultValue;

    if (pOptions && pOptions->isIDPresent(id)) {
        QVariant varValue = pOptions->getValue(id);

        if (varValue.isValid()) {
            result = varValue;
        }
    }

    return result;
}

void setDatabaseControlsVisible(Ui::XScanSortWidget *pUi, bool bMain, bool bExtra, bool bCustom)
{
    pUi->checkBoxDatabaseMain->setVisible(bMain);
    pUi->lineEditDatabaseMain->setVisible(bMain);
    pUi->pushButtonDatabaseMain->setVisible(bMain);

    pUi->checkBoxDatabaseExtra->setVisible(bExtra);
    pUi->lineEditDatabaseExtra->setVisible(bExtra);
    pUi->pushButtonDatabaseExtra->setVisible(bExtra);

    pUi->checkBoxDatabaseCustom->setVisible(bCustom);
    pUi->lineEditDatabaseCustom->setVisible(bCustom);
    pUi->pushButtonDatabaseCustom->setVisible(bCustom);
}

void selectDatabaseDirectory(QWidget *pParent, QLineEdit *pLineEdit, const QString &sCaption)
{
    QString sInitDirectory = XOptions::convertPathName(pLineEdit->text());
    QString sDirectoryName = QFileDialog::getExistingDirectory(pParent, sCaption, sInitDirectory, QFileDialog::ShowDirsOnly);

    if (!sDirectoryName.isEmpty()) {
        pLineEdit->setText(QDir().toNativeSeparators(sDirectoryName));
    }
}
}  // namespace

XScanSortWidget::XScanSortWidget(QWidget *pParent)
    : XShortcutsWidget(pParent), ui(new Ui::XScanSortWidget)
{
    ui->setupUi(this);

    m_pScanEngine = nullptr;
    m_engineType = XScanEngine::SCANENGINETYPE_UNKNOWN;
    m_scanOptions = {};
}

XScanSortWidget::~XScanSortWidget()
{
    XScanEngine::setScanFlagsToGlobalOptions(&m_sortOptions, ui->comboBoxFlags->getValue().toULongLong());
    m_sortOptions.setValue(XOptions::ID_SCAN_DIRECTORY_PATH, ui->lineEditDirectoryName->text());
    m_sortOptions.setValue(XOptions::ID_SCAN_SUBDIRECTORIES, ui->checkBoxScanSubdirectories->isChecked());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_ALLTYPES, ui->checkBoxAllTypes->isChecked());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_ALLFILETYPES, ui->checkBoxAllFileTypes->isChecked());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_FILETYPES, ui->comboBoxFileType->getCustomFlagAsString());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_TYPES, ui->comboBoxType->getCustomFlagAsString());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_CATALOG_ENABLED, ui->groupBoxCatalog->isChecked());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_COPY_ENABLED, ui->groupBoxCopy->isChecked());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_CATALOG_FORMAT, ui->lineEditCatalogFormat->text());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_COPY_FORMAT, ui->lineEditCopyFormat->text());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_COPY_REMOVE, ui->checkBoxCopyRemove->isChecked());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_COPY_MOVETOFIRST, ui->checkBoxCopyMoveToFirst->isChecked());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_RESULT_PATH, ui->lineEditResult->text());
    m_sortOptions.setValue(XOptions::ID_SCAN_COLLECTION_LOG, ui->checkBoxScanLog->isChecked());
    m_sortOptions.getComboBox(ui->comboBoxReadBufferSize, XOptions::ID_SCAN_COLLECTION_FEATURE_READBUFFERSIZE);
    m_sortOptions.getComboBox(ui->comboBoxFileBufferSize, XOptions::ID_SCAN_COLLECTION_FEATURE_FILEBUFFERSIZE);
    m_sortOptions.getCheckBox(ui->checkBoxSSE2, XOptions::ID_SCAN_COLLECTION_FEATURE_SSE2);
    m_sortOptions.getCheckBox(ui->checkBoxAVX2, XOptions::ID_SCAN_COLLECTION_FEATURE_AVX2);

    if (m_pScanEngine) {
        if (m_engineType == XScanEngine::SCANENGINETYPE_DIE) {
            m_sortOptions.setValue(XOptions::ID_SCAN_DIE_DATABASE_MAIN_PATH, ui->lineEditDatabaseMain->text());
            m_sortOptions.setValue(XOptions::ID_SCAN_DIE_DATABASE_EXTRA_PATH, ui->lineEditDatabaseExtra->text());
            m_sortOptions.setValue(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH, ui->lineEditDatabaseCustom->text());
            m_sortOptions.setValue(XOptions::ID_SCAN_DIE_DATABASE_EXTRA_ENABLED, ui->checkBoxDatabaseExtra->isChecked());
            m_sortOptions.setValue(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_ENABLED, ui->checkBoxDatabaseCustom->isChecked());
        } else if (m_engineType == XScanEngine::SCANENGINETYPE_PEID) {
            m_sortOptions.setValue(XOptions::ID_SCAN_PEID_DATABASE_PATH, ui->lineEditDatabaseMain->text());
        } else if (m_engineType == XScanEngine::SCANENGINETYPE_YARA) {
            m_sortOptions.setValue(XOptions::ID_SCAN_YARA_DATABASE_PATH, ui->lineEditDatabaseMain->text());
        }
    }

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

    if (!m_pScanEngine) {
        ui->groupBoxDatabases->hide();
        return;
    }

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
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_FILETYPES, "");
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_TYPES, "");
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_CATALOG_ENABLED, false);
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_CATALOG_FORMAT, "{ft}.{type}.{name}.{version}.{info}.txt");
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_COPY_ENABLED, false);
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_COPY_FORMAT, "{ft}/{type}/{name}({version})[{info}]/{md5}_{original_filename}");
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_COPY_REMOVE, false);
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_COPY_MOVETOFIRST, false);
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_RESULT_PATH, "collection");
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_LOG, false);

    XOptions *pGlobalOptions = getGlobalOptions();
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_FEATURE_READBUFFERSIZE,
                        getOptionValue(pGlobalOptions, XOptions::ID_FEATURE_READBUFFERSIZE, 4 * 1024));
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_FEATURE_FILEBUFFERSIZE,
                        getOptionValue(pGlobalOptions, XOptions::ID_FEATURE_FILEBUFFERSIZE, 64 * 1024 * 1024));
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_FEATURE_SSE2, getOptionValue(pGlobalOptions, XOptions::ID_FEATURE_SSE2, true));
    m_sortOptions.addID(XOptions::ID_SCAN_COLLECTION_FEATURE_AVX2, getOptionValue(pGlobalOptions, XOptions::ID_FEATURE_AVX2, true));

    m_engineType = pScanEngine->getEngineType();

    if (m_engineType == XScanEngine::SCANENGINETYPE_DIE) {
        m_sortOptions.addID(XOptions::ID_SCAN_DIE_DATABASE_MAIN_PATH, getOptionString(pGlobalOptions, XOptions::ID_SCAN_DIE_DATABASE_MAIN_PATH, "$data/db"));
        m_sortOptions.addID(XOptions::ID_SCAN_DIE_DATABASE_EXTRA_PATH, getOptionString(pGlobalOptions, XOptions::ID_SCAN_DIE_DATABASE_EXTRA_PATH, "$data/db_extra"));
        m_sortOptions.addID(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH, getOptionString(pGlobalOptions, XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH, "$data/db_custom"));
        m_sortOptions.addID(XOptions::ID_SCAN_DIE_DATABASE_EXTRA_ENABLED, getOptionBool(pGlobalOptions, XOptions::ID_SCAN_DIE_DATABASE_EXTRA_ENABLED, true));
        m_sortOptions.addID(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_ENABLED, getOptionBool(pGlobalOptions, XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_ENABLED, true));
    } else if (m_engineType == XScanEngine::SCANENGINETYPE_PEID) {
        m_sortOptions.addID(XOptions::ID_SCAN_PEID_DATABASE_PATH, getOptionString(pGlobalOptions, XOptions::ID_SCAN_PEID_DATABASE_PATH, "$data/peid"));
    } else if (m_engineType == XScanEngine::SCANENGINETYPE_YARA) {
        m_sortOptions.addID(XOptions::ID_SCAN_YARA_DATABASE_PATH, getOptionString(pGlobalOptions, XOptions::ID_SCAN_YARA_DATABASE_PATH, "$data/yara"));
    }

    m_sortOptions.load();

    ui->comboBoxFlags->setData(XScanEngine::getScanFlags(), XComboBoxEx::CBTYPE_FLAGS, 0, tr("Flags"));

    {
        QList<XComboBoxEx::CUSTOM_FLAG> listCustomFlags;

        QSetIterator<XBinary::FT> i(pScanEngine->getFileTypesSupported());
        while (i.hasNext()) {
            XBinary::FT fileType = i.next();
            XComboBoxEx::CUSTOM_FLAG customFlag = {};
            customFlag.value = XBinary::fileTypeIdToFtString(fileType);
            customFlag.sString = XBinary::fileTypeIdToString(fileType);
            customFlag.bIsChecked = false;
            customFlag.bIsReadOnly = false;

            listCustomFlags.append(customFlag);

            std::stable_sort(listCustomFlags.begin(), listCustomFlags.end(), XComboBoxEx::sortCustomFlagByValue);

            ui->comboBoxFileType->addCustomFlags("", listCustomFlags);
        }

        ui->comboBoxFileType->setCustomFlagsFromString(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_FILETYPES).toString());
    }

    {
        QList<XComboBoxEx::CUSTOM_FLAG> listCustomFlags;

        QSetIterator<XScanEngine::RECORD_TYPE> i(pScanEngine->getTypesSupported());
        while (i.hasNext()) {
            XScanEngine::RECORD_TYPE recordType = i.next();
            XComboBoxEx::CUSTOM_FLAG customFlag = {};
            customFlag.value = XScanEngine::recordTypeIdToFtString(recordType);
            customFlag.sString = XScanEngine::recordTypeIdToString(recordType);
            customFlag.bIsChecked = false;
            customFlag.bIsReadOnly = false;

            listCustomFlags.append(customFlag);

            std::stable_sort(listCustomFlags.begin(), listCustomFlags.end(), XComboBoxEx::sortCustomFlagByValue);

            ui->comboBoxType->addCustomFlags("", listCustomFlags);
        }

        ui->comboBoxType->setCustomFlagsFromString(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_TYPES).toString());
    }

    ui->comboBoxFlags->setValue(XScanEngine::getScanFlagsFromGlobalOptions(&m_sortOptions));

    QString sDirectoryName = m_sortOptions.getValue(XOptions::ID_SCAN_DIRECTORY_PATH).toString();
    if (!sDirectoryName.isEmpty()) {
        ui->lineEditDirectoryName->setText(QDir().toNativeSeparators(sDirectoryName));
    }

    ui->checkBoxScanSubdirectories->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_SUBDIRECTORIES).toBool());

    ui->checkBoxAllFileTypes->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_ALLFILETYPES).toBool());
    ui->checkBoxAllTypes->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_ALLTYPES).toBool());
    ui->comboBoxFileType->setValue(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_FILETYPES));
    ui->comboBoxType->setValue(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_TYPES));

    ui->groupBoxCatalog->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_CATALOG_ENABLED).toBool());
    ui->groupBoxCopy->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_COPY_ENABLED).toBool());
    ui->lineEditCatalogFormat->setText(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_CATALOG_FORMAT).toString());
    ui->lineEditCopyFormat->setText(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_COPY_FORMAT).toString());
    ui->checkBoxCopyRemove->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_COPY_REMOVE).toBool());
    ui->checkBoxCopyMoveToFirst->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_COPY_MOVETOFIRST).toBool());

    ui->lineEditResult->setText(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_RESULT_PATH).toString());
    ui->checkBoxScanLog->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_COLLECTION_LOG).toBool());
    m_sortOptions.setComboBox(ui->comboBoxReadBufferSize, XOptions::ID_SCAN_COLLECTION_FEATURE_READBUFFERSIZE);
    m_sortOptions.setComboBox(ui->comboBoxFileBufferSize, XOptions::ID_SCAN_COLLECTION_FEATURE_FILEBUFFERSIZE);
    m_sortOptions.setCheckBox(ui->checkBoxSSE2, XOptions::ID_SCAN_COLLECTION_FEATURE_SSE2);
    m_sortOptions.setCheckBox(ui->checkBoxAVX2, XOptions::ID_SCAN_COLLECTION_FEATURE_AVX2);
#ifdef USE_XSIMD
    if (!xsimd_is_sse2_present()) {
        ui->checkBoxSSE2->hide();
    }

    if (!xsimd_is_avx2_present()) {
        ui->checkBoxAVX2->hide();
    }
#endif

    if (m_engineType == XScanEngine::SCANENGINETYPE_DIE) {
        ui->groupBoxDatabases->show();
        setDatabaseControlsVisible(ui, true, true, true);

        ui->lineEditDatabaseMain->setText(m_sortOptions.getValue(XOptions::ID_SCAN_DIE_DATABASE_MAIN_PATH).toString());
        ui->lineEditDatabaseExtra->setText(m_sortOptions.getValue(XOptions::ID_SCAN_DIE_DATABASE_EXTRA_PATH).toString());
        ui->lineEditDatabaseCustom->setText(m_sortOptions.getValue(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH).toString());
        ui->checkBoxDatabaseMain->setChecked(true);
        ui->checkBoxDatabaseExtra->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_DIE_DATABASE_EXTRA_ENABLED).toBool());
        ui->checkBoxDatabaseCustom->setChecked(m_sortOptions.getValue(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_ENABLED).toBool());
    } else if (m_engineType == XScanEngine::SCANENGINETYPE_PEID) {
        ui->groupBoxDatabases->show();
        setDatabaseControlsVisible(ui, true, false, false);
        ui->lineEditDatabaseMain->setText(m_sortOptions.getValue(XOptions::ID_SCAN_PEID_DATABASE_PATH).toString());
        ui->checkBoxDatabaseMain->setChecked(true);
    } else if (m_engineType == XScanEngine::SCANENGINETYPE_YARA) {
        ui->groupBoxDatabases->show();
        setDatabaseControlsVisible(ui, true, false, false);
        ui->lineEditDatabaseMain->setText(m_sortOptions.getValue(XOptions::ID_SCAN_YARA_DATABASE_PATH).toString());
        ui->checkBoxDatabaseMain->setChecked(true);
    } else {
        ui->groupBoxDatabases->hide();
    }

    ui->checkBoxDatabaseMain->setEnabled(false);

    on_checkBoxAllFileTypes_stateChanged(ui->checkBoxAllFileTypes->checkState());
    on_checkBoxAllTypes_stateChanged(ui->checkBoxAllTypes->checkState());
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

    if (sDirectory.isEmpty()) {
        QMessageBox::warning(this, tr("Warning"), tr("Please select a directory"));
        return;
    }

    if (!QDir(sDirectory).exists()) {
        QMessageBox::critical(this, tr("Error"), tr("Directory does not exist"));
        return;
    }

    m_scanOptions = {};
    m_scanOptions.bShowType = true;
    m_scanOptions.bShowVersion = true;
    m_scanOptions.bShowInfo = true;
    m_scanOptions.bSubdirectories = ui->checkBoxScanSubdirectories->isChecked();
    m_scanOptions.bCollection = true;
    m_scanOptions.bCollectionAllFileTypes = ui->checkBoxAllFileTypes->isChecked();
    m_scanOptions.bCollectionAllTypes = ui->checkBoxAllTypes->isChecked();
    m_scanOptions.bCollectionCopyFiles = ui->groupBoxCopy->isChecked();
    m_scanOptions.bCollectionCopyRemove = ui->checkBoxCopyRemove->isChecked();
    m_scanOptions.bCollectionCopyMoveToFirst = ui->checkBoxCopyMoveToFirst->isChecked();
    m_scanOptions.sCollectionCopyFormat = ui->lineEditCopyFormat->text();
    m_scanOptions.bCollectionCreateCatalog = ui->groupBoxCatalog->isChecked();
    m_scanOptions.sCollectionCatalogFormat = ui->lineEditCatalogFormat->text();
    m_scanOptions.sCollectionResultDirectory = ui->lineEditResult->text();
    m_scanOptions.bCollectionLog = ui->checkBoxScanLog->isChecked();
    XScanEngine::setScanFlags(&m_scanOptions, ui->comboBoxFlags->getValue().toULongLong());

    if (!m_scanOptions.bCollectionAllFileTypes) {
        QString sFileTypes = ui->comboBoxFileType->getCustomFlagAsString();

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        QList<QString> listFileTypes = sFileTypes.split("|", Qt::SkipEmptyParts);
#else
        QList<QString> listFileTypes = sFileTypes.split("|", QString::SkipEmptyParts);
#endif

        qint32 nNumberOfFileTypes = listFileTypes.count();
        for (qint32 nI = 0; nI < nNumberOfFileTypes; nI++) {
            QString sFileType = listFileTypes.at(nI).trimmed();
            XBinary::FT fileType = XBinary::ftStringToFileTypeId(sFileType);

            if (fileType != XBinary::FT_UNKNOWN) {
                m_scanOptions.stCollectionFileTypes.insert(fileType);
            }
        }
    }

    if (m_pScanEngine && m_pScanEngine->isDatabaseUsing()) {
        if (m_engineType == XScanEngine::SCANENGINETYPE_DIE) {
            m_scanOptions.sMainDatabasePath = ui->lineEditDatabaseMain->text();
            m_scanOptions.sExtraDatabasePath = ui->lineEditDatabaseExtra->text();
            m_scanOptions.sCustomDatabasePath = ui->lineEditDatabaseCustom->text();
            m_scanOptions.bUseExtraDatabase = ui->checkBoxDatabaseExtra->isChecked();
            m_scanOptions.bUseCustomDatabase = ui->checkBoxDatabaseCustom->isChecked();
        } else if (m_engineType == XScanEngine::SCANENGINETYPE_PEID) {
            m_scanOptions.sMainDatabasePath = ui->lineEditDatabaseMain->text();
        } else if (m_engineType == XScanEngine::SCANENGINETYPE_YARA) {
            m_scanOptions.sMainDatabasePath = ui->lineEditDatabaseMain->text();
        }

        m_pScanEngine->loadDatabase(&m_scanOptions, nullptr);
    }

    XScanEngineProcess scanEngineProcess(m_pScanEngine);

    XDialogProcess ds(this, &scanEngineProcess);
    ds.setGlobal(getShortcuts(), getGlobalOptions());
    XBinary::PDSTRUCT *pPdStruct = ds.getPdStruct();
    pPdStruct->nBufferSize = ui->comboBoxReadBufferSize->currentData().toInt();
    pPdStruct->nFileBufferSize = ui->comboBoxFileBufferSize->currentData().toInt();
    scanEngineProcess.setData(sDirectory, &m_scanOptions, pPdStruct);
#ifdef USE_XSIMD
    qint32 nOldSSE2 = xsimd_is_sse2_enabled();
    qint32 nOldAVX2 = xsimd_is_avx2_enabled();

    if (xsimd_is_sse2_present()) {
        xsimd_set_sse2(ui->checkBoxSSE2->isChecked());
    }

    if (xsimd_is_avx2_present()) {
        xsimd_set_avx2(ui->checkBoxAVX2->isChecked());
    }
#endif
    ds.start();
    ds.exec();
#ifdef USE_XSIMD
    if (xsimd_is_sse2_present()) {
        xsimd_set_sse2(nOldSSE2);
    }

    if (xsimd_is_avx2_present()) {
        xsimd_set_avx2(nOldAVX2);
    }
#endif
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

void XScanSortWidget::on_pushButtonDatabaseMain_clicked()
{
    selectDatabaseDirectory(this, ui->lineEditDatabaseMain, tr("Open directory") + "...");
}

void XScanSortWidget::on_pushButtonDatabaseExtra_clicked()
{
    selectDatabaseDirectory(this, ui->lineEditDatabaseExtra, tr("Open directory") + "...");
}

void XScanSortWidget::on_pushButtonDatabaseCustom_clicked()
{
    selectDatabaseDirectory(this, ui->lineEditDatabaseCustom, tr("Open directory") + "...");
}

void XScanSortWidget::on_checkBoxSSE2_toggled(bool bChecked)
{
#ifdef USE_XSIMD
    if (bChecked && (!xsimd_is_sse2_present())) {
        ui->checkBoxSSE2->setChecked(false);
    }
#else
    Q_UNUSED(bChecked)
#endif
}

void XScanSortWidget::on_checkBoxAVX2_toggled(bool bChecked)
{
#ifdef USE_XSIMD
    if (bChecked && (!xsimd_is_avx2_present())) {
        ui->checkBoxAVX2->setChecked(false);
    }
#else
    Q_UNUSED(bChecked)
#endif
}
