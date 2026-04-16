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
#include "xscanengineoptionswidget.h"

#include "ui_xscanengineoptionswidget.h"

XScanEngineOptionsWidget::XScanEngineOptionsWidget(QWidget *pParent) : XShortcutsWidget(pParent), ui(new Ui::XScanEngineOptionsWidget)
{
    ui->setupUi(this);
}

XScanEngineOptionsWidget::~XScanEngineOptionsWidget()
{
    delete ui;
}

void XScanEngineOptionsWidget::adjustView()
{
    // TODO
}

void XScanEngineOptionsWidget::setOptions(XOptions *pOptions)
{
    m_pOptions = pOptions;

    reload();
}

void XScanEngineOptionsWidget::save()
{
    m_pOptions->getCheckBox(ui->checkBoxDeepScan, XOptions::ID_SCAN_FLAG_DEEP);
    m_pOptions->getCheckBox(ui->checkBoxScanAfterOpen, XOptions::ID_SCAN_SCANAFTEROPEN);
    m_pOptions->getCheckBox(ui->checkBoxRecursiveScan, XOptions::ID_SCAN_FLAG_RECURSIVE);
    m_pOptions->getCheckBox(ui->checkBoxHeuristicScan, XOptions::ID_SCAN_FLAG_HEURISTIC);
    m_pOptions->getCheckBox(ui->checkBoxAggressiveScan, XOptions::ID_SCAN_FLAG_AGGRESSIVE);
    m_pOptions->getCheckBox(ui->checkBoxVerbose, XOptions::ID_SCAN_FLAG_VERBOSE);
    m_pOptions->getCheckBox(ui->checkBoxAllTypesScan, XOptions::ID_SCAN_FLAG_ALLTYPES);
    m_pOptions->getCheckBox(ui->checkBoxResources, XOptions::ID_SCAN_FLAG_RESOURCES);
    m_pOptions->getCheckBox(ui->checkBoxArchives, XOptions::ID_SCAN_FLAG_ARCHIVES);
    m_pOptions->getCheckBox(ui->checkBoxOverlay, XOptions::ID_SCAN_FLAG_OVERLAY);
    m_pOptions->getCheckBox(ui->checkBoxFormatResult, XOptions::ID_SCAN_FORMATRESULT);
    m_pOptions->getCheckBox(ui->checkBoxProfiling, XOptions::ID_SCAN_LOG_PROFILING);
    m_pOptions->getCheckBox(ui->groupBoxHighlight, XOptions::ID_SCAN_HIGHLIGHT);
    m_pOptions->getCheckBox(ui->checkBoxSort, XOptions::ID_SCAN_SORT);
    m_pOptions->getCheckBox(ui->checkBoxHideUnknown, XOptions::ID_SCAN_HIDEUNKNOWN);
    m_pOptions->getCheckBox(ui->checkBoxUseCache, XOptions::ID_SCAN_USECACHE);
    if (m_pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE_DIE_ENABLED)) {
        m_pOptions->getLineEdit(ui->lineEditDIEDatabase, XOptions::ID_SCAN_DIE_DATABASE_MAIN_PATH);
        m_pOptions->getLineEdit(ui->lineEditDIEDatabaseExtra, XOptions::ID_SCAN_DIE_DATABASE_EXTRA_PATH);
        m_pOptions->getLineEdit(ui->lineEditDIEDatabaseCustom, XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH);
        m_pOptions->getCheckBox(ui->groupBoxDIEDatabaseExtra, XOptions::ID_SCAN_DIE_DATABASE_EXTRA_ENABLED);
        m_pOptions->getCheckBox(ui->groupBoxDIEDatabaseCustom, XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_ENABLED);
    }
    if (m_pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE_PEID_ENABLED)) {
        m_pOptions->getLineEdit(ui->lineEditPeidDatabase, XOptions::ID_SCAN_PEID_DATABASE_PATH);
    }
    if (m_pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE_YARA_ENABLED)) {
        m_pOptions->getLineEdit(ui->lineEditYaraRules, XOptions::ID_SCAN_YARA_DATABASE_PATH);
    }
    if (m_pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE)) {
        m_pOptions->getComboBox(ui->comboBoxScanEngine, XOptions::ID_SCAN_ENGINE);
    } else if (m_pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE_EMPTY)) {
        m_pOptions->getComboBox(ui->comboBoxScanEngine, XOptions::ID_SCAN_ENGINE_EMPTY);
    }
}

void XScanEngineOptionsWidget::reload()
{
    m_pOptions->setCheckBox(ui->checkBoxScanAfterOpen, XOptions::ID_SCAN_SCANAFTEROPEN);
    m_pOptions->setCheckBox(ui->checkBoxRecursiveScan, XOptions::ID_SCAN_FLAG_RECURSIVE);
    m_pOptions->setCheckBox(ui->checkBoxDeepScan, XOptions::ID_SCAN_FLAG_DEEP);
    m_pOptions->setCheckBox(ui->checkBoxHeuristicScan, XOptions::ID_SCAN_FLAG_HEURISTIC);
    m_pOptions->setCheckBox(ui->checkBoxAggressiveScan, XOptions::ID_SCAN_FLAG_AGGRESSIVE);
    m_pOptions->setCheckBox(ui->checkBoxVerbose, XOptions::ID_SCAN_FLAG_VERBOSE);
    m_pOptions->setCheckBox(ui->checkBoxFormatResult, XOptions::ID_SCAN_FORMATRESULT);
    m_pOptions->setCheckBox(ui->checkBoxAllTypesScan, XOptions::ID_SCAN_FLAG_ALLTYPES);
    m_pOptions->setCheckBox(ui->checkBoxResources, XOptions::ID_SCAN_FLAG_RESOURCES);
    m_pOptions->setCheckBox(ui->checkBoxArchives, XOptions::ID_SCAN_FLAG_ARCHIVES);
    m_pOptions->setCheckBox(ui->checkBoxOverlay, XOptions::ID_SCAN_FLAG_OVERLAY);
    m_pOptions->setCheckBox(ui->groupBoxHighlight, XOptions::ID_SCAN_HIGHLIGHT);
    m_pOptions->setCheckBox(ui->checkBoxSort, XOptions::ID_SCAN_SORT);
    m_pOptions->setCheckBox(ui->checkBoxHideUnknown, XOptions::ID_SCAN_HIDEUNKNOWN);
    m_pOptions->setCheckBox(ui->checkBoxUseCache, XOptions::ID_SCAN_USECACHE);
    m_pOptions->setCheckBox(ui->checkBoxProfiling, XOptions::ID_SCAN_LOG_PROFILING);
    if (m_pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE_DIE_ENABLED)) {
        ui->groupBoxDIEDatabase->show();
        ui->groupBoxDIEDatabaseExtra->show();
        ui->groupBoxDIEDatabaseCustom->show();
        m_pOptions->setLineEdit(ui->lineEditDIEDatabase, XOptions::ID_SCAN_DIE_DATABASE_MAIN_PATH);
        m_pOptions->setLineEdit(ui->lineEditDIEDatabaseExtra, XOptions::ID_SCAN_DIE_DATABASE_EXTRA_PATH);
        m_pOptions->setLineEdit(ui->lineEditDIEDatabaseCustom, XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH);
        m_pOptions->setCheckBox(ui->groupBoxDIEDatabaseExtra, XOptions::ID_SCAN_DIE_DATABASE_EXTRA_ENABLED);
        m_pOptions->setCheckBox(ui->groupBoxDIEDatabaseCustom, XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_ENABLED);
    } else {
        ui->groupBoxDIEDatabase->hide();
        ui->groupBoxDIEDatabaseExtra->hide();
        ui->groupBoxDIEDatabaseCustom->hide();
    }

    if (m_pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE_PEID_ENABLED)) {
        ui->groupBoxPeidDatabase->show();
        m_pOptions->setLineEdit(ui->lineEditPeidDatabase, XOptions::ID_SCAN_PEID_DATABASE_PATH);
    } else {
        ui->groupBoxPeidDatabase->hide();
    }

    if (m_pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE_YARA_ENABLED)) {
        ui->groupBoxYaraRules->show();
        m_pOptions->setLineEdit(ui->lineEditYaraRules, XOptions::ID_SCAN_YARA_DATABASE_PATH);
    } else {
        ui->groupBoxYaraRules->hide();
    }

    if (m_pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE)) {
        ui->groupBoxScanEngine->show();
        m_pOptions->setComboBox(ui->comboBoxScanEngine, XOptions::ID_SCAN_ENGINE);
    } else if (m_pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE_EMPTY)) {
        ui->groupBoxScanEngine->show();
        m_pOptions->setComboBox(ui->comboBoxScanEngine, XOptions::ID_SCAN_ENGINE_EMPTY);
    } else {
        ui->groupBoxScanEngine->hide();
    }
}

void XScanEngineOptionsWidget::setDefaultValues(XOptions *pOptions)
{
    pOptions->addID(XOptions::ID_SCAN_SCANAFTEROPEN, true);
    pOptions->addID(XOptions::ID_SCAN_FLAG_RECURSIVE, true);
    pOptions->addID(XOptions::ID_SCAN_FLAG_DEEP, true);
    pOptions->addID(XOptions::ID_SCAN_FLAG_HEURISTIC, true);
    pOptions->addID(XOptions::ID_SCAN_FLAG_AGGRESSIVE, false);
    pOptions->addID(XOptions::ID_SCAN_FLAG_VERBOSE, true);
    pOptions->addID(XOptions::ID_SCAN_FLAG_ALLTYPES, false);
    pOptions->addID(XOptions::ID_SCAN_FLAG_RESOURCES, false);
    pOptions->addID(XOptions::ID_SCAN_FLAG_ARCHIVES, false);
    pOptions->addID(XOptions::ID_SCAN_FLAG_OVERLAY, false);
    pOptions->addID(XOptions::ID_SCAN_FORMATRESULT, true);
    pOptions->addID(XOptions::ID_SCAN_LOG_PROFILING, false);
    pOptions->addID(XOptions::ID_SCAN_HIGHLIGHT, true);
    pOptions->addID(XOptions::ID_SCAN_SORT, true);
    pOptions->addID(XOptions::ID_SCAN_HIDEUNKNOWN, false);
    pOptions->addID(XOptions::ID_SCAN_USECACHE, false);
    pOptions->addID(XOptions::ID_SCAN_DIRECTORY_PATH, "");

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    pOptions->addID(XOptions::ID_SCAN_COLOR_INSTALLER, QString("%1|%2").arg(QColor(Qt::darkGreen).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_SFX, QString("%1|%2").arg(QColor(Qt::darkGreen).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_ARCHIVE, QString("%1|%2").arg(QColor(Qt::darkGreen).name(), ""));
#else
    pOptions->addID(XOptions::ID_SCAN_COLOR_INSTALLER, QString("%1|%2").arg(QColor(Qt::cyan).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_SFX, QString("%1|%2").arg(QColor(Qt::cyan).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_ARCHIVE, QString("%1|%2").arg(QColor(Qt::cyan).name(), ""));
#endif
    pOptions->addID(XOptions::ID_SCAN_COLOR_PROTECTION, QString("%1|%2").arg(QColor(Qt::red).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_PETOOL, QString("%1|%2").arg(QColor(Qt::green).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_APKTOOL, QString("%1|%2").arg(QColor(Qt::green).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_OS, QString("%1|%2").arg(QColor(Qt::darkYellow).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_VM, QString("%1|%2").arg(QColor(Qt::darkYellow).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_PLATFORM, QString("%1|%2").arg(QColor(Qt::darkYellow).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_DOSEXTENDER, QString("%1|%2").arg(QColor(Qt::darkYellow).name(), ""));
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    pOptions->addID(XOptions::ID_SCAN_COLOR_FORMAT, QString("%1|%2").arg(QColor(Qt::darkGreen).name(), ""));
#else
    pOptions->addID(XOptions::ID_SCAN_COLOR_FORMAT, QString("%1|%2").arg(QColor(Qt::green).name(), ""));
#endif
    pOptions->addID(XOptions::ID_SCAN_COLOR_SIGNTOOL, QString("%1|%2").arg(QColor(Qt::gray).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_CERTIFICATE, QString("%1|%2").arg(QColor(Qt::gray).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_LICENSING, QString("%1|%2").arg(QColor(Qt::gray).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_LANGUAGE, QString("%1|%2").arg(QColor(Qt::darkCyan).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_CORRUPTEDDATA, QString("%1|%2").arg(QColor(Qt::darkRed).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_PERSONALDATA, QString("%1|%2").arg(QColor(Qt::darkRed).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_AUTHOR, QString("%1|%2").arg(QColor(Qt::darkRed).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_VIRUS, QString("%1|%2").arg(QColor(Qt::white).name(), QColor(Qt::darkRed).name()));
    pOptions->addID(XOptions::ID_SCAN_COLOR_TROJAN, QString("%1|%2").arg(QColor(Qt::white).name(), QColor(Qt::darkRed).name()));
    pOptions->addID(XOptions::ID_SCAN_COLOR_MALWARE, QString("%1|%2").arg(QColor(Qt::white).name(), QColor(Qt::darkRed).name()));
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    pOptions->addID(XOptions::ID_SCAN_COLOR_DEBUG, QString("%1|%2").arg(QColor(Qt::darkBlue).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_DEBUGDATA, QString("%1|%2").arg(QColor(Qt::darkBlue).name(), ""));
#else
    pOptions->addID(XOptions::ID_SCAN_COLOR_DEBUG, QString("%1|%2").arg(QColor(Qt::yellow).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_DEBUGDATA, QString("%1|%2").arg(QColor(Qt::yellow).name(), ""));
#endif
    pOptions->addID(XOptions::ID_SCAN_COLOR_GAMEENGINE, QString("%1|%2").arg(QColor(Qt::darkGreen).name(), ""));
    pOptions->addID(XOptions::ID_SCAN_COLOR_COMPILER, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_COMPRESSOR, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_CONVERTER, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_CREATOR, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_DATA, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_DATABASE, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_DOCUMENT, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_GENERIC, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_IMAGE, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_INSTALLERDATA, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_LIBRARY, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_LINKER, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_LOADER, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_OBFUSCATOR, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_OVERLAY, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_PACKAGE, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_PLAYER, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_PRODUCER, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_PROTECTORDATA, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_ROM, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_SFXDATA, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_SOURCECODE, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_STUB, QString("|"));
    pOptions->addID(XOptions::ID_SCAN_COLOR_TOOL, QString("|"));

    if (pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE_DIE_ENABLED)) {
        pOptions->addID(XOptions::ID_SCAN_DIE_DATABASE_MAIN_PATH, "$data/db");
        pOptions->addID(XOptions::ID_SCAN_DIE_DATABASE_EXTRA_PATH, "$data/db_extra");
        pOptions->addID(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH, "$data/db_custom");
        pOptions->addID(XOptions::ID_SCAN_DIE_DATABASE_EXTRA_ENABLED, true);
        pOptions->addID(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_ENABLED, true);
    }

    if (pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE_PEID_ENABLED)) {
        pOptions->addID(XOptions::ID_SCAN_PEID_DATABASE_PATH, "$data/peid");
    }

    if (pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE_YARA_ENABLED)) {
        pOptions->addID(XOptions::ID_SCAN_YARA_DATABASE_PATH, "$data/yara");
    }
}

void XScanEngineOptionsWidget::reloadData(bool bSaveSelection)
{
    Q_UNUSED(bSaveSelection)

    reload();
}

void XScanEngineOptionsWidget::on_toolButtonDIEDatabase_clicked()
{
    QString sText = ui->lineEditDIEDatabase->text();
    QString sInitDirectory = XOptions::convertPathName(sText);

    QString sDirectoryName = QFileDialog::getExistingDirectory(this, tr("Open directory") + QString("..."), sInitDirectory, QFileDialog::ShowDirsOnly);

    if (!sDirectoryName.isEmpty()) {
        ui->lineEditDIEDatabase->setText(sDirectoryName);
    }
}

void XScanEngineOptionsWidget::on_toolButtonDIEDatabaseExtra_clicked()
{
    QString sText = ui->lineEditDIEDatabaseExtra->text();
    QString sInitDirectory = XOptions::convertPathName(sText);

    QString sDirectoryName = QFileDialog::getExistingDirectory(this, tr("Open directory") + QString("..."), sInitDirectory, QFileDialog::ShowDirsOnly);

    if (!sDirectoryName.isEmpty()) {
        ui->lineEditDIEDatabaseExtra->setText(sDirectoryName);
    }
}

void XScanEngineOptionsWidget::on_toolButtonDIEDatabaseCustom_clicked()
{
    QString sText = ui->lineEditDIEDatabaseCustom->text();
    QString sInitDirectory = XOptions::convertPathName(sText);

    QString sDirectoryName = QFileDialog::getExistingDirectory(this, tr("Open directory") + QString("..."), sInitDirectory, QFileDialog::ShowDirsOnly);

    if (!sDirectoryName.isEmpty()) {
        ui->lineEditDIEDatabaseCustom->setText(sDirectoryName);
    }
}

void XScanEngineOptionsWidget::on_toolButtonYaraRules_clicked()
{
    QString sText = ui->lineEditYaraRules->text();
    QString sInitDirectory = XOptions::convertPathName(sText);

    QString sDirectoryName = QFileDialog::getExistingDirectory(this, tr("Open directory") + QString("..."), sInitDirectory, QFileDialog::ShowDirsOnly);

    if (!sDirectoryName.isEmpty()) {
        ui->lineEditYaraRules->setText(sDirectoryName);
    }
}

void XScanEngineOptionsWidget::on_toolButtonPeidDatabase_clicked()
{
    QString sText = ui->lineEditPeidDatabase->text();
    QString sInitDirectory = XOptions::convertPathName(sText);

    QString sDirectoryName = QFileDialog::getExistingDirectory(this, tr("Open directory") + QString("..."), sInitDirectory, QFileDialog::ShowDirsOnly);

    if (!sDirectoryName.isEmpty()) {
        ui->lineEditPeidDatabase->setText(sDirectoryName);
    }
}

QList<DialogViewColors::RECORD> XScanEngineOptionsWidget::getRecords()
{
    QList<DialogViewColors::RECORD> listResult;

    // TODO Create a table with color IDs and names
    {
        DialogViewColors::RECORD record = {"", tr("APK tool"), XOptions::ID_SCAN_COLOR_APKTOOL};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Archive"), XOptions::ID_SCAN_COLOR_ARCHIVE};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Author"), XOptions::ID_SCAN_COLOR_AUTHOR};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Certificate"), XOptions::ID_SCAN_COLOR_CERTIFICATE};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Compiler"), XOptions::ID_SCAN_COLOR_COMPILER};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Compressor"), XOptions::ID_SCAN_COLOR_COMPRESSOR};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Converter"), XOptions::ID_SCAN_COLOR_CONVERTER};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Corrupted data"), XOptions::ID_SCAN_COLOR_CORRUPTEDDATA};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Creator"), XOptions::ID_SCAN_COLOR_CREATOR};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Data"), XOptions::ID_SCAN_COLOR_DATA};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Database"), XOptions::ID_SCAN_COLOR_DATABASE};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Debug"), XOptions::ID_SCAN_COLOR_DEBUG};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Debug data"), XOptions::ID_SCAN_COLOR_DEBUGDATA};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Document"), XOptions::ID_SCAN_COLOR_DOCUMENT};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("DOS extender"), XOptions::ID_SCAN_COLOR_DOSEXTENDER};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Format"), XOptions::ID_SCAN_COLOR_FORMAT};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Game engine"), XOptions::ID_SCAN_COLOR_GAMEENGINE};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Generic"), XOptions::ID_SCAN_COLOR_GENERIC};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Image"), XOptions::ID_SCAN_COLOR_IMAGE};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Installer"), XOptions::ID_SCAN_COLOR_INSTALLER};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Installer data"), XOptions::ID_SCAN_COLOR_INSTALLERDATA};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Language"), XOptions::ID_SCAN_COLOR_LANGUAGE};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Library"), XOptions::ID_SCAN_COLOR_LIBRARY};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Licensing"), XOptions::ID_SCAN_COLOR_LICENSING};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Linker"), XOptions::ID_SCAN_COLOR_LINKER};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Loader"), XOptions::ID_SCAN_COLOR_LOADER};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Malware"), XOptions::ID_SCAN_COLOR_MALWARE};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Obfuscator"), XOptions::ID_SCAN_COLOR_OBFUSCATOR};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Operation system"), XOptions::ID_SCAN_COLOR_OS};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Overlay"), XOptions::ID_SCAN_COLOR_OVERLAY};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Package"), XOptions::ID_SCAN_COLOR_PACKAGE};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("PE tool"), XOptions::ID_SCAN_COLOR_PETOOL};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Personal data"), XOptions::ID_SCAN_COLOR_PERSONALDATA};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Platform"), XOptions::ID_SCAN_COLOR_PLATFORM};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Player"), XOptions::ID_SCAN_COLOR_PLAYER};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Producer"), XOptions::ID_SCAN_COLOR_PRODUCER};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Protector data"), XOptions::ID_SCAN_COLOR_PROTECTORDATA};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Protection"), XOptions::ID_SCAN_COLOR_PROTECTION};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("ROM"), XOptions::ID_SCAN_COLOR_ROM};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("SFX"), XOptions::ID_SCAN_COLOR_SFX};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("SFX data"), XOptions::ID_SCAN_COLOR_SFXDATA};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Sign tool"), XOptions::ID_SCAN_COLOR_SIGNTOOL};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Source code"), XOptions::ID_SCAN_COLOR_SOURCECODE};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Stub"), XOptions::ID_SCAN_COLOR_STUB};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Tool"), XOptions::ID_SCAN_COLOR_TOOL};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Trojan"), XOptions::ID_SCAN_COLOR_TROJAN};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Virtual machine"), XOptions::ID_SCAN_COLOR_VM};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Virus"), XOptions::ID_SCAN_COLOR_VIRUS};
        listResult.append(record);
    }

    return listResult;
}

void XScanEngineOptionsWidget::on_pushButtonScanColors_clicked()
{
    DialogViewColors dialogColors(this);
    dialogColors.setGlobal(getShortcuts(), getGlobalOptions());

    QList<DialogViewColors::RECORD> listRecords = getRecords();

    dialogColors.setOptions(m_pOptions, listRecords, tr("Colors"));

    dialogColors.exec();
}

void XScanEngineOptionsWidget::registerShortcuts(bool bState)
{
    Q_UNUSED(bState)
}
