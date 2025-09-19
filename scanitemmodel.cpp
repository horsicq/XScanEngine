/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "scanitemmodel.h"

ScanItemModel::ScanItemModel(XScanEngine::SCAN_OPTIONS *pScanOptions, const QList<XScanEngine::SCANSTRUCT> *pListScanStructs, qint32 nNumberOfColumns)
    : QAbstractItemModel(0)
{
    m_scanOptions = *pScanOptions;

    m_pRootItem = new ScanItem(tr("Result"), nullptr, nNumberOfColumns, true);
    XScanEngine::SCANSTRUCT emptySS = {};
    m_pRootItem->setScanStruct(emptySS);

    QMap<QString, ScanItem *> mapParents;

    qint32 nNumberOfDetects = pListScanStructs->count();

    for (qint32 i = 0; i < nNumberOfDetects; i++) {
        if (!mapParents.contains(pListScanStructs->at(i).id.sUuid)) {
            ScanItem *_pItemParent = nullptr;

            if (pListScanStructs->at(i).parentId.sUuid == "") {
                _pItemParent = m_pRootItem;
            } else {
                _pItemParent = mapParents.value(pListScanStructs->at(i).parentId.sUuid);
            }

            if (_pItemParent == nullptr) {
                // _pItemParent = g_pRootItem;
                QString sParent = XBinary::fileTypeIdToString(pListScanStructs->at(i).parentId.fileType);
                _pItemParent = new ScanItem(sParent, m_pRootItem, nNumberOfColumns, true);
                m_pRootItem->appendChild(_pItemParent);
                mapParents.insert(pListScanStructs->at(i).parentId.sUuid, _pItemParent);
            }

            QString sTypeString = XScanEngine::createTypeString(pScanOptions, &pListScanStructs->at(i));

            ScanItem *pItemMain = new ScanItem(sTypeString, _pItemParent, nNumberOfColumns, true);
            XScanEngine::SCANSTRUCT ss = XScanEngine::createHeaderScanStruct(&pListScanStructs->at(i));
            pItemMain->setScanStruct(ss);
            _pItemParent->appendChild(pItemMain);

            mapParents.insert(pListScanStructs->at(i).id.sUuid, pItemMain);
        }

        if (pListScanStructs->at(i).sName != "") {
            bool bAdd = true;

            if (pListScanStructs->at(i).bIsUnknown && pScanOptions->bHideUnknown) {
                bAdd = false;
            }

            if (bAdd) {
                ScanItem *pItemParent = mapParents.value(pListScanStructs->at(i).id.sUuid);

                QString sItem = XScanEngine::createResultStringEx(pScanOptions, &pListScanStructs->at(i));
                ScanItem *pItem = new ScanItem(sItem, pItemParent, nNumberOfColumns, false);
                pItem->setScanStruct(pListScanStructs->at(i));
                pItemParent->appendChild(pItem);
            }
        }
    }
}

ScanItemModel::~ScanItemModel()
{
    delete m_pRootItem;
}

QVariant ScanItemModel::headerData(int nSection, Qt::Orientation orientation, int nRole) const
{
    QVariant result;

    if ((orientation == Qt::Horizontal) && (nRole == Qt::DisplayRole)) {
        result = m_pRootItem->data(nSection);
    }

    return result;
}

QModelIndex ScanItemModel::index(int nRow, int nColumn, const QModelIndex &parent) const
{
    QModelIndex result;

    if (hasIndex(nRow, nColumn, parent)) {
        ScanItem *pParentItem = nullptr;

        if (!parent.isValid()) {
            pParentItem = m_pRootItem;
        } else {
            pParentItem = static_cast<ScanItem *>(parent.internalPointer());
        }

        ScanItem *pItemChild = pParentItem->child(nRow);

        if (pItemChild) {
            result = createIndex(nRow, nColumn, pItemChild);
        }
    }

    return result;
}

QModelIndex ScanItemModel::parent(const QModelIndex &index) const
{
    QModelIndex result;

    if (index.isValid()) {
        ScanItem *pChildItem = static_cast<ScanItem *>(index.internalPointer());
        ScanItem *pParentItem = pChildItem->getParentItem();

        if (pParentItem != m_pRootItem) {
            result = createIndex(pParentItem->row(), 0, pParentItem);
        }
    }

    return result;
}

int ScanItemModel::rowCount(const QModelIndex &parent) const
{
    int nResult = 0;

    if (parent.column() <= 0) {
        ScanItem *pParentItem = nullptr;

        if (!parent.isValid()) {
            pParentItem = m_pRootItem;
        } else {
            pParentItem = static_cast<ScanItem *>(parent.internalPointer());
        }

        nResult = pParentItem->childCount();
    }

    return nResult;
}

int ScanItemModel::columnCount(const QModelIndex &parent) const
{
    int nResult = 0;

    if (parent.isValid()) {
        nResult = static_cast<ScanItem *>(parent.internalPointer())->columnCount();
    } else {
        nResult = m_pRootItem->columnCount();
    }

    return nResult;
}

QVariant ScanItemModel::data(const QModelIndex &index, int nRole) const
{
    QVariant result;

    if (index.isValid()) {
        ScanItem *pItem = static_cast<ScanItem *>(index.internalPointer());

        if (nRole == Qt::DisplayRole) {
            result = pItem->data(index.column());
        } else if (nRole == Qt::UserRole + UD_FILETYPE) {
            result = pItem->scanStruct().id.fileType;
        } else if (nRole == Qt::UserRole + UD_NAME) {
            result = pItem->scanStruct().sName;
        } else if (nRole == Qt::UserRole + UD_INFO) {
            result = pItem->scanStruct().varInfo;
        } else if (nRole == Qt::UserRole + UD_INFO2) {
            result = pItem->scanStruct().varInfo2;
        } else if (nRole == Qt::UserRole + UD_UUID) {
            result = pItem->scanStruct().id.sUuid;
        }
#ifdef QT_GUI_LIB
        else if (nRole == Qt::ForegroundRole) {
            if (g_scanOptions.bIsHighlight) {
                if ((pItem->scanStruct().globalColorRecord.colorMain == Qt::transparent) || (pItem->scanStruct().globalColorRecord.colorMain == Qt::color0)) {
                    result = QVariant();
                } else {
                    result = QVariant(QColor(pItem->scanStruct().globalColorRecord.colorMain));
                }
            } else {
                result = QVariant();
            }
        } else if (nRole == Qt::BackgroundRole) {
            if (g_scanOptions.bIsHighlight) {
                if ((pItem->scanStruct().globalColorRecord.colorBackground == Qt::transparent) || (pItem->scanStruct().globalColorRecord.colorBackground == Qt::color0)) {
                    result = QVariant();
                } else {
                    result = QVariant(QColor(pItem->scanStruct().globalColorRecord.colorBackground));
                }
            } else {
                result = QVariant();
            }
        }
#endif
    }

    return result;
}

Qt::ItemFlags ScanItemModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags result = Qt::NoItemFlags;

    if (index.isValid()) {
        result = QAbstractItemModel::flags(index);
    }

    return result;
}

QString ScanItemModel::toXML()
{
    QString sResult;
    QXmlStreamWriter xml(&sResult);

    xml.setAutoFormatting(true);

    _toXML(&xml, m_pRootItem, 0);

    return sResult;
}

QString ScanItemModel::toJSON()
{
    QString sResult;
#if (QT_VERSION_MAJOR > 4)
    QJsonObject jsonResult;

    _toJSON(&jsonResult, m_pRootItem, 0);

    QJsonDocument saveFormat(jsonResult);

    QByteArray baData = saveFormat.toJson(QJsonDocument::Indented);

    sResult = baData.data();
#endif

    return sResult;
}

QString ScanItemModel::toCSV()
{
    QString sResult;

    _toCSV(&sResult, m_pRootItem, 0);

    return sResult;
}

QString ScanItemModel::toTSV()
{
    QString sResult;

    _toTSV(&sResult, m_pRootItem, 0);

    return sResult;
}

QString ScanItemModel::toFormattedString()
{
    QString sResult;

    _toFormattedString(&sResult, m_pRootItem, 0);

    return sResult;
}

void ScanItemModel::coloredOutput()
{
    _coloredOutput(m_pRootItem, 0);
}

QString ScanItemModel::toString(XBinary::FORMATTYPE formatType)
{
    QString sResult;

    if (formatType == XBinary::FORMATTYPE_UNKNOWN) {
        if (m_scanOptions.bResultAsCSV) formatType = XBinary::FORMATTYPE_CSV;
        else if (m_scanOptions.bResultAsJSON) formatType = XBinary::FORMATTYPE_JSON;
        else if (m_scanOptions.bResultAsTSV) formatType = XBinary::FORMATTYPE_TSV;
        else if (m_scanOptions.bResultAsXML) formatType = XBinary::FORMATTYPE_XML;
        else formatType = XBinary::FORMATTYPE_PLAINTEXT;
    }

    if (formatType == XBinary::FORMATTYPE_PLAINTEXT) {
        sResult = toFormattedString();
    } else if (formatType == XBinary::FORMATTYPE_XML) {
        sResult = toXML();
    } else if (formatType == XBinary::FORMATTYPE_JSON) {
        sResult = toJSON();
    } else if (formatType == XBinary::FORMATTYPE_CSV) {
        sResult = toCSV();
    } else if (formatType == XBinary::FORMATTYPE_TSV) {
        sResult = toTSV();
    }

    return sResult;
}

ScanItem *ScanItemModel::rootItem()
{
    return this->m_pRootItem;
}

void ScanItemModel::_toXML(QXmlStreamWriter *pXml, ScanItem *pItem, qint32 nLevel)
{
    XScanEngine::SCANSTRUCT ss = pItem->scanStruct();

    if (pItem->childCount()) {
        pXml->writeStartElement(pItem->data(0).toString());

        if (ss.id.filePart != XBinary::FILEPART_UNKNOWN) {
            pXml->writeAttribute("parentfilepart", XBinary::recordFilePartIdToString(ss.parentId.filePart));
            pXml->writeAttribute("filetype", XBinary::fileTypeIdToString(ss.id.fileType));
            pXml->writeAttribute("info", ss.id.sInfo);
            pXml->writeAttribute("offset", QString::number(ss.id.nOffset));
            pXml->writeAttribute("size", QString::number(ss.id.nSize));
        }

        qint32 nNumberOfChildren = pItem->childCount();

        for (qint32 i = 0; i < nNumberOfChildren; i++) {
            _toXML(pXml, pItem->child(i), nLevel + 1);
        }

        pXml->writeEndElement();
    } else {
        pXml->writeStartElement("detect");
        pXml->writeAttribute("type", ss.sType);
        pXml->writeAttribute("name", ss.sName);
        pXml->writeAttribute("version", ss.sVersion);
        pXml->writeAttribute("info", ss.sInfo);
        pXml->writeCharacters(pItem->data(0).toString());
        pXml->writeEndElement();
    }
}
#if (QT_VERSION_MAJOR > 4)
void ScanItemModel::_toJSON(QJsonObject *pJsonObject, ScanItem *pItem, qint32 nLevel)
{
    XScanEngine::SCANSTRUCT ss = pItem->scanStruct();

    if (pItem->childCount()) {
        QString sArrayName = "detects";

        if (ss.id.filePart != XBinary::FILEPART_UNKNOWN) {
            pJsonObject->insert("parentfilepart", XBinary::recordFilePartIdToString(ss.parentId.filePart));
            pJsonObject->insert("filetype", XBinary::fileTypeIdToString(ss.id.fileType));
            pJsonObject->insert("info", ss.id.sInfo);
            pJsonObject->insert("offset", QString::number(ss.id.nOffset));
            pJsonObject->insert("size", QString::number(ss.id.nSize));

            sArrayName = "values";
        }

        QJsonArray jsArray;

        qint32 nNumberOfChildren = pItem->childCount();

        for (qint32 i = 0; i < nNumberOfChildren; i++) {
            QJsonObject jsRecord;

            _toJSON(&jsRecord, pItem->child(i), nLevel + 1);

            jsArray.append(jsRecord);
        }

        pJsonObject->insert(sArrayName, jsArray);
    } else {
        pJsonObject->insert("type", ss.sType);
        pJsonObject->insert("name", ss.sName);
        pJsonObject->insert("version", ss.sVersion);
        pJsonObject->insert("info", ss.sInfo);
        pJsonObject->insert("string", pItem->data(0).toString());
    }
}
#endif
void ScanItemModel::_toCSV(QString *pString, ScanItem *pItem, qint32 nLevel)
{
    if (pItem->childCount()) {
        qint32 nNumberOfChildren = pItem->childCount();

        for (qint32 i = 0; i < nNumberOfChildren; i++) {
            _toCSV(pString, pItem->child(i), nLevel + 1);
        }
    } else {
        XScanEngine::SCANSTRUCT ss = pItem->scanStruct();

        QString sResult = QString("%1;%2;%3;%4;%5\n").arg(ss.sType, ss.sName, ss.sVersion, ss.sInfo, pItem->data(0).toString());

        pString->append(sResult);
    }
}

void ScanItemModel::_toTSV(QString *pString, ScanItem *pItem, qint32 nLevel)
{
    if (pItem->childCount()) {
        qint32 nNumberOfChildren = pItem->childCount();

        for (qint32 i = 0; i < nNumberOfChildren; i++) {
            _toTSV(pString, pItem->child(i), nLevel + 1);
        }
    } else {
        XScanEngine::SCANSTRUCT ss = pItem->scanStruct();

        QString sResult = QString("%1\t%2\t%3\t%4\t%5\n").arg(ss.sType, ss.sName, ss.sVersion, ss.sInfo, pItem->data(0).toString());

        pString->append(sResult);
    }
}

void ScanItemModel::_toFormattedString(QString *pString, ScanItem *pItem, qint32 nLevel)
{
    if (nLevel) {
        QString sResult;
        sResult = sResult.leftJustified(4 * (nLevel - 1), ' ');  // TODO function !!!
        sResult.append(QString("%1\n").arg(pItem->data(0).toString()));
        pString->append(sResult);
    }

    qint32 nNumberOfChildren = pItem->childCount();

    for (qint32 i = 0; i < nNumberOfChildren; i++) {
        _toFormattedString(pString, pItem->child(i), nLevel + 1);
    }
}

void ScanItemModel::_coloredOutput(ScanItem *pItem, qint32 nLevel)
{
#ifdef QT_GUI_LIB
    Q_UNUSED(pItem)
    Q_UNUSED(nLevel)
#else
    if (nLevel) {
        QString sPrefix;
        sPrefix = sPrefix.leftJustified(4 * (nLevel - 1), ' ');
        printf("%s", sPrefix.toUtf8().data());
        _coloredItem(pItem);
        printf("\n");
    }

    qint32 nNumberOfChildren = pItem->childCount();

    for (qint32 i = 0; i < nNumberOfChildren; i++) {
        _coloredOutput(pItem->child(i), nLevel + 1);
    }
#endif
}

void ScanItemModel::_coloredItem(ScanItem *pItem)
{
#ifdef QT_GUI_LIB
    Q_UNUSED(pItem)
#else
    if (m_scanOptions.bIsHighlight) {
        XOptions::printConsole(pItem->data(0).toString(), pItem->scanStruct().globalColorRecord.colorMain, pItem->scanStruct().globalColorRecord.colorBackground);
    } else {
        XOptions::printConsole(pItem->data(0).toString(), Qt::transparent, Qt::transparent);
    }
#endif
}
