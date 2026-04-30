/* Copyright (c) 2017-2026 hors<horsicq@gmail.com>
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
#include "scanitem.h"

ScanItem::ScanItem(const QString &sString, ScanItem *pItemParent, qint32 nNumberOfColumns, bool bIsParent)
    : m_sString(sString), m_pParentItem(pItemParent), m_nNumberOfColumns(nNumberOfColumns), m_bIsParent(bIsParent), m_scanStruct()
{
}

ScanItem::~ScanItem()
{
    qDeleteAll(m_listChildItems);
}

void ScanItem::appendChild(ScanItem *pItemChild)
{
    if (pItemChild && !m_listChildItems.contains(pItemChild)) {
        pItemChild->m_pParentItem = this;
        m_listChildItems.append(pItemChild);
    }
}

ScanItem *ScanItem::child(int nRow)
{
    return m_listChildItems.value(nRow);
}

const ScanItem *ScanItem::child(int nRow) const
{
    return m_listChildItems.value(nRow);
}

int ScanItem::childCount() const
{
    return m_listChildItems.count();
}

int ScanItem::columnCount() const
{
    return m_nNumberOfColumns;
}

QVariant ScanItem::data(int nColumn) const
{
    if ((nColumn < 0) || (nColumn >= m_nNumberOfColumns)) {
        return QVariant();
    }

    if (nColumn == COLUMN_TEXT) {
        return m_sString;
    }

    if (m_bIsParent) {
        return QVariant();
    }

    if (nColumn == COLUMN_SCAN_STATUS) {
        return QStringLiteral("S");  // TODO icon
    } else if (nColumn == COLUMN_INFO_STATUS) {
        return QStringLiteral("?");  // TODO icon
    }

    return QVariant();
}

void ScanItem::setScanStruct(const XScanEngine::SCANSTRUCT &scanStruct)
{
    this->m_scanStruct = scanStruct;
}

const XScanEngine::SCANSTRUCT &ScanItem::scanStruct() const
{
    return m_scanStruct;
}

int ScanItem::row() const
{
    if (!m_pParentItem) {
        return 0;
    }

    const int nNumberOfChildItems = m_pParentItem->m_listChildItems.count();

    for (int i = 0; i < nNumberOfChildItems; i++) {
        if (m_pParentItem->m_listChildItems.at(i) == this) {
            return i;
        }
    }

    return -1;
}

ScanItem *ScanItem::parentItem()
{
    return m_pParentItem;
}

const ScanItem *ScanItem::parentItem() const
{
    return m_pParentItem;
}

ScanItem *ScanItem::getParentItem()
{
    return parentItem();
}
