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
#include "scanitem.h"

ScanItem::ScanItem(const QString &sString, ScanItem *pItemParent, qint32 nNumberOfColumns, bool bIsParent)
{
    m_pParentItem = pItemParent;
    m_sString = sString;
    m_nNumberOfColumns = nNumberOfColumns;
    m_bIsParent = bIsParent;
    m_scanStruct = XScanEngine::SCANSTRUCT();
}

ScanItem::~ScanItem()
{
    qDeleteAll(m_listChildItems);
}

void ScanItem::appendChild(ScanItem *pItemChild)
{
    m_listChildItems.append(pItemChild);
}

ScanItem *ScanItem::child(int nRow)
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
    QVariant result;

    if (nColumn < m_nNumberOfColumns) {
        if (nColumn == 0) {
            result = m_sString;
        } else if (nColumn == 1) {
            if (!m_bIsParent) {
                result = "S";  // TODO icon
            }
        } else if (nColumn == 2) {
            if (!m_bIsParent) {
                result = "?";  // TODO icon
            }
        }
    }

    return result;
}

void ScanItem::setScanStruct(const XScanEngine::SCANSTRUCT &scanStruct)
{
    this->m_scanStruct = scanStruct;
}

XScanEngine::SCANSTRUCT ScanItem::scanStruct() const
{
    return m_scanStruct;
}

int ScanItem::row() const
{
    int nResult = 0;

    if (m_pParentItem) {
        nResult = m_pParentItem->m_listChildItems.indexOf(const_cast<ScanItem *>(this));
    }

    return nResult;
}

ScanItem *ScanItem::getParentItem()
{
    return m_pParentItem;
}
