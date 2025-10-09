/* Copyright (c) 2019-2025 hors<horsicq@gmail.com>
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
#include "dex_script.h"

DEX_Script::DEX_Script(XDEX *pDex, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : Binary_Script(pDex, filePart, pOptions, pPdStruct)
{
    this->m_pDex = pDex;
    m_MapItemsHash = 0;

    m_listItems = pDex->getMapItems(pPdStruct);
    m_bIsStringPoolSorted = pDex->isStringPoolSorted(&m_listItems, pPdStruct);
    m_listStrings = pDex->getStrings(&m_listItems, pPdStruct);
    m_listItemStrings = pDex->getTypeItemStrings(&m_listItems, &m_listStrings, pPdStruct);
}

DEX_Script::~DEX_Script()
{
}

bool DEX_Script::isStringPoolSorted()
{
    return m_bIsStringPoolSorted;
}

bool DEX_Script::isDexStringPresent(const QString &sString)
{
    return m_pDex->isStringInListPresent(&m_listStrings, sString, getPdStruct());
}

bool DEX_Script::isDexItemStringPresent(const QString &sItemString)
{
    return m_pDex->isStringInListPresent(&m_listItemStrings, sItemString, getPdStruct());
}

quint32 DEX_Script::getMapItemsHash()
{
    if (m_MapItemsHash == 0) {
        m_MapItemsHash = XDEX::getMapItemsHash(&m_listItems, getPdStruct());
    }

    return m_MapItemsHash;
}
