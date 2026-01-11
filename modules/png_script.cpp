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
#include "png_script.h"

PNG_Script::PNG_Script(XPNG *pPNG, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : Image_Script(pPNG, filePart, pOptions, pPdStruct)
{
    m_pPNG = pPNG;
    m_ihdr = m_pPNG->getIHDR();
}

quint32 PNG_Script::getWidth()
{
    return m_ihdr.nWidth;
}

quint32 PNG_Script::getHeight()
{
    return m_ihdr.nHeight;
}

quint8 PNG_Script::getBitDepth()
{
    return m_ihdr.nBitDepth;
}

quint8 PNG_Script::getColorType()
{
    return m_ihdr.nColorType;
}

quint8 PNG_Script::getCompression()
{
    return m_ihdr.nCompression;
}

quint8 PNG_Script::getFilter()
{
    return m_ihdr.nFilter;
}

quint8 PNG_Script::getInterlace()
{
    return m_ihdr.nInterlace;
}

bool PNG_Script::isChunkPresent(const QString &sChunkType)
{
    // TODO: Implement chunk enumeration and checking
    // This would require adding a getChunks() method to XPNG class
    Q_UNUSED(sChunkType)
    return false;
}

qint32 PNG_Script::getNumberOfChunks()
{
    // TODO: Implement chunk counting
    // This would require adding a getChunks() method to XPNG class
    return 0;
}

QString PNG_Script::getChunkName(qint32 nIndex)
{
    // TODO: Implement chunk name retrieval
    // This would require adding a getChunks() method to XPNG class
    Q_UNUSED(nIndex)
    return "";
}

quint32 PNG_Script::getChunkSize(qint32 nIndex)
{
    // TODO: Implement chunk size retrieval
    // This would require adding a getChunks() method to XPNG class
    Q_UNUSED(nIndex)
    return 0;
}
