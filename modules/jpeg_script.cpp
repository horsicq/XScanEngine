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
#include "jpeg_script.h"

Jpeg_Script::Jpeg_Script(XJpeg *pJpeg, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : Image_Script(pJpeg, filePart, pOptions, pPdStruct)
{
    m_pJpeg = pJpeg;

    m_listChunks = m_pJpeg->getChunks(pPdStruct);
    m_osExif = m_pJpeg->getExif(&m_listChunks);
    m_listExifChunks = XTiff::getExifChunks(pJpeg->getDevice(), m_osExif);
    m_sExifCameraName = XTiff::getExifCameraName(pJpeg->getDevice(), m_osExif, &m_listExifChunks);
}

QString Jpeg_Script::getComment()
{
    return m_pJpeg->getComment(&m_listChunks);
}

QString Jpeg_Script::getDqtMD5()
{
    return m_pJpeg->getDqtMD5(&m_listChunks);
}

bool Jpeg_Script::isChunkPresent(qint32 nID)
{
    return m_pJpeg->isChunkPresent(&m_listChunks, (qint8)nID);
}

bool Jpeg_Script::isExifPresent()
{
    return m_pJpeg->isExifPresent(m_osExif);
}

QString Jpeg_Script::getExifCameraName()
{
    return m_sExifCameraName;
}
