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
#ifndef PNG_SCRIPT_H
#define PNG_SCRIPT_H

#include "image_script.h"

class PNG_Script : public Image_Script {
    Q_OBJECT
public:
    explicit PNG_Script(XPNG *pPNG, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

public slots:
    quint32 getWidth();
    quint32 getHeight();
    quint8 getBitDepth();
    quint8 getColorType();
    quint8 getCompression();
    quint8 getFilter();
    quint8 getInterlace();
    bool isChunkPresent(const QString &sChunkType);
    qint32 getNumberOfChunks();
    QString getChunkName(qint32 nIndex);
    quint32 getChunkSize(qint32 nIndex);

private:
    XPNG *m_pPNG;
    XPNG::IHDR m_ihdr;
};

#endif  // PNG_SCRIPT_H
