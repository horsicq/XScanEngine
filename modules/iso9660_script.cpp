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
#include "iso9660_script.h"

ISO9660_Script::ISO9660_Script(XISO9660 *pISO, XBinary::FILEPART filePart, const OPTIONS &scanOptions, XBinary::PDSTRUCT *pPdStruct)
    : Archive_Script(pISO, filePart, scanOptions, pPdStruct)
{
    m_pISO = pISO;

    m_sSystemIdentifier = m_pISO->getSystemIdentifier();
    m_sVolumeIdentifier = m_pISO->getVolumeIdentifier();
    m_sVolumeSetIdentifier = m_pISO->getVolumeSetIdentifier();
    m_sPublisherIdentifier = m_pISO->getPublisherIdentifier();
    m_sDataPreparerIdentifier = m_pISO->getDataPreparerIdentifier();
    m_sApplicationIdentifier = m_pISO->getApplicationIdentifier();
    m_sCopyrightFileIdentifier = m_pISO->getCopyrightFileIdentifier();
    m_sAbstractFileIdentifier = m_pISO->getAbstractFileIdentifier();
    m_sBibliographicFileIdentifier = m_pISO->getBibliographicFileIdentifier();
}

QString ISO9660_Script::getSystemIdentifier()
{
    return m_sSystemIdentifier;
}

QString ISO9660_Script::getVolumeIdentifier()
{
    return m_sVolumeIdentifier;
}

QString ISO9660_Script::getVolumeSetIdentifier()
{
    return m_sVolumeSetIdentifier;
}

QString ISO9660_Script::getPublisherIdentifier()
{
    return m_sPublisherIdentifier;
}

QString ISO9660_Script::getDataPreparerIdentifier()
{
    return m_sDataPreparerIdentifier;
}

QString ISO9660_Script::getApplicationIdentifier()
{
    return m_sApplicationIdentifier;
}

QString ISO9660_Script::getCopyrightFileIdentifier()
{
    return m_sCopyrightFileIdentifier;
}

QString ISO9660_Script::getAbstractFileIdentifier()
{
    return m_sAbstractFileIdentifier;
}

QString ISO9660_Script::getBibliographicFileIdentifier()
{
    return m_sBibliographicFileIdentifier;
}
