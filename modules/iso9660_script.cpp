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

ISO9660_Script::ISO9660_Script(XISO9660 *pISO, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : Archive_Script(pISO, filePart, pOptions, pPdStruct)
{
    this->m_pISO = pISO;

    g_sSystemIdentifier = m_pISO->getSystemIdentifier();
    g_sVolumeIdentifier = m_pISO->getVolumeIdentifier();
    g_sVolumeSetIdentifier = m_pISO->getVolumeSetIdentifier();
    g_sPublisherIdentifier = m_pISO->getPublisherIdentifier();
    g_sDataPreparerIdentifier = m_pISO->getDataPreparerIdentifier();
    g_sApplicationIdentifier = m_pISO->getApplicationIdentifier();
    g_sCopyrightFileIdentifier = m_pISO->getCopyrightFileIdentifier();
    g_sAbstractFileIdentifier = m_pISO->getAbstractFileIdentifier();
    g_sBibliographicFileIdentifier = m_pISO->getBibliographicFileIdentifier();
}

ISO9660_Script::~ISO9660_Script()
{
}

QString ISO9660_Script::getSystemIdentifier()
{
    return g_sSystemIdentifier;
}

QString ISO9660_Script::getVolumeIdentifier()
{
    return g_sVolumeIdentifier;
}

QString ISO9660_Script::getVolumeSetIdentifier()
{
    return g_sVolumeSetIdentifier;
}

QString ISO9660_Script::getPublisherIdentifier()
{
    return g_sPublisherIdentifier;
}

QString ISO9660_Script::getDataPreparerIdentifier()
{
    return g_sDataPreparerIdentifier;
}

QString ISO9660_Script::getApplicationIdentifier()
{
    return g_sApplicationIdentifier;
}

QString ISO9660_Script::getCopyrightFileIdentifier()
{
    return g_sCopyrightFileIdentifier;
}

QString ISO9660_Script::getAbstractFileIdentifier()
{
    return g_sAbstractFileIdentifier;
}

QString ISO9660_Script::getBibliographicFileIdentifier()
{
    return g_sBibliographicFileIdentifier;
}
