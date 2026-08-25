/* Copyright (c) 2026 hors<horsicq@gmail.com>
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
#include "xscanengineconsole.h"
#include "xconsoloutput.h"
#include "xarchives.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaType>
#include <QSet>
#include <QVector>
#include <QXmlStreamWriter>

#include <algorithm>
#include <cstdio>

namespace {

// Collect full archive records through the streaming unpack API so every
// property the format parser filled (method, timestamps, CRC, ownership, ...)
// is available, not just the handful the legacy flat RECORD struct carries.
QList<XBinary::ARCHIVERECORD> collectArchiveRecords(XBinary *pArchive, const QMap<XBinary::UNPACK_PROP, QVariant> &mapUnpackProperties,
                                                    XBinary::PDSTRUCT *pPdStruct, bool *pbComplete = nullptr)
{
    QList<XBinary::ARCHIVERECORD> listResult;

    if (pbComplete) {
        *pbComplete = false;
    }

    if (!pArchive) {
        return listResult;
    }

    XBinary::UNPACK_STATE state = {};
    QMap<XBinary::UNPACK_PROP, QVariant> mapProperties = mapUnpackProperties;
    bool bInitialized = pArchive->initUnpack(&state, mapProperties, pPdStruct);

    if (!bInitialized && XBinary::isPdStructNotCanceled(pPdStruct)) {
        state = XBinary::UNPACK_STATE();
        mapProperties.insert(XBinary::UNPACK_PROP_METADATAONLY, true);
        bInitialized = pArchive->initUnpack(&state, mapProperties, pPdStruct);
    }

    if (bInitialized) {
        const qint32 nNumberOfRecords = state.nNumberOfRecords;
        bool bEnumerationComplete = (state.nCurrentIndex == 0) &&
                                    (nNumberOfRecords >= 0) &&
                                    (state.nCurrentIndex <= nNumberOfRecords);

        // The streaming contract advances only *between* declared records.
        // A single-record archive therefore finishes with currentIndex == 0;
        // moveToNext() returning false at that point is not an enumeration
        // failure.  Keep an independent bounded loop and validate that the
        // archive cannot silently change its declared count or cursor.
        for (qint32 i = 0; bEnumerationComplete &&
             (i < nNumberOfRecords) &&
             XBinary::isPdStructNotCanceled(pPdStruct); ++i) {
            const qint32 nExpectedIndex = state.nCurrentIndex;
            const XBinary::ARCHIVERECORD record =
                pArchive->infoCurrent(&state, pPdStruct);
            if (!XBinary::isPdStructNotCanceled(pPdStruct) ||
                record.mapProperties.isEmpty() ||
                !XBinary::isArchiveRecordExtentValid(record) ||
                (state.nCurrentIndex < 0) ||
                (state.nCurrentIndex >= nNumberOfRecords) ||
                (state.nCurrentIndex != nExpectedIndex) ||
                (state.nNumberOfRecords != nNumberOfRecords)) {
                bEnumerationComplete = false;
                break;
            }
            listResult.append(record);

            if (i + 1 < nNumberOfRecords) {
                const qint32 nPreviousIndex = state.nCurrentIndex;
                const bool bMoved =
                    pArchive->moveToNext(&state, pPdStruct);
                if (!bMoved ||
                    !XBinary::isPdStructNotCanceled(pPdStruct) ||
                    (state.nCurrentIndex != (nPreviousIndex + 1)) ||
                    (state.nCurrentIndex >= nNumberOfRecords) ||
                    (state.nNumberOfRecords != nNumberOfRecords)) {
                    bEnumerationComplete = false;
                    break;
                }
            }
        }

        const bool bFinished = pArchive->finishUnpack(&state, nullptr);
        bEnumerationComplete = bEnumerationComplete && bFinished &&
                               (listResult.size() == nNumberOfRecords) &&
                               XBinary::isPdStructNotCanceled(pPdStruct);
        if (pbComplete) {
            *pbComplete = bEnumerationComplete;
        }
        if (!bEnumerationComplete) {
            listResult.clear();
        }
    }

    return listResult;
}

bool allowsReadOnlyMetadataFallback(const QString &sPassword)
{
    // With no credential supplied, a native parser may still expose public
    // headers from an encrypted archive. An explicitly supplied credential is
    // authoritative and must never be disguised by metadata-only fallback.
    return sPassword.isEmpty();
}

bool listWithIp7zSource(XBinary::FT fileType, QIODevice *pDevice, const QString &sFileName, const QString &sPassword,
                        QList<XBinary::ARCHIVERECORD> *pListRecords, QString *pIp7zError,
                        XBinary::PDSTRUCT *pPdStruct, bool *pbTerminalFailure)
{
    if (pbTerminalFailure) *pbTerminalFailure = false;

    // The native compressed-TAR handlers expose the records inside the TAR.
    // 7-Zip intentionally treats the outer compressor as a one-file archive,
    // so accepting that result would hide the actual members from the UI/CLI.
    if (XArchives::isNativeReaderPreferredFileType(fileType, pDevice, pPdStruct)) return false;

    if (XArchives::isIp7zSourceAvailable()) {
        if (XArchives::listArchiveWithIp7zSource(sFileName, sPassword, pListRecords, pIp7zError, pPdStruct)) {
            return true;
        }
        const QString sError = pIp7zError ? *pIp7zError : QString();
        if (!XBinary::isPdStructNotCanceled(pPdStruct) ||
            (!XArchives::isIp7zUnsupportedFormatError(sError) &&
             !allowsReadOnlyMetadataFallback(sPassword))) {
            if (pbTerminalFailure) *pbTerminalFailure = true;
            return false;
        }
    }

    return false;
}

QString recordName(const XBinary::ARCHIVERECORD &record)
{
    return record.mapProperties.value(XBinary::FPART_PROP_ORIGINALNAME).toString();
}

bool recordIsFolder(const XBinary::ARCHIVERECORD &record)
{
    QString sName = recordName(record);

    return record.mapProperties.value(XBinary::FPART_PROP_ISFOLDER).toBool() || sName.endsWith(QChar('/')) || sName.endsWith(QChar('\\'));
}

bool recordHasSize(const XBinary::ARCHIVERECORD &record)
{
    if (!record.mapProperties.contains(XBinary::FPART_PROP_UNCOMPRESSEDSIZE)) {
        return false;
    }

    bool bOk = false;
    const qint64 nSize = record.mapProperties.value(XBinary::FPART_PROP_UNCOMPRESSEDSIZE).toLongLong(&bOk);
    return bOk && (nSize >= 0);
}

qint64 recordSize(const XBinary::ARCHIVERECORD &record)
{
    return recordHasSize(record) ? record.mapProperties.value(XBinary::FPART_PROP_UNCOMPRESSEDSIZE).toLongLong() : 0;
}

// A record's stream coordinates are not always its own.  Two cases:
//   * an archive-stream record (HANDLE_METHOD_ARCHIVE_STREAM) publishes no
//     extent at all, because the member has no addressable extent on the
//     compressed device - the container's single stream holds every member;
//   * a solid record whose stream decodes to more than the member itself
//     (FPART_PROP_STREAMUNPACKEDSIZE > its uncompressed size) shares one
//     compressed stream with every other member of the block.
// In both cases nStreamSize is the container's number, not the member's, and
// printing it per row multiplies the archive size by the record count.
bool recordSharesContainerStream(const XBinary::ARCHIVERECORD &record)
{
    qint32 nArchiveStreamIndex = -1;

    if (XBinary::getArchiveStreamRecordIndex(record, &nArchiveStreamIndex)) {
        return true;
    }

    if (record.mapProperties.value(XBinary::FPART_PROP_ISSOLID).toBool() && record.mapProperties.contains(XBinary::FPART_PROP_STREAMUNPACKEDSIZE)) {
        return record.mapProperties.value(XBinary::FPART_PROP_STREAMUNPACKEDSIZE).toLongLong() >
               record.mapProperties.value(XBinary::FPART_PROP_UNCOMPRESSEDSIZE).toLongLong();
    }

    return false;
}

enum PACKEDSTATE {
    PACKEDSTATE_VALUE = 0,  // the member's own packed size
    PACKEDSTATE_NONE,       // no payload to account for (directory entry)
    PACKEDSTATE_UNKNOWN     // not derivable from this container
};

// Report the member's own packed size, never a number that belongs to the
// container.  An honest "unknown" is preferable to a confident wrong total.
PACKEDSTATE recordPacked(const XBinary::ARCHIVERECORD &record, qint64 *pnPacked)
{
    if (pnPacked) *pnPacked = 0;

    // Directories have no payload, so they have no packed size - not zero, not
    // the container's size.
    if (recordIsFolder(record)) {
        return PACKEDSTATE_NONE;
    }

    if (record.mapProperties.contains(XBinary::FPART_PROP_COMPRESSEDSIZE)) {
        if (pnPacked) *pnPacked = record.mapProperties.value(XBinary::FPART_PROP_COMPRESSEDSIZE).toLongLong();
        return PACKEDSTATE_VALUE;
    }

    if (recordSharesContainerStream(record)) {
        return PACKEDSTATE_UNKNOWN;
    }

    // Some static unpackers (including NSIS) publish one packed stream extent
    // on every solid member without a separate block id. Count that extent
    // before synthesizing zero for an empty member, otherwise a leading empty
    // member can claim the stream's deduplication key with a false zero.
    if (record.mapProperties.value(XBinary::FPART_PROP_ISSOLID).toBool() && (record.nStreamSize > 0)) {
        if (pnPacked) *pnPacked = record.nStreamSize;
        return PACKEDSTATE_VALUE;
    }

    // Only an explicitly reported zero denotes an empty regular file. A
    // missing size is unknown, not an implicit zero. Prefer an explicit packed
    // size above because an empty payload can still have nonzero framing.
    if (recordHasSize(record) && (recordSize(record) == 0)) {
        return PACKEDSTATE_VALUE;
    }

    if (record.nStreamSize > 0) {
        if (pnPacked) *pnPacked = record.nStreamSize;
        return PACKEDSTATE_VALUE;
    }

    return PACKEDSTATE_UNKNOWN;
}

QString recordPackedString(const XBinary::ARCHIVERECORD &record)
{
    qint64 nPacked = 0;

    if (recordPacked(record, &nPacked) == PACKEDSTATE_VALUE) {
        return QString::number(nPacked);
    }

    return QString();
}

QString recordModified(const XBinary::ARCHIVERECORD &record)
{
    QDateTime dateTime;

    if (record.mapProperties.contains(XBinary::FPART_PROP_DATETIME)) {
        dateTime = record.mapProperties.value(XBinary::FPART_PROP_DATETIME).toDateTime();
    } else if (record.mapProperties.contains(XBinary::FPART_PROP_MTIME)) {
        dateTime = record.mapProperties.value(XBinary::FPART_PROP_MTIME).toDateTime();
    }

    if (dateTime.isValid()) {
        // absolute timestamps (7z FILETIME is UTC) are shown in the viewer's local
        // zone; local/wall-clock timestamps (DOS/ZIP) are already local, so
        // toLocalTime() leaves them unchanged
        return dateTime.toLocalTime().toString("yyyy-MM-dd hh:mm:ss");
    }

    return QString();
}

// Render a POSIX file mode as the familiar symbolic form plus octal, e.g.
// "-rwxr-xr-x (0755)".  Decimal mode values are unreadable on their own.
QString modeToString(quint32 nMode, bool bIsFolder)
{
    QString sResult;

    quint32 nType = nMode & 0xF000u;  // S_IFMT

    if (nType == 0x4000u) sResult += QChar('d');       // S_IFDIR
    else if (nType == 0xA000u) sResult += QChar('l');  // S_IFLNK
    else if (nType == 0x8000u) sResult += QChar('-');  // S_IFREG
    else sResult += bIsFolder ? QChar('d') : QChar('-');

    const char cPerms[9] = {'r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x'};

    for (qint32 i = 0; i < 9; i++) {
        sResult += (nMode & (1u << (8 - i))) ? QChar(cPerms[i]) : QChar('-');
    }

    return QString("%1 (0%2)").arg(sResult).arg(nMode & 0777u, 0, 8);
}

QString recordCRC(const XBinary::ARCHIVERECORD &record)
{
    XBinary::FPART_PROP prop = XBinary::FPART_PROP_UNKNOWN;

    if (record.mapProperties.contains(XBinary::FPART_PROP_RESULTCRC)) {
        prop = XBinary::FPART_PROP_RESULTCRC;
    } else if (record.mapProperties.contains(XBinary::FPART_PROP_UNCOMPRESSEDCRC)) {
        prop = XBinary::FPART_PROP_UNCOMPRESSEDCRC;
    }

    if (prop != XBinary::FPART_PROP_UNKNOWN) {
        return QString("%1").arg(record.mapProperties.value(prop).toULongLong(), 8, 16, QChar('0')).toUpper();
    }

    const QString sChecksum = record.mapProperties.value(
        XBinary::FPART_PROP_CHECKSUM).toString().trimmed();
    if (!sChecksum.isEmpty()) {
        return sChecksum.toUpper();
    }

    return QString();
}

QString recordAttr(const XBinary::ARCHIVERECORD &record)
{
    QString sResult;

    // Match the technical-list convention used by UnRAR: R H A D S C I.
    // Compression/indexing are not currently exposed by the record model, so
    // those two positions remain dots.  Encryption is not a DOS attribute;
    // retain the app's existing '+' marker as an optional suffix.
    sResult += record.mapProperties.value(XBinary::FPART_PROP_ISREADONLY).toBool() ? QChar('R') : QChar('.');
    sResult += record.mapProperties.value(XBinary::FPART_PROP_ISHIDDEN).toBool() ? QChar('H') : QChar('.');
    sResult += record.mapProperties.value(XBinary::FPART_PROP_ISARCHIVE).toBool() ? QChar('A') : QChar('.');
    sResult += recordIsFolder(record) ? QChar('D') : QChar('.');
    sResult += record.mapProperties.value(XBinary::FPART_PROP_ISSYSTEM).toBool() ? QChar('S') : QChar('.');
    sResult += QStringLiteral("..");
    if (record.mapProperties.value(XBinary::FPART_PROP_ENCRYPTED).toBool()) {
        sResult += QChar('+');
    }

    return sResult;
}

QString recordRatio(const XBinary::ARCHIVERECORD &record)
{
    if (recordIsFolder(record) ||
        record.mapProperties.value(XBinary::FPART_PROP_ISSOLID).toBool() || !recordHasSize(record)) {
        return QString();
    }

    const qint64 nSize = recordSize(record);
    qint64 nPacked = 0;
    if ((nSize <= 0) || (recordPacked(record, &nPacked) != PACKEDSTATE_VALUE)) {
        return QString();
    }

    return QString("%1%").arg(QString::number(
        (double)nPacked * 100.0 / (double)nSize, 'f', 1));
}

QString consoleFPartName(XBinary::FPART_PROP prop)
{
    QString sResult;

    if (prop == XBinary::FPART_PROP_ORIGINALNAME) sResult = "Name";
    else if (prop == XBinary::FPART_PROP_UNCOMPRESSEDSIZE) sResult = "Size";
    else if (prop == XBinary::FPART_PROP_COMPRESSEDSIZE) sResult = "Compressed size";
    else if (prop == XBinary::FPART_PROP_HANDLEMETHOD) sResult = "Method";
    else if (prop == XBinary::FPART_PROP_HANDLEMETHOD2) sResult = "Method 2";
    else if (prop == XBinary::FPART_PROP_DATETIME) sResult = "Modified";
    else if (prop == XBinary::FPART_PROP_MTIME) sResult = "Modified";
    else if (prop == XBinary::FPART_PROP_CTIME) sResult = "Created";
    else if (prop == XBinary::FPART_PROP_ATIME) sResult = "Accessed";
    else if (prop == XBinary::FPART_PROP_RESULTCRC) sResult = "CRC";
    else if (prop == XBinary::FPART_PROP_UNCOMPRESSEDCRC) sResult = "CRC";
    else if (prop == XBinary::FPART_PROP_CRC_TYPE) sResult = "CRC type";
    else if (prop == XBinary::FPART_PROP_ENCRYPTED) sResult = "Encrypted";
    else if (prop == XBinary::FPART_PROP_FILEMODE) sResult = "Mode";
    else if (prop == XBinary::FPART_PROP_USERNAME) sResult = "User";
    else if (prop == XBinary::FPART_PROP_GROUPNAME) sResult = "Group";
    else if (prop == XBinary::FPART_PROP_UID) sResult = "UID";
    else if (prop == XBinary::FPART_PROP_GID) sResult = "GID";
    else if (prop == XBinary::FPART_PROP_LINKNAME) sResult = "Link";
    else if (prop == XBinary::FPART_PROP_INFO) sResult = "Info";
    else if (prop == XBinary::FPART_PROP_ISFOLDER) sResult = "Folder";
    else if (prop == XBinary::FPART_PROP_ISSOLID) sResult = "Solid";
    else if (prop == XBinary::FPART_PROP_SOLIDFOLDERINDEX) sResult = "Solid block";
    else if (prop == XBinary::FPART_PROP_WINDOWSIZE) sResult = "Window size";
    else if (prop == XBinary::FPART_PROP_STREAMOFFSET) sResult = "Stream offset";
    else if (prop == XBinary::FPART_PROP_STREAMSIZE) sResult = "Stream size";
    else if (prop == XBinary::FPART_PROP_STREAMUNPACKEDSIZE) sResult = "Stream unpacked size";
    else if (prop == XBinary::FPART_PROP_SUBSTREAMOFFSET) sResult = "Substream offset";
    else if (prop == XBinary::FPART_PROP_FILEMD5) sResult = "File MD5";
    else if (prop == XBinary::FPART_PROP_FLAGS) sResult = "Flags";
    else if (prop == XBinary::FPART_PROP_TYPE) sResult = "Raw method";
    else if (prop == XBinary::FPART_PROP_COMPRESSPROPERTIES) sResult = "Compress properties";
    else if (prop == XBinary::FPART_PROP_ISREADONLY) sResult = "Read-only";
    else if (prop == XBinary::FPART_PROP_ISHIDDEN) sResult = "Hidden";
    else if (prop == XBinary::FPART_PROP_ISSYSTEM) sResult = "System";
    else if (prop == XBinary::FPART_PROP_ISARCHIVE) sResult = "Archive attribute";
    else if (prop == XBinary::FPART_PROP_ISCOMMENTPRESENT) sResult = "Has comment";
    else if (prop == XBinary::FPART_PROP_ARCHIVE_RECORD_INDEX) sResult = "Archive record index";
    else if (prop == XBinary::FPART_PROP_ARCHIVE_RECORD_TOKEN) sResult = "Archive record token";
    else if (prop == XBinary::FPART_PROP_REPORTEDMETHOD) sResult = "Reported method";
    else if (prop == XBinary::FPART_PROP_HOSTOS) sResult = "Host OS";
    else if (prop == XBinary::FPART_PROP_CHECKSUM) sResult = "Checksum";
    else if (prop == XBinary::FPART_PROP_CHECKSUMTYPE) sResult = "Checksum type";
    else sResult = QString("#%1").arg(static_cast<qint32>(prop));

    return sResult;
}

QString consoleFPartValueString(const XBinary::ARCHIVERECORD &record, XBinary::FPART_PROP prop)
{
    QVariant varValue = record.mapProperties.value(prop);

    if (prop == XBinary::FPART_PROP_HANDLEMETHOD) {
        const QString sMethod = XBinary::getHandleMethods(record.mapProperties);

        if (!sMethod.isEmpty()) {
            return sMethod;
        }
    } else if ((prop == XBinary::FPART_PROP_HANDLEMETHOD2) || (prop == XBinary::FPART_PROP_HANDLEMETHOD3)) {
        QMap<XBinary::FPART_PROP, QVariant> mapOne;
        mapOne.insert(XBinary::FPART_PROP_HANDLEMETHOD, varValue);
        QString sMethod = XBinary::getHandleMethods(mapOne);

        if (!sMethod.isEmpty()) {
            return sMethod;
        }
    }

    if ((prop == XBinary::FPART_PROP_RESULTCRC) || (prop == XBinary::FPART_PROP_UNCOMPRESSEDCRC)) {
        return QString("%1").arg(varValue.toULongLong(), 8, 16, QChar('0')).toUpper();
    }

    if ((prop == XBinary::FPART_PROP_DATETIME) || (prop == XBinary::FPART_PROP_MTIME) || (prop == XBinary::FPART_PROP_CTIME) ||
        (prop == XBinary::FPART_PROP_ATIME)) {
        return varValue.toDateTime().toLocalTime().toString("yyyy-MM-dd hh:mm:ss");
    }

    if (prop == XBinary::FPART_PROP_FILEMODE) {
        return modeToString(varValue.toUInt(), recordIsFolder(record));
    }

    if ((prop == XBinary::FPART_PROP_COMPRESSPROPERTIES) || (prop == XBinary::FPART_PROP_COMPRESSPROPERTIES2)) {
        QByteArray baProps = varValue.toByteArray();
        QString sHex = QString(baProps.toHex());
        XBinary::FPART_PROP methodProp = (prop == XBinary::FPART_PROP_COMPRESSPROPERTIES) ? XBinary::FPART_PROP_HANDLEMETHOD : XBinary::FPART_PROP_HANDLEMETHOD2;
        XBinary::HANDLE_METHOD handleMethod = (XBinary::HANDLE_METHOD)record.mapProperties.value(methodProp).toUInt();
        QString sDecoded = XBinary::getCoderParamsString(handleMethod, baProps);

        if (!sDecoded.isEmpty()) {
            return QString("%1 (%2:%3)").arg(sHex, XBinary::handleMethodToString(handleMethod), sDecoded);
        }

        return sHex;
    }

    if (varValue.userType() == QMetaType::Bool) {
        return varValue.toBool() ? QString("Yes") : QString("No");
    }

    if (varValue.userType() == QMetaType::QByteArray) {
        return QString(varValue.toByteArray().toHex());
    }

    return varValue.toString();
}

QString cellValue(const XBinary::ARCHIVERECORD &record, qint32 nColId)
{
    if (nColId == 0) return recordAttr(record);
    if (nColId == 1) return recordModified(record);
    if (nColId == 2) return recordHasSize(record) ? QString::number(recordSize(record)) : QString();
    if (nColId == 3) return recordPackedString(record);
    if (nColId == 4) return XBinary::getHandleMethods(record.mapProperties);
    if (nColId == 5) return recordCRC(record);
    if (nColId == 7) return recordRatio(record);

    return recordName(record);
}

// Human-readable, aligned archive listing with a format/size summary line and
// (when bVerbose) a full per-record property dump.  Only columns the format
// actually populates are shown, so each archive type surfaces its own metadata.
QString formatArchiveList(XBinary::FT fileType, const QList<XBinary::ARCHIVERECORD> &listRecords, qint64 nPhysicalSize, bool bVerbose)
{
    QString sResult;

    qint32 nNumberOfRecords = listRecords.count();

    qint64 nTotalSize = 0;
    qint64 nTotalPacked = 0;
    qint32 nNumberOfFiles = 0;
    qint32 nNumberOfFolders = 0;
    bool bAnyModified = false;
    bool bAnyMethod = false;
    bool bAnyCRC = false;
    bool bAnyAttr = false;
    bool bAnyRatio = false;
    bool bSolid = false;
    bool bSizeComplete = true;
    bool bPackedComplete = true;
    QSet<qint64> stBlocks;

    // Solid formats report the same shared compressed stream on every member of
    // a block, so count each distinct stream region once for the total and blank
    // the repeated "Packed" cells (7-Zip shows the compressed size on the first
    // member of a folder only).  Only records that actually declare solid-block
    // membership are folded this way: readers that report offset 0 for every
    // member (the 7-Zip source does) would otherwise collapse distinct members
    // of equal size into one and understate the total.
    QStringList listPackedDisplay;
    QSet<QString> stSeenStreams;
    QSet<qint64> stSeenPackedBlocks;
    QSet<qint64> stBlocksWithPackedValue;
    QSet<qint64> stBlocksWithUnknownMembers;
    bool bUnknownPackedWithoutBlock = false;

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        const XBinary::ARCHIVERECORD &record = listRecords.at(i);

        if (recordHasSize(record)) {
            nTotalSize += recordSize(record);
        } else if (!recordIsFolder(record)) {
            bSizeComplete = false;
        }

        if (recordIsFolder(record)) {
            nNumberOfFolders++;
        } else {
            nNumberOfFiles++;
        }

        if (record.mapProperties.value(XBinary::FPART_PROP_ISSOLID).toBool()) {
            bSolid = true;
        }

        if (record.mapProperties.contains(XBinary::FPART_PROP_SOLIDFOLDERINDEX)) {
            stBlocks.insert(record.mapProperties.value(XBinary::FPART_PROP_SOLIDFOLDERINDEX).toLongLong());
        }

        qint64 nPacked = 0;
        PACKEDSTATE packedState = recordPacked(record, &nPacked);
        QString sPackedDisplay;
        const bool bHasBlock = record.mapProperties.contains(XBinary::FPART_PROP_SOLIDFOLDERINDEX);
        const qint64 nBlock = bHasBlock ?
            record.mapProperties.value(XBinary::FPART_PROP_SOLIDFOLDERINDEX).toLongLong() : -1;

        if (packedState == PACKEDSTATE_UNKNOWN) {
            if (bHasBlock) {
                stBlocksWithUnknownMembers.insert(nBlock);
            } else {
                bUnknownPackedWithoutBlock = true;
            }
        } else if (packedState == PACKEDSTATE_VALUE) {
            sPackedDisplay = QString::number(nPacked);

            const bool bDeclaresSolidBlock = record.mapProperties.value(XBinary::FPART_PROP_ISSOLID).toBool() ||
                                             bHasBlock;

            if (bHasBlock) {
                // recordPacked() synthesizes zero for an empty regular file.
                // That is a valid row value, but it is not evidence that the
                // provider supplied this solid folder's packed size.  Only an
                // actual packed-size/stream value can make unknown sibling
                // members complete.
                const bool bProviderPackedValue =
                    record.mapProperties.contains(XBinary::FPART_PROP_COMPRESSEDSIZE) ||
                    (record.nStreamSize > 0);

                if (bProviderPackedValue) {
                    stBlocksWithPackedValue.insert(nBlock);

                    if (stSeenPackedBlocks.contains(nBlock)) {
                        sPackedDisplay.clear();
                    } else {
                        stSeenPackedBlocks.insert(nBlock);
                        nTotalPacked += nPacked;
                    }
                }
            } else if (bDeclaresSolidBlock && (record.nStreamSize > 0)) {
                QString sStreamKey = QString("%1:%2").arg(record.nStreamOffset).arg(record.nStreamSize);

                if (stSeenStreams.contains(sStreamKey)) {
                    sPackedDisplay.clear();  // already counted: this file shares the block
                } else {
                    stSeenStreams.insert(sStreamKey);
                    nTotalPacked += nPacked;
                }
            } else {
                nTotalPacked += nPacked;
            }
        }
        // PACKEDSTATE_NONE (directory): no cell, no contribution, and no reason
        // to call the total incomplete.

        listPackedDisplay.append(sPackedDisplay);

        if (!recordModified(record).isEmpty()) bAnyModified = true;
        if (!XBinary::getHandleMethods(record.mapProperties).isEmpty()) bAnyMethod = true;
        if (!recordCRC(record).isEmpty()) bAnyCRC = true;
        if (recordIsFolder(record) ||
            record.mapProperties.value(XBinary::FPART_PROP_ISREADONLY).toBool() ||
            record.mapProperties.value(XBinary::FPART_PROP_ISHIDDEN).toBool() ||
            record.mapProperties.value(XBinary::FPART_PROP_ISSYSTEM).toBool() ||
            record.mapProperties.value(XBinary::FPART_PROP_ISARCHIVE).toBool() ||
            record.mapProperties.value(XBinary::FPART_PROP_ENCRYPTED).toBool()) bAnyAttr = true;
        if (!recordRatio(record).isEmpty()) bAnyRatio = true;
    }

    // Missing per-member sizes are complete when every such member belongs to
    // a block for which the provider reported one folder-level packed size.
    // This is the kpidPackSize/kpidBlock contract used by solid 7z and RAR.
    if (bUnknownPackedWithoutBlock) {
        bPackedComplete = false;
    }
    for (qint64 nBlock : stBlocksWithUnknownMembers) {
        if (!stBlocksWithPackedValue.contains(nBlock)) {
            bPackedComplete = false;
            break;
        }
    }

    // A packed total can never exceed the bytes that are actually on disk.  If
    // the per-record numbers add up to more than the file itself, they are not
    // this container's packed sizes; report that they are unknown rather than
    // publishing a sum (and a ratio) that the file cannot support.
    if (bPackedComplete && (nPhysicalSize > 0) && (nTotalPacked > nPhysicalSize)) {
        bPackedComplete = false;
    }

    QString sRatio;

    if (bSizeComplete && bPackedComplete && (nTotalSize > 0)) {
        sRatio = QString(" (%1%)").arg(QString::number(double(nTotalPacked) * 100.0 / double(nTotalSize), 'f', 1));
    }

    const QString sSizeSummary = bSizeComplete ?
        XBinary::bytesCountToString(nTotalSize, 1024) : QString("unknown");
    const QString sPackedSummary = bPackedComplete ?
        XBinary::bytesCountToString(nTotalPacked, 1024) : QString("unknown");

    sResult += QString("%1: %2 file(s)%3, %4 -> %5%6\n")
                   .arg(XBinary::fileTypeIdToString(fileType))
                   .arg(nNumberOfFiles)
                   .arg(nNumberOfFolders > 0 ? QString(", %1 folder(s)").arg(nNumberOfFolders) : QString())
                   .arg(sSizeSummary)
                   .arg(sPackedSummary)
                   .arg(sRatio);

    // archive-level info line: on-disk size, metadata overhead, solidity
    QStringList listInfo;

    if (nPhysicalSize > 0) {
        listInfo.append(QString("physical %1").arg(XBinary::bytesCountToString(nPhysicalSize, 1024)));

        qint64 nOverhead = bPackedComplete ? (nPhysicalSize - nTotalPacked) : 0;

        if (nOverhead > 0) {
            listInfo.append(QString("overhead %1").arg(XBinary::bytesCountToString(nOverhead, 1024)));
        }
    }

    if (bSolid) {
        listInfo.append(QString("solid"));

        if (stBlocks.count() > 0) {
            listInfo.append(QString("%1 block(s)").arg(stBlocks.count()));
        }
    }

    if (!listInfo.isEmpty()) {
        sResult += QString("  %1\n").arg(listInfo.join(", "));
    }

    if (bVerbose) {
        for (qint32 i = 0; i < nNumberOfRecords; i++) {
            const XBinary::ARCHIVERECORD &record = listRecords.at(i);

            sResult += QString("\n[%1]\n").arg(recordName(record));

            QList<XBinary::FPART_PROP> listKeys = record.mapProperties.keys();
            std::sort(listKeys.begin(), listKeys.end());

            for (qint32 k = 0; k < listKeys.count(); k++) {
                XBinary::FPART_PROP prop = listKeys.at(k);

                if (prop == XBinary::FPART_PROP_ORIGINALNAME) {
                    continue;
                }

                // An opaque identity digest is bookkeeping between a record and
                // the session that produced it, not something the archive says
                // about this member.  A listing describes the member.
                if (prop == XBinary::FPART_PROP_ARCHIVE_RECORD_TOKEN) {
                    continue;
                }

                // The exact provider text is already rendered as Method via
                // getHandleMethods(); do not print a duplicate verbose field.
                if ((prop == XBinary::FPART_PROP_REPORTEDMETHOD) &&
                    record.mapProperties.contains(XBinary::FPART_PROP_HANDLEMETHOD)) {
                    continue;
                }

                // A stream coordinate describes where a payload lives.  A
                // directory entry has no payload, so no coordinate on any
                // device describes it and none may be shown for it.
                if (recordIsFolder(record) &&
                    ((prop == XBinary::FPART_PROP_STREAMOFFSET) || (prop == XBinary::FPART_PROP_STREAMSIZE) ||
                     (prop == XBinary::FPART_PROP_STREAMUNPACKEDSIZE) || (prop == XBinary::FPART_PROP_SUBSTREAMOFFSET))) {
                    continue;
                }

                // A record that shares the container's single compressed
                // stream has no extent of its own either; printing the shared
                // one per row presents a transport-envelope number as this
                // member's own metadata, which is how "Stream size: <whole
                // container>" ended up on every row of a compressed-tar
                // listing.
                if (((prop == XBinary::FPART_PROP_STREAMOFFSET) || (prop == XBinary::FPART_PROP_STREAMSIZE)) &&
                    recordSharesContainerStream(record)) {
                    continue;
                }

                sResult += QString("  %1: %2\n").arg(consoleFPartName(prop), consoleFPartValueString(record, prop));
            }
        }

        return sResult;
    }

    // choose the columns present for this format (Name/Size/Packed always shown)
    QList<qint32> listColIds;
    QStringList listHeaders;
    QList<bool> listRightAlign;

    if (bAnyAttr) {
        listColIds.append(0);
        listHeaders.append("Attr");
        listRightAlign.append(false);
    }

    if (bAnyModified) {
        listColIds.append(1);
        listHeaders.append("Modified");
        listRightAlign.append(false);
    }

    listColIds.append(2);
    listHeaders.append("Size");
    listRightAlign.append(true);

    listColIds.append(3);
    listHeaders.append("Packed");
    listRightAlign.append(true);

    if (bAnyRatio) {
        listColIds.append(7);
        listHeaders.append("Ratio");
        listRightAlign.append(true);
    }

    if (bAnyMethod) {
        listColIds.append(4);
        listHeaders.append("Method");
        listRightAlign.append(false);
    }

    if (bAnyCRC) {
        listColIds.append(5);
        listHeaders.append("Checksum");
        listRightAlign.append(false);
    }

    listColIds.append(6);
    listHeaders.append("Name");
    listRightAlign.append(false);

    qint32 nNumberOfColumns = listColIds.count();

    QVector<qint32> vWidths(nNumberOfColumns);

    for (qint32 c = 0; c < nNumberOfColumns; c++) {
        vWidths[c] = listHeaders.at(c).length();
    }

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        for (qint32 c = 0; c < nNumberOfColumns; c++) {
            qint32 nColId = listColIds.at(c);
            QString sCell = (nColId == 3) ? listPackedDisplay.at(i) : cellValue(listRecords.at(i), nColId);
            qint32 nLength = sCell.length();

            if (nLength > vWidths[c]) {
                vWidths[c] = nLength;
            }
        }
    }

    QString sHeader;
    QString sSeparator;

    for (qint32 c = 0; c < nNumberOfColumns; c++) {
        if (c > 0) {
            sHeader += "  ";
            sSeparator += "  ";
        }

        bool bLastColumn = (c == (nNumberOfColumns - 1));

        if (listRightAlign.at(c)) {
            sHeader += listHeaders.at(c).rightJustified(vWidths[c], QChar(' '));
        } else if (bLastColumn) {
            sHeader += listHeaders.at(c);
        } else {
            sHeader += listHeaders.at(c).leftJustified(vWidths[c], QChar(' '));
        }

        sSeparator += QString(vWidths[c], QChar('-'));
    }

    sResult += sHeader + "\n";
    sResult += sSeparator + "\n";

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        QString sRow;

        for (qint32 c = 0; c < nNumberOfColumns; c++) {
            if (c > 0) {
                sRow += "  ";
            }

            qint32 nColId = listColIds.at(c);
            QString sCell = (nColId == 3) ? listPackedDisplay.at(i) : cellValue(listRecords.at(i), nColId);
            bool bLastColumn = (c == (nNumberOfColumns - 1));

            if (listRightAlign.at(c)) {
                sRow += sCell.rightJustified(vWidths[c], QChar(' '));
            } else if (bLastColumn) {
                sRow += sCell;
            } else {
                sRow += sCell.leftJustified(vWidths[c], QChar(' '));
            }
        }

        sResult += sRow + "\n";
    }

    return sResult;
}

}  // namespace

XScanEngineConsole::XScanEngineConsole(QCoreApplication &app, XScanEngine &scanEngine, const QString &sDescription, QObject *pParent)
    : QObject(pParent), m_app(app), m_scanEngine(scanEngine), m_sDescription(sDescription)
{
}

XScanEngine *XScanEngineConsole::scanEngine()
{
    return &m_scanEngine;
}

void XScanEngineConsole::addEngineOptions(QCommandLineParser *pParser)
{
    Q_UNUSED(pParser)
}

void XScanEngineConsole::applyEngineOptions(const QCommandLineParser *pParser, XScanEngine::SCAN_OPTIONS *pScanOptions)
{
    Q_UNUSED(pParser)
    Q_UNUSED(pScanOptions)
}

bool XScanEngineConsole::processEngineModes(const QCommandLineParser *pParser, const QStringList &listArgs, XScanEngine::SCAN_OPTIONS *pScanOptions,
                                            XBinary::PDSTRUCT *pPdStruct, qint32 *pnResult)
{
    Q_UNUSED(pParser)
    Q_UNUSED(listArgs)
    Q_UNUSED(pScanOptions)
    Q_UNUSED(pPdStruct)
    Q_UNUSED(pnResult)

    return false;
}

XOptions::CR XScanEngineConsole::reportScanErrors(XScanEngine::SCAN_RESULT *pScanResult)
{
    printf("%s", XScanEngine::getErrorsString(pScanResult).toUtf8().data());

    return XOptions::CR_CANNOTOPENFILE;
}

XOptions::CR XScanEngineConsole::showDatabaseState(XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    XScanEngine::DATABASE_STATE dataBaseState = m_scanEngine.getDatabaseState(pScanOptions);

    QString sResult;

    if (pScanOptions->bResultAsJSON) {
        sResult = XScanEngine::databaseStateToJson(dataBaseState);
    } else if (pScanOptions->bResultAsXML) {
        sResult = XScanEngine::databaseStateToXml(dataBaseState);
    } else if (pScanOptions->bResultAsCSV) {
        sResult = XScanEngine::databaseStateToCSV(dataBaseState);
    } else if (pScanOptions->bResultAsTSV) {
        sResult = XScanEngine::databaseStateToTSV(dataBaseState);
    } else {
        sResult = XScanEngine::databaseStateToText(dataBaseState);
    }

    printf("%s", sResult.toUtf8().data());

    return XOptions::CR_SUCCESS;
}

XOptions::CR XScanEngineConsole::showStructsOverview(const QStringList &listArgs, XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XOptions::CR result = XOptions::CR_SUCCESS;

    if (!listArgs.isEmpty()) {
        XBinary::FT fileType = pScanOptions->fileType;

        QFile file;

        file.setFileName(listArgs.at(0));

        if (file.open(QIODevice::ReadOnly)) {
            if (fileType == XBinary::FT_UNKNOWN) {
                fileType = XFormats::getPrefFileType(&file, XBinary::FT_FLAG_FORMATS, pPdStruct);
            }

            XBinary *pBinary = XFormats::createClass(fileType, &file);

            if (pBinary) {
                QList<XBinary::XFHEADER> listHeaders = pBinary->_getXFHeaders(pPdStruct);
                XBinary::INDATA inData = XFormats::createINDATA(fileType, &file);

                XFTreeModel treeModel(nullptr);
                treeModel.setData(inData, listHeaders);

                QString sStructs;

                if (pScanOptions->bResultAsJSON) {
                    sStructs = treeModel.toJSON();
                } else if (pScanOptions->bResultAsXML) {
                    sStructs = treeModel.toXML();
                } else if (pScanOptions->bResultAsCSV) {
                    sStructs = treeModel.toCSV();
                } else if (pScanOptions->bResultAsTSV) {
                    sStructs = treeModel.toTSV();
                } else {
                    sStructs = treeModel.toFormattedString();
                }

                printf("%s", sStructs.toUtf8().data());

                delete pBinary;
            } else {
                printf("Cannot read structures: %s\n", listArgs.at(0).toUtf8().data());
                result = XOptions::CR_CANNOTOPENFILE;
            }

            file.close();
        } else {
            printf("Cannot open: %s\n", listArgs.at(0).toUtf8().data());
            result = XOptions::CR_CANNOTOPENFILE;
        }
    } else {
        printf("Error: --showstructs requires <target>\n");
        result = XOptions::CR_INVALIDPARAMETER;
    }

    return result;
}

XOptions::CR XScanEngineConsole::showFileEntropy(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XOptions::CR result = XOptions::CR_SUCCESS;

    QFile file;
    file.setFileName(sFileName);

    if (file.open(QIODevice::ReadOnly)) {
        QVector<XBinary::KeyValueItem> listItems = XFormats::getEntropy(&file, false, -1, pPdStruct);

        QString sResult;
        if (pScanOptions->bResultAsJSON) sResult = XFormats::toJSON(listItems);
        else if (pScanOptions->bResultAsXML) sResult = XFormats::toXML(listItems);
        else if (pScanOptions->bResultAsCSV) sResult = XFormats::toCSV(listItems);
        else if (pScanOptions->bResultAsTSV) sResult = XFormats::toTSV(listItems);
        else sResult = XFormats::toFormattedString(listItems);

        printf("%s", sResult.toUtf8().data());
        file.close();
    } else {
        printf("Cannot open: %s\n", sFileName.toUtf8().data());
        result = XOptions::CR_CANNOTOPENFILE;
    }

    return result;
}

XOptions::CR XScanEngineConsole::showFileInfo(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XOptions::CR result = XOptions::CR_SUCCESS;

    QFile file;
    file.setFileName(sFileName);

    if (file.open(QIODevice::ReadOnly)) {
        QVector<XBinary::KeyValueItem> listItems = XFormats::getFileInfo(&file, false, -1, pPdStruct, pScanOptions->fileType);

        QString sResult;
        if (pScanOptions->bResultAsJSON) sResult = XFormats::toJSON(listItems);
        else if (pScanOptions->bResultAsXML) sResult = XFormats::toXML(listItems);
        else if (pScanOptions->bResultAsCSV) sResult = XFormats::toCSV(listItems);
        else if (pScanOptions->bResultAsTSV) sResult = XFormats::toTSV(listItems);
        else sResult = XFormats::toFormattedString(listItems);

        printf("%s", sResult.toUtf8().data());
        file.close();
    } else {
        printf("Cannot open: %s\n", sFileName.toUtf8().data());
        result = XOptions::CR_CANNOTOPENFILE;
    }

    return result;
}

XOptions::CR XScanEngineConsole::showFileStruct(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pScanOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XOptions::CR result = XOptions::CR_SUCCESS;

    QFile file;

    file.setFileName(sFileName);

    if (file.open(QIODevice::ReadOnly)) {
        XBinary::XFHEADER xFHeader = XFormats::getXFHeaderFromStructName(&file, pScanOptions->sStruct, false, -1, pPdStruct);

        if (xFHeader.xfType != XBinary::XFTYPE_UNKNOWN) {
            XBinary *pBinary = XFormats::createClass(xFHeader.fileType, &file);

            if (pBinary) {
                QString sStructInfo;
                XBinary::INDATA inData = XFormats::createINDATA(xFHeader.fileType, &file);

                if (xFHeader.xfType == XBinary::XFTYPE_HEADER) {
                    XFModel_header modelHeader(nullptr);
                    modelHeader.setData(inData, xFHeader);

                    if (pScanOptions->bResultAsJSON) {
                        sStructInfo = modelHeader.toJSON();
                    } else if (pScanOptions->bResultAsXML) {
                        sStructInfo = modelHeader.toXML();
                    } else if (pScanOptions->bResultAsCSV) {
                        sStructInfo = XFModel::exportToString(&modelHeader, XFModel::EXPORT_CSV);
                    } else if (pScanOptions->bResultAsTSV) {
                        sStructInfo = XFModel::exportToString(&modelHeader, XFModel::EXPORT_TSV);
                    } else {
                        XOptions::printModel(&modelHeader);
                    }
                } else if (xFHeader.xfType == XBinary::XFTYPE_TABLE) {
                    XFModel_table modelTable;
                    modelTable.setData(inData, xFHeader);
                    modelTable.setShowPresentation(true);

                    if (pScanOptions->bResultAsJSON) {
                        sStructInfo = modelTable.toJSON();
                    } else if (pScanOptions->bResultAsXML) {
                        sStructInfo = modelTable.toXML();
                    } else if (pScanOptions->bResultAsCSV) {
                        sStructInfo = XFModel::exportToString(&modelTable, XFModel::EXPORT_CSV);
                    } else if (pScanOptions->bResultAsTSV) {
                        sStructInfo = XFModel::exportToString(&modelTable, XFModel::EXPORT_TSV);
                    } else {
                        XOptions::printModel(&modelTable);
                    }
                }

                if (!sStructInfo.isEmpty()) {
                    printf("%s", sStructInfo.toUtf8().data());
                }

                delete pBinary;
            } else {
                printf("Cannot read structure: %s\n", sFileName.toUtf8().data());
                result = XOptions::CR_CANNOTOPENFILE;
            }
        } else {
            printf("Cannot find struct '%s': %s\n", pScanOptions->sStruct.toUtf8().data(), sFileName.toUtf8().data());
            result = XOptions::CR_INVALIDPARAMETER;
        }

        file.close();
    } else {
        printf("Cannot open: %s\n", sFileName.toUtf8().data());
        result = XOptions::CR_CANNOTOPENFILE;
    }

    return result;
}

int XScanEngineConsole::process()
{
    qint32 nResult = XOptions::CR_SUCCESS;

    // Text codecs (e.g. cp437 for DOS-era strings) are used by the format
    // parsers; register them once for every console front end.
    XOptions::registerCodecs();

    XBinary::PDSTRUCT pdStruct = XBinary::createPdStruct();

    QCommandLineParser parser;
    parser.setApplicationDescription(m_sDescription);
    parser.addHelpOption();
    parser.addVersionOption();

    parser.addPositionalArgument("target", "The file or directory to open.");

    XScanEngine::SCANENGINETYPE engineType = m_scanEngine.getEngineType();
    bool bHasMainDb = (engineType != XScanEngine::SCANENGINETYPE_NFD);
    bool bIsDatabaseUsing = m_scanEngine.isDatabaseUsing();
    bool bHasExtraCustomDb = (engineType == XScanEngine::SCANENGINETYPE_DIE);

    QCommandLineOption clRecursiveScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_RECURSIVESCAN);
    QCommandLineOption clDeepScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_DEEPSCAN);
    QCommandLineOption clHeuristicScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_HEURISTICSCAN);
    QCommandLineOption clVerbose = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_VERBOSE);
    QCommandLineOption clAggresiveScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_AGGRESSIVESCAN);
    QCommandLineOption clResourcesScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_RESOURCESSCAN);
    QCommandLineOption clArchivesScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_ARCHIVESSCAN);
    QCommandLineOption clOverlayScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_OVERLAYSCAN);
    QCommandLineOption clAllTypesScan = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_ALLTYPES);

    QCommandLineOption clProfiling = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_PROFILING);
    QCommandLineOption clMessages = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_MESSAGES);
    QCommandLineOption clHideUnknown = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_HIDEUNKNOWN);

    QCommandLineOption clEntropy = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_ENTROPY);
    QCommandLineOption clInfo = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_INFO);

    QCommandLineOption clResultAsXml = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_XML);
    QCommandLineOption clResultAsJson = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_JSON);
    QCommandLineOption clResultAsCSV = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_CSV);
    QCommandLineOption clResultAsTSV = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_TSV);
    QCommandLineOption clResultAsPlainText = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_PLAINTEXT);

    QCommandLineOption clDatabaseMain = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_DATABASE);
    QCommandLineOption clDatabaseCustom = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_CUSTOMDATABASE);
    QCommandLineOption clShowDatabase = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_SHOWDATABASE);

    QCommandLineOption clStruct = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_STRUCT);
    QCommandLineOption clShowStructs = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_SHOWSTRUCTS);
    QCommandLineOption clListArchive = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_LISTARCHIVE);
    QCommandLineOption clExtractArchive = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_EXTRACTARCHIVE);
    QCommandLineOption clArchivePassword(QStringList() << QStringLiteral("password"),
                                         QStringLiteral("Archive password (use --password-stdin to read it from standard input instead)."),
                                         QStringLiteral("password"));
    QCommandLineOption clArchivePasswordStdin(QStringList() << QStringLiteral("password-stdin"),
                                               QStringLiteral("Read the archive password as one UTF-8 line from standard input."));
    QCommandLineOption clArchivePasswordHex(QStringList() << QStringLiteral("password-hex"),
                                             QStringLiteral("Exact legacy archive password bytes as hexadecimal."),
                                             QStringLiteral("hex"));
    QCommandLineOption clArchiveCodePage(QStringList() << QStringLiteral("codepage"),
                                         QStringLiteral("Windows code page for legacy archive filenames and password bytes."),
                                         QStringLiteral("number"));

    QCommandLineOption clFileType = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_FILETYPE);
    QCommandLineOption clFirstWrapperOnly = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_FIRSTWRAPPERONLY);
    QCommandLineOption clNoColor = XOptions::getCommandLineOption(XOptions::CONSOLE_OPTION_ID_NOCOLOR);

    parser.addOption(clRecursiveScan);
    parser.addOption(clDeepScan);
    parser.addOption(clHeuristicScan);
    parser.addOption(clVerbose);
    parser.addOption(clAggresiveScan);
    parser.addOption(clAllTypesScan);
    parser.addOption(clProfiling);
    parser.addOption(clMessages);
    parser.addOption(clHideUnknown);
    parser.addOption(clEntropy);
    parser.addOption(clInfo);
    parser.addOption(clStruct);
    parser.addOption(clResultAsXml);
    parser.addOption(clResultAsJson);
    parser.addOption(clResultAsCSV);
    parser.addOption(clResultAsTSV);
    parser.addOption(clResultAsPlainText);
    if (bHasMainDb) {
        parser.addOption(clDatabaseMain);
        parser.addOption(clShowDatabase);
    }
    if (bHasExtraCustomDb) {
        parser.addOption(clDatabaseCustom);
    }
    parser.addOption(clOverlayScan);
    parser.addOption(clResourcesScan);
    parser.addOption(clArchivesScan);
    parser.addOption(clFileType);
    parser.addOption(clFirstWrapperOnly);
    parser.addOption(clShowStructs);
    parser.addOption(clListArchive);
    parser.addOption(clExtractArchive);
    parser.addOption(clArchivePassword);
    parser.addOption(clArchivePasswordStdin);
    parser.addOption(clArchivePasswordHex);
    parser.addOption(clArchiveCodePage);
    parser.addOption(clNoColor);

    addEngineOptions(&parser);

    parser.process(m_app);

    QStringList listArgs = parser.positionalArguments();

    qint32 nNumberOfResultFormats = 0;
    nNumberOfResultFormats += parser.isSet(clResultAsXml);
    nNumberOfResultFormats += parser.isSet(clResultAsJson);
    nNumberOfResultFormats += parser.isSet(clResultAsCSV);
    nNumberOfResultFormats += parser.isSet(clResultAsTSV);
    nNumberOfResultFormats += parser.isSet(clResultAsPlainText);

    if (nNumberOfResultFormats > 1) {
        printf("Error: select only one result format\n");
        return XOptions::CR_INVALIDPARAMETER;
    }

    XScanEngine::SCAN_OPTIONS scanOptions = {};

    scanOptions.bUseCustomDatabase = (engineType == XScanEngine::SCANENGINETYPE_DIE);
    scanOptions.bShowType = true;
    scanOptions.bShowInfo = true;
    scanOptions.bShowVersion = true;
    scanOptions.bFormatResult = true;
    scanOptions.bIsRecursiveScan = parser.isSet(clRecursiveScan);
    scanOptions.bIsDeepScan = parser.isSet(clDeepScan);
    scanOptions.bIsHeuristicScan = parser.isSet(clHeuristicScan);
    scanOptions.bIsVerbose = parser.isSet(clVerbose);
    scanOptions.bIsAggressiveScan = parser.isSet(clAggresiveScan);
    scanOptions.bIsOverlayScan = parser.isSet(clOverlayScan);
    scanOptions.bIsResourcesScan = parser.isSet(clResourcesScan);
    scanOptions.bIsArchivesScan = parser.isSet(clArchivesScan);
    scanOptions.bIsAllTypesScan = parser.isSet(clAllTypesScan);
    scanOptions.bIsFirstWrapperScan = parser.isSet(clFirstWrapperOnly);
    scanOptions.bHideUnknown = parser.isSet(clHideUnknown);
    scanOptions.bLogProfiling = parser.isSet(clProfiling);
    scanOptions.bShowEntropy = parser.isSet(clEntropy);
    scanOptions.bShowFileInfo = parser.isSet(clInfo);
    scanOptions.bResultAsXML = parser.isSet(clResultAsXml);
    scanOptions.bResultAsJSON = parser.isSet(clResultAsJson);
    scanOptions.bResultAsCSV = parser.isSet(clResultAsCSV);
    scanOptions.bResultAsTSV = parser.isSet(clResultAsTSV);
    scanOptions.bResultAsPlainText = parser.isSet(clResultAsPlainText);
    scanOptions.bIsSort = true;
    scanOptions.fileType = parser.isSet(clFileType) ? XBinary::ftStringToFileTypeId(parser.value(clFileType)) : XBinary::FT_UNKNOWN;

    if (parser.isSet(clNoColor)) {
        XOptions::setNoColor(true);
    }

    scanOptions.sStruct = parser.value(clStruct);

    QMap<XBinary::UNPACK_PROP, QVariant> mapUnpackProperties;
    QString sArchivePassword;
    const qint32 nPasswordOptions = qint32(parser.isSet(clArchivePassword)) +
                                    qint32(parser.isSet(clArchivePasswordStdin)) +
                                    qint32(parser.isSet(clArchivePasswordHex));
    if (nPasswordOptions > 1) {
        printf("Error: use only one of --password, --password-stdin, or --password-hex\n");
        return XOptions::CR_INVALIDPARAMETER;
    }
    if (parser.isSet(clArchivePasswordStdin)) {
        QFile passwordInput;
        if (!passwordInput.open(stdin, QIODevice::ReadOnly, QFileDevice::DontCloseHandle)) {
            printf("Error: cannot read archive password from standard input\n");
            return XOptions::CR_INVALIDPARAMETER;
        }
        QByteArray baPassword = passwordInput.readLine(1024 * 1024);
        if (!baPassword.endsWith('\n') && !passwordInput.atEnd()) {
            printf("Error: archive password is too long\n");
            return XOptions::CR_INVALIDPARAMETER;
        }
        if (baPassword.endsWith('\n')) baPassword.chop(1);
        if (baPassword.endsWith('\r')) baPassword.chop(1);
        sArchivePassword = QString::fromUtf8(baPassword);
    } else if (parser.isSet(clArchivePassword)) {
        sArchivePassword = parser.value(clArchivePassword);
    }
    if (!sArchivePassword.isEmpty()) {
        mapUnpackProperties.insert(XBinary::UNPACK_PROP_PASSWORD, sArchivePassword);
    }
    if (parser.isSet(clArchivePasswordHex)) {
        const QByteArray baHex = parser.value(clArchivePasswordHex).toLatin1();
        bool bHexValid = !baHex.isEmpty() && ((baHex.size() & 1) == 0) &&
                         (baHex.size() <= 2 * 1024 * 1024);
        for (char ch : baHex) {
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                  (ch >= 'A' && ch <= 'F'))) {
                bHexValid = false;
                break;
            }
        }
        if (!bHexValid) {
            printf("Error: --password-hex requires an even, non-empty hexadecimal byte string\n");
            return XOptions::CR_INVALIDPARAMETER;
        }
        mapUnpackProperties.insert(XBinary::UNPACK_PROP_PASSWORD_BYTES,
                                   QByteArray::fromHex(baHex));
    }
    if (parser.isSet(clArchiveCodePage)) {
        bool bCodePageValid = false;
        const quint32 nCodePage = parser.value(clArchiveCodePage).toUInt(&bCodePageValid);
        if (!bCodePageValid || (nCodePage == 0)) {
            printf("Error: --codepage requires a non-zero numeric Windows code page\n");
            return XOptions::CR_INVALIDPARAMETER;
        }
        mapUnpackProperties.insert(XBinary::UNPACK_PROP_CODEPAGE, nCodePage);
    }

    applyEngineOptions(&parser, &scanOptions);

    if (bHasMainDb) {
        scanOptions.sMainDatabasePath = parser.value(clDatabaseMain);
    }
    if (bHasExtraCustomDb) {
        scanOptions.sCustomDatabasePath = parser.value(clDatabaseCustom);
    }

    if (scanOptions.sMainDatabasePath.isEmpty()) {
        if (engineType == XScanEngine::SCANENGINETYPE_PEID) {
            scanOptions.sMainDatabasePath = "$data/peid";
        } else if (engineType == XScanEngine::SCANENGINETYPE_YARA) {
            scanOptions.sMainDatabasePath = "$data/yara";
        } else {
            scanOptions.sMainDatabasePath = "$data/db";
        }
    }

    if (bHasExtraCustomDb) {
        if (scanOptions.sCustomDatabasePath.isEmpty()) {
            scanOptions.sCustomDatabasePath = "$data/db_custom";
        }
    }

    XConsoleOutput consoleOutput;

    if (parser.isSet(clMessages)) {
        QObject::connect(&m_scanEngine, SIGNAL(errorMessage(QString)), &consoleOutput, SLOT(errorMessage(QString)));
        QObject::connect(&m_scanEngine, SIGNAL(warningMessage(QString)), &consoleOutput, SLOT(warningMessage(QString)));
        QObject::connect(&m_scanEngine, SIGNAL(infoMessage(QString)), &consoleOutput, SLOT(infoMessage(QString)));
    }

    bool bIsDbUsed = false;
    bool bDbLoaded = false;
    bool bProcessed = false;

    if (bHasMainDb && parser.isSet(clShowDatabase)) {
        if (!bIsDbUsed) {
            bDbLoaded = m_scanEngine.loadDatabase(&scanOptions, &pdStruct);
            bIsDbUsed = true;
        }

        XOptions::CR crDatabase = showDatabaseState(&scanOptions, &pdStruct);

        if (crDatabase != XOptions::CR_SUCCESS) {
            nResult = crDatabase;
        }

        bProcessed = true;
    }

    if (parser.isSet(clListArchive)) {
        if (!listArgs.isEmpty()) {
            bool bShowFileName = (listArgs.count() > 1);

            for (const QString &sFileName : listArgs) {
                if (!QFileInfo::exists(sFileName)) {
                    printf("Cannot find: %s\n", sFileName.toUtf8().data());
                    nResult = XOptions::CR_CANNOTFINDFILE;
                    continue;
                }

                if (bShowFileName) {
                    printf("%s:\n", QDir().toNativeSeparators(sFileName).toUtf8().data());
                }

                QFile file;
                file.setFileName(sFileName);

                if (!file.open(QIODevice::ReadOnly)) {
                    printf("Cannot open: %s\n", sFileName.toUtf8().data());
                    nResult = XOptions::CR_CANNOTOPENFILE;
                    continue;
                }

                XBinary::FT fileType = scanOptions.fileType;

                if (!XFormats::isStaticUnpacker(fileType)) {
                    // A preliminary scan commonly reports a generic PE type. Probe the executable
                    // for a specific packer/installer before sending it to the archive backends.
                    const XBinary::FT ftStatic = XFormats::getPrefFileType(
                        &file, XBinary::FT_FLAG_EXECUTABLES | XBinary::FT_FLAG_STATICUNPACKERS, &pdStruct);

                    if (XFormats::isStaticUnpacker(ftStatic)) {
                        fileType = ftStatic;
                    } else if (fileType == XBinary::FT_UNKNOWN) {
                        // Only re-probe for an archive type when the user did not
                        // force one with -F.  Without this guard an explicit
                        // --filetype (e.g. UDF on a bridge disc that, by definition,
                        // also carries an ISO 9660 descriptor) is silently overwritten
                        // by auto-detection.  This mirrors the FT_UNKNOWN guard the
                        // --extractarchive path already applies to the same re-probe.
                        const XBinary::FT ftArchive = XFormats::getPrefFileType(
                            &file, XBinary::FT_FLAG_ARCHIVES | XBinary::FT_FLAG_STATICUNPACKERS, &pdStruct);

                        if (XFormats::isStaticUnpacker(ftArchive) ||
                            XArchives::getArchiveOpenValidFileTypes().contains(ftArchive)) {
                            fileType = ftArchive;
                        }
                    }
                }

                QList<XBinary::ARCHIVERECORD> listRecords;
                QString sSevenZipError;
                bool bTerminalSourceFailure = false;
                bool bListed = false;
                XBinary *pArchive = nullptr;

                if (XFormats::isStaticUnpacker(fileType)) {
                    // Installers/packers are enumerated through the shared XBinary streaming API
                    // (initUnpack/infoCurrent/moveToNext), not the XArchive container readers.
                    pArchive = XFormats::createClass(fileType, &file);
                    if (pArchive) {
                        bool bStaticComplete = false;
                        listRecords = collectArchiveRecords(pArchive, mapUnpackProperties, &pdStruct, &bStaticComplete);
                        bListed = bStaticComplete;
                    }
                } else {
                    bListed = listWithIp7zSource(fileType, &file, sFileName, sArchivePassword, &listRecords,
                                                 &sSevenZipError, &pdStruct, &bTerminalSourceFailure);
                    if (bListed && (fileType == XBinary::FT_UNKNOWN)) {
                        fileType = XBinary::FT_ARCHIVE;
                    }

                    // Password, corruption, cancellation, resource-limit, and
                    // safety failures from the compiled-source reader are
                    // authoritative. Its unsupported-format result permits the
                    // native reader to try the same input.
                    if (!bListed && !bTerminalSourceFailure && XFormats::isArchive(fileType)) {
                        pArchive = XFormats::createClass(fileType, &file);
                        if (pArchive) {
                            bool bNativeComplete = false;
                            listRecords = collectArchiveRecords(pArchive, mapUnpackProperties, &pdStruct, &bNativeComplete);
                            bListed = bNativeComplete;
                        }
                    }
                }

                const qint64 nPhysicalSize = file.size();

                if (bListed) {
                    QString sListing = formatArchiveList(fileType, listRecords, nPhysicalSize, parser.isSet(clVerbose));
                    printf("%s", sListing.toUtf8().data());
                } else {
                    printf("Cannot open archive: %s\n", sFileName.toUtf8().data());
                    if (parser.isSet(clVerbose) && !sSevenZipError.isEmpty()) {
                        printf("  7-Zip: %s\n", sSevenZipError.toUtf8().data());
                    }
                    nResult = XOptions::CR_CANNOTOPENFILE;
                }

                delete pArchive;
                file.close();
            }
        } else {
            printf("Error: --listarchive requires <target>\n");
            nResult = XOptions::CR_INVALIDPARAMETER;
        }

        bProcessed = true;
    }

    if (parser.isSet(clExtractArchive)) {
        QString sResultDirectory = parser.value(clExtractArchive);

        if (sResultDirectory.isEmpty() || listArgs.isEmpty()) {
            printf("Error: --extractarchive requires <directory> <target>\n");
            nResult = XOptions::CR_INVALIDPARAMETER;
        } else if (!QDir().mkpath(sResultDirectory)) {
            printf("Cannot create directory: %s\n", sResultDirectory.toUtf8().data());
            nResult = XOptions::CR_INVALIDPARAMETER;
        } else {
            for (const QString &sFileName : listArgs) {
                if (!QFileInfo::exists(sFileName)) {
                    printf("Cannot find: %s\n", sFileName.toUtf8().data());
                    nResult = XOptions::CR_CANNOTFINDFILE;
                    continue;
                }

                QFile file;
                file.setFileName(sFileName);

                if (!file.open(QIODevice::ReadOnly)) {
                    printf("Cannot open: %s\n", sFileName.toUtf8().data());
                    nResult = XOptions::CR_CANNOTOPENFILE;
                    continue;
                }

                XBinary::FT fileType = scanOptions.fileType;

                if (!XFormats::isStaticUnpacker(fileType)) {
                    const XBinary::FT staticType = XFormats::getPrefFileType(
                        &file,
                        XBinary::FT_FLAG_EXECUTABLES |
                            XBinary::FT_FLAG_STATICUNPACKERS,
                        &pdStruct);
                    if (XFormats::isStaticUnpacker(staticType)) {
                        fileType = staticType;
                    } else if (fileType == XBinary::FT_UNKNOWN) {
                        fileType = XFormats::getPrefFileType(
                            &file, XBinary::FT_FLAG_ARCHIVES, &pdStruct);
                    }
                }

                qint32 nNumberOfFiles = 0;
                qint64 nTotalSize = 0;
                bool bTotalSizeComplete = true;
                QList<XBinary::ARCHIVERECORD> listRecords;
                QString sSevenZipError;
                bool bTerminalSourceFailure = false;
                bool bListed = false;
                XBinary *pArchive = nullptr;

                if (XFormats::isStaticUnpacker(fileType)) {
                    pArchive = XFormats::createClass(fileType, &file);
                    if (pArchive) {
                        bool bComplete = false;
                        listRecords = collectArchiveRecords(
                            pArchive, mapUnpackProperties, &pdStruct,
                            &bComplete);
                        bListed = bComplete;
                    }
                } else {
                    bListed = listWithIp7zSource(
                        fileType, &file, sFileName, sArchivePassword,
                        &listRecords, &sSevenZipError, &pdStruct,
                        &bTerminalSourceFailure);

                    if (!bListed && !bTerminalSourceFailure &&
                        XFormats::isArchive(fileType)) {
                        pArchive = XFormats::createClass(fileType, &file);
                        if (pArchive) {
                            bool bComplete = false;
                            listRecords = collectArchiveRecords(
                                pArchive, mapUnpackProperties, &pdStruct,
                                &bComplete);
                            bListed = bComplete;
                        }
                    }
                }

                for (qint32 i = 0; i < listRecords.count(); i++) {
                    if (!recordIsFolder(listRecords.at(i))) {
                        nNumberOfFiles++;
                        if (recordHasSize(listRecords.at(i))) {
                            nTotalSize += recordSize(listRecords.at(i));
                        } else {
                            bTotalSizeComplete = false;
                        }

                        if (parser.isSet(clVerbose)) {
                            printf("  %s\n", recordName(listRecords.at(i)).toUtf8().data());
                        }
                    }
                }

                delete pArchive;
                file.close();

                XBinary::setPdStructErrorString(&pdStruct, QString());
                const bool bExtracted = XArchives::decompressToFolder(sFileName, sResultDirectory, mapUnpackProperties, &pdStruct);

                if (bExtracted) {
                    const QString sTotalSize = bTotalSizeComplete ? XBinary::bytesCountToString(nTotalSize, 1024) : QString("unknown");
                    printf("Extracted %d file(s), %s -> %s\n", nNumberOfFiles, sTotalSize.toUtf8().data(),
                           QDir().toNativeSeparators(sResultDirectory).toUtf8().data());
                } else {
                    printf("Cannot extract: %s\n", sFileName.toUtf8().data());
                    QString sExtractionError = XBinary::getPdStructErrorString(&pdStruct);
                    if (sExtractionError.isEmpty()) {
                        sExtractionError = sSevenZipError;
                    }
                    if (parser.isSet(clVerbose) && !sExtractionError.isEmpty()) {
                        printf("  %s\n", sExtractionError.toUtf8().data());
                    }
                    nResult = XOptions::CR_CANNOTOPENFILE;
                }
            }
        }

        bProcessed = true;
    }

    if (parser.isSet(clShowStructs)) {
        XOptions::CR crStructs = showStructsOverview(listArgs, &scanOptions, &pdStruct);

        if (crStructs != XOptions::CR_SUCCESS) {
            nResult = crStructs;
        }

        bProcessed = true;
    }

    if (!bProcessed) {
        if (processEngineModes(&parser, listArgs, &scanOptions, &pdStruct, &nResult)) {
            bProcessed = true;
        }
    }

    if (!bProcessed && !scanOptions.sStruct.isEmpty() && listArgs.isEmpty()) {
        printf("Error: --struct requires <target>\n");
        nResult = XOptions::CR_INVALIDPARAMETER;
        bProcessed = true;
    }

    if (!bProcessed && listArgs.count()) {
        // The signature database is only needed for actual scanning; entropy,
        // file info and structure dumps must work without one.
        bool bNeedDatabase = bIsDatabaseUsing && (!(scanOptions.bShowEntropy || scanOptions.bShowFileInfo || (scanOptions.sStruct != "")));

        if (bNeedDatabase && !bIsDbUsed) {
            bDbLoaded = m_scanEngine.loadDatabase(&scanOptions, &pdStruct);
            bIsDbUsed = true;
        }

        if ((!bNeedDatabase) || bDbLoaded) {
            nResult = handleFiles(listArgs, &scanOptions, m_scanEngine, &pdStruct);
        } else {
            printf("Cannot load database: %s\n", scanOptions.sMainDatabasePath.toUtf8().data());
        }

        bProcessed = true;
    }

    if (!bProcessed) {
        parser.showHelp();
        Q_UNREACHABLE();
    }

    if (bIsDbUsed && (!bDbLoaded)) {
        nResult = XOptions::CR_CANNOTFINDDATABASE;
    }

    return nResult;
}

XOptions::CR XScanEngineConsole::handleFiles(const QStringList &listArgs, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine &scanEngine, XBinary::PDSTRUCT *pPdStruct)
{
    XOptions::CR result = XOptions::CR_SUCCESS;

    QStringList listFileNames;

    for (const QString &sFileName : listArgs) {
        if (QFileInfo::exists(sFileName)) {
            XBinary::findFiles(sFileName, &listFileNames, pPdStruct);
        } else {
            printf("Cannot find: %s\n", sFileName.toUtf8().data());

            result = XOptions::CR_CANNOTFINDFILE;
        }
    }

    bool bShowFileName = listFileNames.count() > 1;

    qint32 nNumberOfFiles = listFileNames.count();

    for (qint32 i = 0; i < nNumberOfFiles; i++) {
        QString sFileName = listFileNames.at(i);

        if (bShowFileName) {
            printf("%s:\n", QDir().toNativeSeparators(sFileName).toUtf8().data());
        }

        if (pScanOptions->bShowEntropy) {
            XOptions::CR crFile = showFileEntropy(sFileName, pScanOptions, pPdStruct);

            if (crFile != XOptions::CR_SUCCESS) {
                result = crFile;
            }
        } else if (pScanOptions->bShowFileInfo) {
            XOptions::CR crFile = showFileInfo(sFileName, pScanOptions, pPdStruct);

            if (crFile != XOptions::CR_SUCCESS) {
                result = crFile;
            }
        } else if (pScanOptions->sStruct != "") {
            XOptions::CR crFile = showFileStruct(sFileName, pScanOptions, pPdStruct);

            if (crFile != XOptions::CR_SUCCESS) {
                result = crFile;
            }
        } else {
            XScanEngine::SCAN_RESULT scanResult = scanEngine.scanFile(sFileName, pScanOptions, pPdStruct);

            ScanItemModel model(pScanOptions, &(scanResult.listRecords), 1, nullptr);

            XBinary::FORMATTYPE formatType = XBinary::FORMATTYPE_TEXT;

            if (pScanOptions->bResultAsCSV) formatType = XBinary::FORMATTYPE_CSV;
            else if (pScanOptions->bResultAsJSON) formatType = XBinary::FORMATTYPE_JSON;
            else if (pScanOptions->bResultAsTSV) formatType = XBinary::FORMATTYPE_TSV;
            else if (pScanOptions->bResultAsXML) formatType = XBinary::FORMATTYPE_XML;
            else if (pScanOptions->bResultAsPlainText) formatType = XBinary::FORMATTYPE_PLAINTEXT;

            if (formatType != XBinary::FORMATTYPE_TEXT) {
                printf("%s\n", model.toString(formatType).toUtf8().data());
            } else {
                model.coloredOutput();
            }

            if (scanResult.listErrors.count()) {
                XOptions::CR crErrors = reportScanErrors(&scanResult);

                if (crErrors != XOptions::CR_SUCCESS) {
                    result = crErrors;
                }
            }
            printf("\n");
        }
    }

    return result;
}
