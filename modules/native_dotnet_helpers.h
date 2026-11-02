/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT */
#ifndef XSCAN_NATIVE_DOTNET_HELPERS_H
#define XSCAN_NATIVE_DOTNET_HELPERS_H

#include "native_scan_helpers.h"
#include "xcliassembly.h"
#include "xpe.h"
#include <QPointer>
#include "xxfclib/formats/executable/dotnet/xx_dotnet_cil.h"

namespace XScanNative {
// Queries borrow the existing CLI snapshot. Device reads preserve its cursor;
// all extents are file offsets, never virtual zero-filled PE memory.
class DotNetQueries {
public:
    DotNetQueries(const XCLIAssembly::CLI_INFO &info, QIODevice *device, qint64 size, quint32 headers,
                  const QList<XPE_DEF::IMAGE_SECTION_HEADER> &sections, const std::function<bool()> &alive)
        : m_cli(info.metaData), m_device(device), m_size(size), m_headers(headers), m_sections(sections), m_alive(alive), m_valid(info.bValid) {}

    quint32 methodCount() const { return valid() ? m_cli.Tables_TablesNumberOfIndexes[6] : 0; }
    QVariant methodInfo(quint32 rid)
    {
        Method method;
        if (!readMethod(rid, &method)) return nullResult();
        QString name = QStringLiteral(""), type = QStringLiteral(""), space = QStringLiteral("");
        bool nameCut = false, typeCut = false, spaceCut = false;
        QByteArray signature;
        if (!string(method.name, &name, &nameCut) || !blob(method.signature, &signature)) return nullResult();
        quint32 owner = methodOwner(rid);
        if (owner) {
            const uchar *row = tableRow(2, owner);
            if (!row || !string(index(row + 4, m_cli.nStringIndexSize), &type, &typeCut) ||
                !string(index(row + 4 + m_cli.nStringIndexSize, m_cli.nStringIndexSize), &space, &spaceCut)) return nullResult();
        }
        Body body;
        bool hasBody = method.rva && !(method.impl & 7) && !(method.flags & 0x2000) && methodBody(method.rva, &body);
        if (!valid()) return nullResult();
        QVariantMap result;
        result.insert(QStringLiteral("rid"), double(rid));
        result.insert(QStringLiteral("token"), double(0x06000000u + rid));
        result.insert(QStringLiteral("rva"), double(method.rva));
        result.insert(QStringLiteral("flags"), double(method.flags));
        result.insert(QStringLiteral("implFlags"), double(method.impl));
        result.insert(QStringLiteral("owner"), double(owner));
        result.insert(QStringLiteral("name"), name);
        result.insert(QStringLiteral("typeName"), type);
        result.insert(QStringLiteral("namespace"), space);
        result.insert(QStringLiteral("signature"), QString::fromLatin1(signature.toHex().toUpper()));
        result.insert(QStringLiteral("nameTruncated"), nameCut);
        result.insert(QStringLiteral("typeNameTruncated"), typeCut || spaceCut);
        result.insert(QStringLiteral("hasBody"), hasBody);
        result.insert(QStringLiteral("codeOffset"), double(hasBody ? body.codeOffset : 0));
        result.insert(QStringLiteral("codeSize"), double(hasBody ? body.codeSize : 0));
        result.insert(QStringLiteral("localSignatureToken"), double(hasBody ? body.localToken : 0));
        result.insert(QStringLiteral("hasExceptionHandlers"), hasBody && body.hasEH);
        return result;
    }
    QVariant userString(quint32 token)
    {
        const quint32 offset = token & 0xffffff;
        const QByteArray &heap = m_cli.baUS;
        quint32 size, prefix;
        if (!valid() || (token >> 24) != 0x70 || !offset || !heapValid(m_cli.osUS, heap) ||
            !compressed(heap, offset, &size, &prefix) || !size || !(size & 1) || size > 0x20001) return nullResult();
        const uchar *bytes = reinterpret_cast<const uchar *>(heap.constData()) + offset + prefix;
        if (bytes[size - 1] > 1) return nullResult();
        QString result = QStringLiteral("");
        result.reserve((size - 1) / 2);
        for (quint32 i = 0; i < size - 1; i += 2) {
            if (!(i & 0xfff) && !valid()) return nullResult();
            result.append(QChar(u16(bytes + i)));
        }
        return valid() ? QVariant(result) : nullResult();
    }
    bool calledBy(quint32 callee, quint32 caller)
    {
        Method method;
        Body body;
        QByteArray code;
        if (!callee || callee > methodCount() || !readMethod(caller, &method) || (method.impl & 7) || (method.flags & 0x2000) ||
            !method.rva || !methodBody(method.rva, &body) || !body.codeSize || !read(body.codeOffset, body.codeSize, &code)) return false;
        bool found = false;
        quint32 at = 0, steps = 0;
        while (at < body.codeSize) {
            if (!(steps++ & 0x3ff) && !valid()) return false;
            xx_dotnet_cil_instruction instruction;
            if (xx_dotnet_cil_decode(reinterpret_cast<const uint8_t *>(code.constData()), size_t(code.size()), at, &instruction) != XX_DOTNET_CIL_OK) return false;
            if ((instruction.opcode == 0x28 || instruction.opcode == 0x6f) && instruction.value == 0x06000000u + callee) found = true;
            at += instruction.width;
        }
        return valid() && found;
    }

private:
    struct Method { quint32 rva, name, signature; quint16 impl, flags; };
    struct Body { qint64 codeOffset = 0; quint32 codeSize = 0, localToken = 0; bool hasEH = false; };
    static quint16 u16(const uchar *p) { return quint16(p[0]) | quint16(p[1]) << 8; }
    static quint32 u32(const uchar *p) { return quint32(p[0]) | quint32(p[1]) << 8 | quint32(p[2]) << 16 | quint32(p[3]) << 24; }
    static bool width(int n) { return n == 2 || n == 4; }
    static quint32 index(const uchar *p, int n) { return n == 2 ? u16(p) : u32(p); }
    static bool range(qint64 limit, qint64 at, quint64 count)
    {
        return limit >= 0 && at >= 0 && at <= limit && count <= quint64(limit - at);
    }
    bool valid() const
    {
        return m_valid && m_size >= 0 && m_device && !m_device->isSequential() && (!m_alive || m_alive());
    }
    bool heapValid(const XBinary::OFFSETSIZE &where, const QByteArray &data) const
    {
        return where.nSize >= 0 && where.nSize == data.size() && range(m_size, where.nOffset, quint64(where.nSize));
    }
    const uchar *tableRow(unsigned table, quint32 rid) const
    {
        if (!valid() || table >= 64 || !rid || rid > m_cli.Tables_TablesNumberOfIndexes[table] ||
            m_cli.Tables_TablesNumberOfIndexes[table] > 0xffffff || !heapValid(m_cli.osMetadata, m_cli.baMetadata)) return nullptr;
        qint64 step = m_cli.Tables_TableElementSizes[table], start = m_cli.Tables_TablesOffsets[table];
        if (step <= 0 || quint64(step) > 0xffffffffu || start < m_cli.osMetadata.nOffset) return nullptr;
        const quint64 extent = quint64(m_cli.Tables_TablesNumberOfIndexes[table]) * quint64(step);
        const qint64 relative = start - m_cli.osMetadata.nOffset;
        if (!range(m_cli.baMetadata.size(), relative, extent)) return nullptr;
        return reinterpret_cast<const uchar *>(m_cli.baMetadata.constData()) + relative + quint64(rid - 1) * quint64(step);
    }
    bool readMethod(quint32 rid, Method *result) const
    {
        if (!width(m_cli.nStringIndexSize) || !width(m_cli.nBLOBIndexSize) ||
            m_cli.Tables_TableElementSizes[6] < 8 + m_cli.nStringIndexSize + m_cli.nBLOBIndexSize + 2) return false;
        const uchar *row = tableRow(6, rid);
        if (!row) return false;
        result->rva = u32(row); result->impl = u16(row + 4); result->flags = u16(row + 6);
        result->name = index(row + 8, m_cli.nStringIndexSize);
        result->signature = index(row + 8 + m_cli.nStringIndexSize, m_cli.nBLOBIndexSize);
        return true;
    }
    bool string(quint32 at, QString *result, bool *cut) const
    {
        const QByteArray &heap = m_cli.baStrings;
        *cut = false;
        if (!valid() || !heapValid(m_cli.osStrings, heap) || at >= quint64(heap.size()) || (!at && heap[0])) return false;
        const int available = heap.size() - int(at), count = qMin(available, 4096);
        const char *start = heap.constData() + at;
        const void *zero = std::memchr(start, 0, size_t(count));
        if (zero) { *result = QString::fromUtf8(start, int(static_cast<const char *>(zero) - start)); return true; }
        if (available <= 4096) return false;
        *result = QString::fromUtf8(start, count); *cut = true; return true;
    }
    static bool compressed(const QByteArray &heap, quint32 at, quint32 *size, quint32 *prefix)
    {
        if (at >= quint64(heap.size())) return false;
        const uchar *p = reinterpret_cast<const uchar *>(heap.constData()) + at;
        quint32 remaining = quint32(heap.size()) - at;
        *prefix = p[0] < 0x80 ? 1 : p[0] < 0xc0 ? 2 : p[0] < 0xe0 ? 4 : 0;
        if (!*prefix || remaining < *prefix) return false;
        *size = *prefix == 1 ? p[0] : *prefix == 2 ? (quint32(p[0] & 0x3f) << 8) | p[1] :
            (quint32(p[0] & 0x1f) << 24) | (quint32(p[1]) << 16) | (quint32(p[2]) << 8) | p[3];
        return *size <= remaining - *prefix && !(*prefix == 2 && *size < 0x80) && !(*prefix == 4 && *size < 0x4000);
    }
    bool blob(quint32 at, QByteArray *result)
    {
        const XBinary::OFFSETSIZE &heap = m_cli.osBlob;
        QByteArray prefix;
        if (heap.nSize <= 0 || at >= quint64(heap.nSize) || !range(m_size, heap.nOffset, quint64(heap.nSize)) ||
            !read(heap.nOffset + at, qMin<qint64>(4, heap.nSize - at), &prefix)) return false;
        if (!at) { result->clear(); return !prefix[0]; }
        // Decode the prefix independently: the payload is read only after its
        // complete extent and the signature preview cap have been checked.
        const uchar *p = reinterpret_cast<const uchar *>(prefix.constData());
        quint32 n = p[0] < 0x80 ? 1 : p[0] < 0xc0 ? 2 : p[0] < 0xe0 ? 4 : 0, size;
        if (!n || quint32(prefix.size()) < n) return false;
        size = n == 1 ? p[0] : n == 2 ? (quint32(p[0] & 0x3f) << 8) | p[1] :
            (quint32(p[0] & 0x1f) << 24) | (quint32(p[1]) << 16) | (quint32(p[2]) << 8) | p[3];
        if ((n == 2 && size < 0x80) || (n == 4 && size < 0x4000) || size > 256 || size > quint64(heap.nSize - at - n)) return false;
        return read(heap.nOffset + at + n, size, result);
    }
    quint32 methodOwner(quint32 rid) const
    {
        if (m_cli.Tables_TablesNumberOfIndexes[5] || !width(m_cli.nStringIndexSize) || !width(m_cli.nTypeDefOrRefSize) ||
            !width(m_cli.indexSize[4]) || !width(m_cli.indexSize[6])) return 0;
        const int delta = 4 + 2 * m_cli.nStringIndexSize + m_cli.nTypeDefOrRefSize + m_cli.indexSize[4];
        if (m_cli.Tables_TableElementSizes[2] < delta + m_cli.indexSize[6] || m_cli.Tables_TablesNumberOfIndexes[2] > 0xffffff) return 0;
        quint32 low = 1, high = m_cli.Tables_TablesNumberOfIndexes[2] + 1, candidate = 0;
        while (low < high) {
            quint32 mid = low + (high - low) / 2;
            const uchar *row = tableRow(2, mid);
            if (!row) return 0;
            quint32 first = index(row + delta, m_cli.indexSize[6]);
            if (!first || first > m_cli.Tables_TablesNumberOfIndexes[6] + 1) return 0;
            if (first <= rid) { candidate = mid; low = mid + 1; } else high = mid;
        }
        const uchar *row = candidate ? tableRow(2, candidate) : nullptr;
        if (!row) return 0;
        quint32 first = index(row + delta, m_cli.indexSize[6]), next = m_cli.Tables_TablesNumberOfIndexes[6] + 1;
        if (candidate < m_cli.Tables_TablesNumberOfIndexes[2]) {
            row = tableRow(2, candidate + 1);
            if (!row) return 0;
            next = index(row + delta, m_cli.indexSize[6]);
        }
        return first <= rid && rid < next && next <= m_cli.Tables_TablesNumberOfIndexes[6] + 1 ? candidate : 0;
    }
    bool read(qint64 at, quint32 size, QByteArray *result)
    {
        if (!valid() || !range(m_size, at, size) || size > 0x1000000) return false;
        const qint64 saved = m_device->pos();
        if (saved < 0) return false;
        if (!m_device->seek(at)) { if (m_device) m_device->seek(saved); return false; }
        result->resize(int(size));
        quint32 done = 0;
        bool okay = true;
        while (done < size) {
            if (!valid()) { okay = false; break; }
            qint64 count = m_device->read(result->data() + done, qMin<quint32>(size - done, 0x10000));
            if (count <= 0 || count > size - done) { okay = false; break; }
            done += quint32(count);
        }
        if (!m_device || !m_device->seek(saved)) okay = false;
        return okay && valid();
    }
    bool rawRange(quint32 rva, qint64 *at, quint64 *available) const
    {
        if (!valid() || !rva || m_sections.size() > 4096) return false;
        if (rva < m_headers && quint64(rva) < quint64(m_size)) {
            *at = rva; *available = qMin(quint64(m_headers - rva), quint64(m_size - rva)); return true;
        }
        for (const XPE_DEF::IMAGE_SECTION_HEADER &section : m_sections) {
            if (rva < section.VirtualAddress) continue;
            quint64 delta = quint64(rva) - section.VirtualAddress;
            if (delta >= section.SizeOfRawData) continue;
            quint64 offset = quint64(section.PointerToRawData) + delta;
            if (offset >= quint64(m_size)) return false;
            *at = qint64(offset); *available = qMin(qMin(quint64(section.SizeOfRawData) - delta, Q_UINT64_C(0x100000000) - rva), quint64(m_size) - offset);
            return true;
        }
        return false;
    }
    bool token(quint32 value, bool local) const
    {
        unsigned table = value >> 24;
        if (local ? table != 0x11 : (table != 1 && table != 2 && table != 0x1b)) return false;
        return tableRow(table, value & 0xffffff) != nullptr;
    }
    bool methodBody(quint32 rva, Body *result)
    {
        qint64 start;
        quint64 available, extent;
        QByteArray data;
        if (!rawRange(rva, &start, &available) || !read(start, 1, &data)) return false;
        quint32 header, code, local = 0;
        bool more;
        if ((uchar(data[0]) & 3) == 2) { header = 1; code = uchar(data[0]) >> 2; more = false; }
        else if ((uchar(data[0]) & 3) == 3) {
            if ((rva & 3) || available < 12 || !read(start, 12, &data)) return false;
            const uchar *p = reinterpret_cast<const uchar *>(data.constData());
            quint16 flags = u16(p);
            if ((flags >> 12) != 3 || (flags & 0x0fe4)) return false;
            header = 12; code = u32(p + 4); local = u32(p + 8); more = (flags & 8) != 0;
            if (local && !token(local, true)) return false;
        } else return false;
        extent = quint64(header) + code;
        if (code > 0x1000000 || extent > available) return false;
        bool hasEH = false;
        unsigned sections = 0, clauses = 0;
        while (more) {
            extent = (extent + 3) & ~Q_UINT64_C(3);
            if (++sections > 64 || extent > available || available - extent < 4 || !read(start + qint64(extent), 4, &data)) return false;
            const uchar *p = reinterpret_cast<const uchar *>(data.constData());
            if ((p[0] & 0x3f) != 1) return false;
            const bool fat = (p[0] & 0x40) != 0;
            more = (p[0] & 0x80) != 0;
            quint32 size = fat ? quint32(p[1]) | quint32(p[2]) << 8 | quint32(p[3]) << 16 : p[1];
            quint32 step = fat ? 24 : 12;
            if ((!fat && (p[2] || p[3])) || size < 4 || size > available - extent || (size - 4) % step) return false;
            quint32 count = (size - 4) / step;
            if (count > 4096 - clauses) return false;
            clauses += count; hasEH = true;
            for (quint32 i = 0; i < count; ++i) {
                if (!read(start + qint64(extent) + 4 + qint64(i) * step, step, &data)) return false;
                p = reinterpret_cast<const uchar *>(data.constData());
                quint32 flags = fat ? u32(p) : u16(p), tryAt = fat ? u32(p + 4) : u16(p + 2), trySize = fat ? u32(p + 8) : p[4];
                quint32 handlerAt = fat ? u32(p + 12) : u16(p + 5), handlerSize = fat ? u32(p + 16) : p[7], extra = fat ? u32(p + 20) : u32(p + 8);
                if ((flags != 0 && flags != 1 && flags != 2 && flags != 4) || tryAt > code || trySize > code - tryAt || handlerAt > code ||
                    handlerSize > code - handlerAt || (flags == 1 && extra >= code) || (flags == 0 && !token(extra, false))) return false;
            }
            extent += size;
        }
        if (extent > 0xffffffffu || !valid()) return false;
        result->codeOffset = start + header; result->codeSize = code; result->localToken = local; result->hasEH = hasEH;
        return true;
    }
    const XCLIAssembly::CLI_METADATA &m_cli;
    QPointer<QIODevice> m_device;
    qint64 m_size;
    quint32 m_headers;
    const QList<XPE_DEF::IMAGE_SECTION_HEADER> &m_sections;
    std::function<bool()> m_alive;
    bool m_valid;
};
}  // namespace XScanNative
#endif
