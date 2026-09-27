/* Native scan primitives: bounded input conversion and shared scan semantics. */
#ifndef XSCAN_NATIVE_SCAN_HELPERS_H
#define XSCAN_NATIVE_SCAN_HELPERS_H

#include <QByteArray>
#include <QObject>
#include <QVariant>
#include <QVector>
#include <cstring>
#include <functional>
#ifdef QT_QML_LIB
#include <QJSValue>
#endif

namespace XScanNative {
static const quint64 MaxSafeInteger = Q_UINT64_C(9007199254740991);
static const quint64 MaxRelationBytes = 16 * 1024 * 1024;

inline QVariant nullResult() { return QVariant::fromValue(static_cast<QObject *>(nullptr)); }
inline bool safeUnsigned(double value, quint64 *result, quint64 maximum = MaxSafeInteger)
{
    if (!(value >= 0 && value <= (double)maximum)) return false;
    *result = (quint64)value;
    return (double)*result == value;
}
inline QVariant plainValue(const QVariant &value)
{
#ifdef QT_QML_LIB
    if (value.userType() == qMetaTypeId<QJSValue>()) return value.value<QJSValue>().toVariant();
#endif
    return value;
}
inline bool numeric(const QVariant &source)
{
    const QVariant value = plainValue(source);
    switch (value.type()) {
    case QVariant::Int: case QVariant::UInt: case QVariant::LongLong: case QVariant::ULongLong: case QVariant::Double: return true;
    default: return false;
    }
}
inline bool unsignedValue(const QVariant &value, quint64 *result, quint64 maximum)
{
    const QVariant plain = plainValue(value);
    return numeric(plain) && safeUnsigned(plain.toDouble(), result, maximum);
}
inline bool strictRange(double offset, double size, qint64 fileSize, qint64 *start, qint64 *length)
{
    quint64 off, count;
    if (fileSize < 0 || !safeUnsigned(offset, &off) || !safeUnsigned(size, &count) ||
        off > (quint64)fileSize || count > (quint64)fileSize - off) return false;
    *start = (qint64)off; *length = (qint64)count;
    return true;
}
inline bool strictRange(const QVariant &offset, const QVariant &size, qint64 fileSize, qint64 *start, qint64 *length)
{
    const QVariant off = plainValue(offset), count = plainValue(size);
    return numeric(off) && numeric(count) && strictRange(off.toDouble(), count.toDouble(), fileSize, start, length);
}
inline bool bytePatterns(const QVariantList &source, QVector<QByteArray> *patterns)
{
    if (source.size() > 128) return false;
    int total = 0;
    for (const QVariant &item : source) {
        if (item.type() != QVariant::List) return false;
        const QVariantList values = item.toList();
        if (values.isEmpty() || values.size() > 65536 - total) return false;
        QByteArray bytes; bytes.reserve(values.size());
        for (const QVariant &value : values) {
            quint64 byte;
            if (!unsignedValue(value, &byte, 255)) return false;
            bytes.append((char)byte);
        }
        total += values.size(); patterns->append(bytes);
    }
    return true;
}
struct ByteHit { qint64 offset; int patternIndex; };
// candidates contains starts owned by this chunk; data includes overlap at its tail.
inline ByteHit findAny(const QByteArray &data, int candidates, const QVector<QByteArray> &patterns)
{
    QVector<int> buckets[256];
    for (int i = 0; i < patterns.size(); ++i) buckets[(quint8)patterns[i][0]].append(i);
    for (int position = 0; position < candidates; ++position) {
        const QVector<int> &ids = buckets[(quint8)data[position]];
        for (int id : ids) {
            const QByteArray &pattern = patterns[id];
            if (pattern.size() <= data.size() - position &&
                std::memcmp(data.constData() + position, pattern.constData(), pattern.size()) == 0) return {position, id};
        }
    }
    return {-1, -1};
}
struct RelationPair { quint32 a; quint32 b; };
typedef QVector<RelationPair> RelationGroup;
inline bool relationGroups(const QVariantList &source, quint32 tailBytes, QVector<RelationGroup> *groups)
{
    if (source.size() > 32) return false;
    int pairCount = 0;
    for (const QVariant &item : source) {
        if (item.type() != QVariant::List) return false;
        const QVariantList pairs = item.toList();
        if (pairs.isEmpty() || pairs.size() > 256 - pairCount) return false;
        RelationGroup group;
        for (const QVariant &value : pairs) {
            if (value.type() != QVariant::List) return false;
            const QVariantList pair = value.toList();
            quint64 a, b;
            if (pair.size() != 2 || !unsignedValue(pair[0], &a, tailBytes) || !unsignedValue(pair[1], &b, tailBytes)) return false;
            group.append({(quint32)a, (quint32)b});
        }
        pairCount += pairs.size(); groups->append(group);
    }
    return true;
}
inline QVector<quint32> relations(const QByteArray &data, const QVector<RelationGroup> &groups, quint32 tailBytes,
                                  bool *completed = nullptr, const std::function<bool()> &alive = std::function<bool()>())
{
    QVector<quint32> result;
    if (completed) *completed = true;
    if (tailBytes >= (quint32)data.size() || groups.isEmpty()) return result;
    const quint32 end = (quint32)data.size() - tailBytes;
    const unsigned char *bytes = reinterpret_cast<const unsigned char *>(data.constData());
    for (quint32 position = 0; position < end; ++position) {
        if ((position & 4095u) == 0 && alive && !alive()) {
            if (completed) *completed = false;
            return QVector<quint32>();
        }
        quint32 mask = 0;
        for (int i = 0; i < groups.size(); ++i) {
            bool equal = true;
            for (const RelationPair &pair : groups[i]) {
                if (bytes[position + pair.a] != bytes[position + pair.b]) { equal = false; break; }
            }
            if (equal) mask |= quint32(1) << i;
        }
        if (mask) { result.append(position); result.append(mask); }
    }
    return result;
}
struct Section { quint32 rva, virtualSize, rawSize, rawOffset, flags; };
template <typename Translate>
QVariant mapRange(double address, double size, double flags, bool fileBacked, quint64 imageBase,
                  qint64 fileSize, const QVector<Section> &sections, Translate translate)
{
    quint64 va, count, required;
    if (!safeUnsigned(address, &va) || !safeUnsigned(size, &count) || !count ||
        !safeUnsigned(flags, &required, 0xffffffffu) || imageBase > MaxSafeInteger || va < imageBase ||
        count - 1 > MaxSafeInteger - va || fileSize < 0) return nullResult();
    const quint64 rva = va - imageBase;
    for (int i = 0; i < sections.size(); ++i) {
        const Section &section = sections[i];
        const quint64 extent = fileBacked ? section.rawSize : qMax(section.virtualSize, section.rawSize);
        if ((section.flags & required) != required || rva < section.rva) continue;
        const quint64 delta = rva - section.rva;
        if (delta > extent || count > extent - delta) continue;
        QVariantMap result; result.insert(QStringLiteral("sectionIndex"), i);
        if (!fileBacked) return result;
        const quint64 offset = (quint64)section.rawOffset + delta;
        // Preserve the old helper's first containing section and endpoint translations.
        if (offset > (quint64)fileSize || count > (quint64)fileSize - offset ||
            offset > MaxSafeInteger || count - 1 > MaxSafeInteger - offset ||
            translate(va) != (qint64)offset || translate(va + count - 1) != (qint64)(offset + count - 1)) return nullResult();
        result.insert(QStringLiteral("fileOffset"), (double)offset);
        return result;
    }
    return nullResult();
}
}
#endif
