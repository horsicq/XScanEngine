#include <QCoreApplication>
#include <QJSEngine>
#include <QScriptEngine>
#include <QJSValue>
#include <cstdio>
#include <cstdlib>
#include <random>
#include "../../native_scan_helpers.h"

#define REQUIRE(c) do { if (!(c)) { std::fprintf(stderr, "line %d: %s\n", __LINE__, #c); std::exit(1); } } while (0)

class ConversionProbe : public QObject {
    Q_OBJECT
public slots:
    QVariant nullOrObject(bool valid) { if (!valid) return XScanNative::nullResult(); return QVariantMap{{"offset", 123.0}, {"patternIndex", 2}}; }
    QVariant validatePatterns(const QVariant &source) {
        QVector<QByteArray> patterns;
        const QVariant input = XScanNative::plainValue(source);
        if (input.type() != QVariant::List || !XScanNative::bytePatterns(input.toList(), &patterns)) return XScanNative::nullResult();
        return patterns.size();
    }
    QVariant safeAddress(const QVariant &value) {
        quint64 address;
        if (!XScanNative::unsignedValue(value, &address, XScanNative::MaxSafeInteger)) return XScanNative::nullResult();
        return (double)address;
    }
    QVariant flatMask() { return QVariantList{3.0, 4294967295.0}; }
    QJSValue typedMask() {
        QJSEngine *engine = qjsEngine(this);
        QJSValue result = engine->globalObject().property("Uint32Array").callAsConstructor({QJSValue(2)});
        result.setProperty(0, 3); result.setProperty(1, QJSValue(4294967295.0)); return result;
    }
};

static XScanNative::ByteHit naiveBytes(const QByteArray &data, int candidates, const QVector<QByteArray> &patterns)
{
    for (int pos = 0; pos < candidates; ++pos) {
        for (int i = 0; i < patterns.size(); ++i) {
            if (patterns[i].size() <= data.size() - pos && data.mid(pos, patterns[i].size()) == patterns[i]) return {pos, i};
        }
    }
    return {-1, -1};
}

static void testByteSearch()
{
    QVector<QByteArray> patterns;
    REQUIRE(XScanNative::bytePatterns({QVariantList{0, 255}, QVariantList{0, 255, 3}, QVariantList{65}}, &patterns));
    REQUIRE(patterns.size() == 3 && (quint8)patterns[0][1] == 255);
    patterns.clear(); REQUIRE(!XScanNative::bytePatterns({QVariant(QVariantList{})}, &patterns));
    REQUIRE(!XScanNative::bytePatterns({QVariantList{256}}, &patterns));
    REQUIRE(!XScanNative::bytePatterns({QVariantList{0.5}}, &patterns));
    REQUIRE(!XScanNative::bytePatterns({QVariantList{true}}, &patterns));
    REQUIRE(!XScanNative::bytePatterns({QVariantList{QString("1")}}, &patterns));
    QVariantList tooMany;
    for (int i = 0; i < 129; ++i) tooMany.append(QVariantList{0});
    REQUIRE(!XScanNative::bytePatterns(tooMany, &patterns));
    QVariantList tooLong; for (int i = 0; i < 65537; ++i) tooLong.append(0);
    REQUIRE(!XScanNative::bytePatterns({QVariant(tooLong)}, &patterns));
    QByteArray last("xyzabc"); QVector<QByteArray> exact{QByteArray("abc"), QByteArray("ab"), QByteArray("bc")};
    const auto hit = XScanNative::findAny(last, last.size(), exact);
    REQUIRE(hit.offset == 3 && hit.patternIndex == 0);
    REQUIRE(XScanNative::findAny(last.left(5), 5, {QByteArray("abc")}).offset == -1);
    QByteArray large(131100, 'x'); large.replace(65535, 4, "abcd");
    const auto cross = XScanNative::findAny(large.left(65539), 65536, {QByteArray("abcd")});
    REQUIRE(cross.offset == 65535);
    std::mt19937 random(47721);
    for (int trial = 0; trial < 1000; ++trial) {
        QByteArray data(50 + random() % 100, 0);
        for (char &byte : data) byte = (char)(random() % 5);
        QVector<QByteArray> needles;
        for (int i = 0; i < 1 + (int)(random() % 20); ++i) {
            QByteArray needle(1 + random() % 15, 0);
            for (char &byte : needle) byte = (char)(random() % 5);
            needles.append(needle);
        }
        const int candidates = random() % (data.size() + 1);
        const auto actual = XScanNative::findAny(data, candidates, needles), expected = naiveBytes(data, candidates, needles);
        REQUIRE(actual.offset == expected.offset && actual.patternIndex == expected.patternIndex);
    }
    qint64 offset, count;
    REQUIRE(XScanNative::strictRange(3, 3, 6, &offset, &count));
    REQUIRE(!XScanNative::strictRange(3, 4, 6, &offset, &count));
    REQUIRE(!XScanNative::strictRange(-1, 3, 6, &offset, &count));
    REQUIRE(!XScanNative::strictRange(0.5, 3, 6, &offset, &count));
    REQUIRE(!XScanNative::strictRange(9007199254740992.0, 0, Q_INT64_C(9007199254740992), &offset, &count));
}

static QVector<quint32> naiveRelations(const QByteArray &data, const QVector<XScanNative::RelationGroup> &groups, quint32 tail)
{
    QVector<quint32> out;
    for (int p = 0; p < data.size() - (qint64)tail; ++p) {
        quint32 mask = 0;
        for (int g = 0; g < groups.size(); ++g) {
            bool same = true;
            for (const auto &pair : groups[g]) same = same && data.at(p + pair.a) == data.at(p + pair.b);
            if (same) mask |= (quint32(1) << g);
        }
        if (mask) { out.append(p); out.append(mask); }
    }
    return out;
}

static void testRelations()
{
    QVector<XScanNative::RelationGroup> groups;
    REQUIRE(XScanNative::relationGroups({QVariantList{QVariantList{0, 2}}, QVariantList{QVariantList{1, 2}}}, 2, &groups));
    REQUIRE(XScanNative::relations(QByteArray("aaaab"), groups, 2) == QVector<quint32>({0, 3, 1, 3}));
    // Pair offset equal to tail is valid because the candidate endpoint is exclusive.
    REQUIRE(XScanNative::relations(QByteArray("aaa"), {{XScanNative::RelationPair{0, 2}}}, 2) == QVector<quint32>({0, 1}));
    REQUIRE(XScanNative::relations(QByteArray("aaa"), groups, 3).isEmpty());
    QVector<XScanNative::RelationGroup> all32;
    for (int i = 0; i < 32; ++i) all32.append({XScanNative::RelationPair{0, 0}});
    REQUIRE(XScanNative::relations(QByteArray("x"), all32, 0) == QVector<quint32>({0, 0xffffffffu}));
    groups.clear(); REQUIRE(!XScanNative::relationGroups({QVariant(QVariantList{})}, 0, &groups));
    REQUIRE(!XScanNative::relationGroups({QVariantList{QVariantList{0, 3}}}, 2, &groups));
    REQUIRE(!XScanNative::relationGroups({QVariantList{QVariantList{0, 1, 2}}}, 2, &groups));
    QVariantList excessGroups;
    for (int i = 0; i < 33; ++i) excessGroups.append(QVariantList{QVariantList{0, 0}});
    REQUIRE(!XScanNative::relationGroups(excessGroups, 0, &groups));
    QVariantList excessPairs;
    for (int i = 0; i < 257; ++i) excessPairs.append(QVariantList{0, 0});
    REQUIRE(!XScanNative::relationGroups({QVariant(excessPairs)}, 0, &groups));
    std::mt19937 random(773);
    for (int trial = 0; trial < 1000; ++trial) {
        QByteArray data(40 + random() % 100, 0);
        for (char &byte : data) byte = (char)(random() % 3);
        const quint32 tail = random() % 20;
        QVector<XScanNative::RelationGroup> checks;
        for (int g = 0; g < 1 + (int)(random() % 32); ++g) {
            XScanNative::RelationGroup group;
            for (int pair = 0; pair < 1 + (int)(random() % 5); ++pair) group.append({(quint32)(random() % (tail + 1)), (quint32)(random() % (tail + 1))});
            checks.append(group);
        }
        REQUIRE(XScanNative::relations(data, checks, tail) == naiveRelations(data, checks, tail));
    }
    bool completed = true;
    REQUIRE(XScanNative::relations(QByteArray(10000, 'x'), all32, 0, &completed, []{return false;}).isEmpty());
    REQUIRE(!completed);
}

static void testMappings()
{
    const QVector<XScanNative::Section> sections{{0x1000, 0x300, 0x100, 0x200, 0x60000020},
                                                {0x1080, 0x200, 0x200, 0x500, 0x60000020}};
    const quint64 base = Q_UINT64_C(0x140000000);
    auto translate = [&](quint64 va) -> qint64 {
        for (const auto &section : sections) {
            const quint64 rva = va - base;
            if (rva >= section.rva && rva - section.rva < section.rawSize) return section.rawOffset + rva - section.rva;
        }
        return -1;
    };
    const auto mapped = XScanNative::mapRange(base + 0x1080, 4, 0x20000000, false, base, 0x1000, sections, translate).toMap();
    REQUIRE(mapped["sectionIndex"].toInt() == 0 && !mapped.contains("fileOffset"));
    const auto raw = XScanNative::mapRange(base + 0x1080, 4, 0x20000000, true, base, 0x1000, sections, translate).toMap();
    REQUIRE(raw["sectionIndex"].toInt() == 0 && raw["fileOffset"].toLongLong() == 0x280);
    REQUIRE(XScanNative::mapRange(base + 0x1100, 1, 0, false, base, 0x1000, sections, translate).toMap().size() == 1);
    REQUIRE(XScanNative::mapRange(base + 0x1000, 0, 0, false, base, 0x1000, sections, translate).isNull());
    REQUIRE(XScanNative::mapRange(base - 1, 1, 0, false, base, 0x1000, sections, translate).isNull());
    REQUIRE(XScanNative::mapRange(base + 0x1080, 4, 0x80000000, true, base, 0x1000, sections, translate).isNull());
    REQUIRE(XScanNative::mapRange(base + 0x1080, 4, 0, true, base, 0x282, sections, translate).isNull());
    // A second overlapping section must not conceal a failed translation of the first one.
    REQUIRE(XScanNative::mapRange(base + 0x1080, 4, 0, true, base, 0x1000, sections, [](quint64){return 0x580;}).isNull());
    REQUIRE(XScanNative::mapRange(9007199254740991.0, 2, 0, false, 0, 10, sections, translate).isNull());
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    testByteSearch(); testRelations(); testMappings();
    // Check real bridge conversion of nested arrays and explicit failure objects in both supported runtimes.
    {
        QJSEngine engine; ConversionProbe probe;
        engine.globalObject().setProperty("probe", engine.newQObject(&probe));
        const QJSValue result = engine.evaluate("probe.nullOrObject(false) === null && probe.nullOrObject(true).offset === 123 && probe.validatePatterns([[0,255],[1]]) === 2 && probe.validatePatterns([[true]]) === null && probe.validatePatterns({}) === null && probe.validatePatterns([[\"1\"]]) === null && probe.safeAddress(1) === 1 && probe.safeAddress(\"1\") === null && probe.safeAddress(true) === null && probe.safeAddress(0.5) === null && probe.safeAddress(9007199254740992) === null && probe.flatMask()[1] === 4294967295 && probe.typedMask() instanceof Uint32Array && probe.typedMask()[1] === 4294967295");
        REQUIRE(!result.isError() && result.toBool());
    }
    {
        QScriptEngine engine; ConversionProbe probe;
        engine.globalObject().setProperty("probe", engine.newQObject(&probe));
        const QScriptValue result = engine.evaluate("probe.nullOrObject(false) === null && probe.nullOrObject(true).offset === 123 && probe.validatePatterns([[0,255],[1]]) === 2 && probe.validatePatterns([[true]]) === null && probe.validatePatterns({}) === null && probe.validatePatterns([[\"1\"]]) === null && probe.safeAddress(1) === 1 && probe.safeAddress(\"1\") === null && probe.safeAddress(true) === null && probe.safeAddress(0.5) === null && probe.safeAddress(9007199254740992) === null && probe.flatMask()[1] === 4294967295");
        REQUIRE(!engine.hasUncaughtException() && result.toBool());
    }
    std::puts("Qt native primitive differential and JS bridge checks passed");
}
#include "test_native_primitives.moc"
