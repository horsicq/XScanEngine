/* Copyright (c) 2024-2025 hors<horsicq@gmail.com>
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
#include "xscanengine.h"
#include <QCryptographicHash>
#include <QFileInfo>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCryptographicHash>
#include <QFileInfo>

QString XScanEngine::heurTypeIdToString(qint32 nId)
{
    // Values are defined in global DETECTTYPE enum (nfd_binary.h). We use constants to avoid include cycles.
    // Keep this mapping synchronized with DETECTTYPE.
    enum {
        DETECTTYPE_UNKNOWN = 0,
        DETECTTYPE_ARCHIVE,
        DETECTTYPE_CODESECTION,
        DETECTTYPE_DEXSTRING,
        DETECTTYPE_DEXTYPE,
        DETECTTYPE_ENTRYPOINT,
        DETECTTYPE_ENTRYPOINTSECTION,
        DETECTTYPE_HEADER,
        DETECTTYPE_IMPORTHASH,
        DETECTTYPE_NETANSISTRING,
        DETECTTYPE_NETUNICODESTRING,
        DETECTTYPE_OVERLAY,
        DETECTTYPE_DEBUGDATA,
        DETECTTYPE_RESOURCES,
        DETECTTYPE_RICH,
        DETECTTYPE_SECTIONNAME
    };

    QString sResult = QObject::tr("Unknown");

    switch (nId) {
        case DETECTTYPE_UNKNOWN: sResult = QObject::tr("Unknown"); break;
        case DETECTTYPE_HEADER: sResult = QObject::tr("Header"); break;
        case DETECTTYPE_OVERLAY: sResult = QObject::tr("Overlay"); break;
        case DETECTTYPE_DEBUGDATA: sResult = QObject::tr("Debug data"); break;
        case DETECTTYPE_ENTRYPOINT: sResult = QObject::tr("Entry point"); break;
        case DETECTTYPE_SECTIONNAME: sResult = QObject::tr("Section name"); break;
        case DETECTTYPE_IMPORTHASH: sResult = QObject::tr("Import hash"); break;
        case DETECTTYPE_CODESECTION: sResult = QObject::tr("Code section"); break;
        case DETECTTYPE_ENTRYPOINTSECTION: sResult = QObject::tr("Entry point section"); break;
        case DETECTTYPE_NETANSISTRING: sResult = QString(".NET ANSI %1").arg(QObject::tr("String")); break;
        case DETECTTYPE_NETUNICODESTRING: sResult = QString(".NET Unicode %1").arg(QObject::tr("String")); break;
        case DETECTTYPE_RICH: sResult = QString("Rich"); break;
        case DETECTTYPE_ARCHIVE: sResult = QObject::tr("Archive"); break;
        case DETECTTYPE_RESOURCES: sResult = QObject::tr("Resources"); break;
        case DETECTTYPE_DEXSTRING: sResult = QString("DEX %1").arg(QObject::tr("String")); break;
        case DETECTTYPE_DEXTYPE: sResult = QString("DEX %1").arg(QObject::tr("Type")); break;
        default: break;
    }

    return sResult;
}

XBinary::XCONVERT _TABLE_XScanEngine_RECORD_TYPE[] = {
    {XScanEngine::RECORD_TYPE_UNKNOWN, "Unknown", QObject::tr("Unknown")},
    {XScanEngine::RECORD_TYPE_APKOBFUSCATOR, "APK obfuscator", QString("APK %1").arg(QObject::tr("Obfuscator"))},
    {XScanEngine::RECORD_TYPE_APKTOOL, "APK Tool", QString("APK %1").arg(QObject::tr("Tool"))},
    {XScanEngine::RECORD_TYPE_ARCHIVE, "Archive", QObject::tr("Archive")},
    {XScanEngine::RECORD_TYPE_CERTIFICATE, "Certificate", QObject::tr("Certificate")},
    {XScanEngine::RECORD_TYPE_COMPILER, "Compiler", QObject::tr("Compiler")},
    {XScanEngine::RECORD_TYPE_COMPRESSOR, "Compressor", QObject::tr("Compressor")},
    {XScanEngine::RECORD_TYPE_CONVERTER, "Converter", QObject::tr("Converter")},
    {XScanEngine::RECORD_TYPE_CRYPTER, "Crypter", QObject::tr("Crypter")},
    {XScanEngine::RECORD_TYPE_CRYPTOR, "Cryptor", QObject::tr("Cryptor")},
    {XScanEngine::RECORD_TYPE_DATABASE, "Database", QObject::tr("Database")},
    {XScanEngine::RECORD_TYPE_DEBUGDATA, "Debug data", QObject::tr("Debug data")},
    {XScanEngine::RECORD_TYPE_DOCUMENT, "Document", QObject::tr("Document")},
    {XScanEngine::RECORD_TYPE_DONGLEPROTECTION, "Dongle protection", QString("Dongle %1").arg(QObject::tr("Protection"))},
    {XScanEngine::RECORD_TYPE_DOSEXTENDER, "DOS extender", QString("DOS %1").arg(QObject::tr("Extender"))},
    {XScanEngine::RECORD_TYPE_FORMAT, "Format", QObject::tr("Format")},
    {XScanEngine::RECORD_TYPE_GENERIC, "Generic", QObject::tr("Generic")},
    {XScanEngine::RECORD_TYPE_IMAGE, "Image", QObject::tr("Image")},
    {XScanEngine::RECORD_TYPE_INSTALLER, "Installer", QObject::tr("Installer")},
    {XScanEngine::RECORD_TYPE_INSTALLERDATA, "Installer data", QObject::tr("Installer data")},
    {XScanEngine::RECORD_TYPE_JAROBFUSCATOR, "JAR obfuscator", QString("JAR %1").arg(QObject::tr("Obfuscator"))},
    {XScanEngine::RECORD_TYPE_JOINER, "Joiner", QObject::tr("Joiner")},
    {XScanEngine::RECORD_TYPE_LANGUAGE, "Language", QObject::tr("Language")},
    {XScanEngine::RECORD_TYPE_LIBRARY, "Library", QObject::tr("Library")},
    {XScanEngine::RECORD_TYPE_LINKER, "Linker", QObject::tr("Linker")},
    {XScanEngine::RECORD_TYPE_LOADER, "Loader", QObject::tr("Loader")},
    {XScanEngine::RECORD_TYPE_NETCOMPRESSOR, ".NET compressor", QString(".NET %1").arg(QObject::tr("Compressor"))},
    {XScanEngine::RECORD_TYPE_NETOBFUSCATOR, ".NET obfuscator", QString(".NET %1").arg(QObject::tr("Obfuscator"))},
    {XScanEngine::RECORD_TYPE_OBFUSCATOR, "Obfuscator", QObject::tr("Obfuscator")},
    {XScanEngine::RECORD_TYPE_OPERATIONSYSTEM, "Operation system", QObject::tr("Operation system")},
    {XScanEngine::RECORD_TYPE_OVERLAY, "Overlay", QObject::tr("Overlay")},
    {XScanEngine::RECORD_TYPE_PACKER, "Packer", QObject::tr("Packer")},
    {XScanEngine::RECORD_TYPE_PETOOL, "PE Tool", QString("PE %1").arg(QObject::tr("Tool"))},
    {XScanEngine::RECORD_TYPE_PLATFORM, "Platform", QObject::tr("Platform")},
    {XScanEngine::RECORD_TYPE_PLAYER, "Player", QObject::tr("Player")},
    {XScanEngine::RECORD_TYPE_PROTECTION, "Protection", QObject::tr("Protection")},
    {XScanEngine::RECORD_TYPE_PROTECTOR, "Protector", QObject::tr("Protector")},
    {XScanEngine::RECORD_TYPE_PROTECTORDATA, "Protector data", QObject::tr("Protector data")},
    {XScanEngine::RECORD_TYPE_SFX, "SFX", QString("SFX")},
    {XScanEngine::RECORD_TYPE_SFXDATA, "SFX data", QString("SFX %1").arg(QObject::tr("data"))},
    {XScanEngine::RECORD_TYPE_SIGNTOOL, "Sign tool", QObject::tr("Sign tool")},
    {XScanEngine::RECORD_TYPE_SOURCECODE, "Source code", QObject::tr("Source code")},
    {XScanEngine::RECORD_TYPE_STUB, "Stub", QObject::tr("Stub")},
    {XScanEngine::RECORD_TYPE_TOOL, "Tool", QObject::tr("Tool")},
    {XScanEngine::RECORD_TYPE_VIRTUALMACHINE, "Virtual machine", QObject::tr("Virtual machine")},
    {XScanEngine::RECORD_TYPE_VIRUS, "Virus", QObject::tr("Virus")},
    {XScanEngine::RECORD_TYPE_TROJAN, "Trojan", QObject::tr("Trojan")},
    {XScanEngine::RECORD_TYPE_MALWARE, "Malware", QObject::tr("Malware")},
    {XScanEngine::RECORD_TYPE_PACKAGE, "Package", QObject::tr("Package")},
    {XScanEngine::RECORD_TYPE_LICENSING, "Licensing", QObject::tr("Licensing")},
    {XScanEngine::RECORD_TYPE_ROM, "ROM", QString("ROM")},
    {XScanEngine::RECORD_TYPE_CORRUPTEDDATA, "Corrupted data", QObject::tr("Corrupted data")},
    {XScanEngine::RECORD_TYPE_PERSONALDATA, "Personal data", QObject::tr("Personal data")},
    {XScanEngine::RECORD_TYPE_AUTHOR, "Author", QObject::tr("Author")},
    {XScanEngine::RECORD_TYPE_CREATOR, "Creator", QObject::tr("Creator")},
    {XScanEngine::RECORD_TYPE_PRODUCER, "Producer", QObject::tr("Producer")},
};

XBinary::XIDSTRING _TABLE_XScanEngine_RECORD_NAME[] = {
    {XScanEngine::RECORD_NAME_UNKNOWN, QString("Unknown")},
    {XScanEngine::RECORD_NAME_12311134, QString("12311134")},
    {XScanEngine::RECORD_NAME_1337EXECRYPTER, QString("1337 Exe Crypter")},
    {XScanEngine::RECORD_NAME_32LITE, QString("32Lite")},
    {XScanEngine::RECORD_NAME_7Z, QString("7-Zip")},
    {XScanEngine::RECORD_NAME_AASE, QString("Aase")},
    {XScanEngine::RECORD_NAME_ABCCRYPTOR, QString("ABC Cryptor")},
    {XScanEngine::RECORD_NAME_ACPROTECT, QString("ACProtect")},
    {XScanEngine::RECORD_NAME_ACTIVEMARK, QString("ActiveMARK")},
    {XScanEngine::RECORD_NAME_ACTUALINSTALLER, QString("Actual Installer")},
    {XScanEngine::RECORD_NAME_ADVANCEDINSTALLER, QString("Advanced Installer")},
    {XScanEngine::RECORD_NAME_ADVANCEDUPXSCRAMMBLER, QString("Advanced UPX Scrammbler")},
    {XScanEngine::RECORD_NAME_AESOBFUSCATOR, QString("AESObfuscator")},
    {XScanEngine::RECORD_NAME_AFFILLIATEEXE, QString("AffilliateEXE")},
    {XScanEngine::RECORD_NAME_AGAINNATIVITYCRYPTER, QString("Again Nativity Crypter")},
    {XScanEngine::RECORD_NAME_AGILENET, QString("Agile .NET")},
    {XScanEngine::RECORD_NAME_AHPACKER, QString("AHPacker")},
    {XScanEngine::RECORD_NAME_AHTEAMEPPROTECTOR, QString("AHTeam EP Protector")},
    {XScanEngine::RECORD_NAME_AINEXE, QString("AINEXE")},
    {XScanEngine::RECORD_NAME_AIX, QString("AIX")},
    {XScanEngine::RECORD_NAME_ALCHEMYMINDWORKS, QString("Alchemy Mindworks")},
    {XScanEngine::RECORD_NAME_ALEXPROTECTOR, QString("Alex Protector")},
    {XScanEngine::RECORD_NAME_ALIASOBJ, QString("ALIASOBJ")},
    {XScanEngine::RECORD_NAME_ALIBABACLANG, QString("Alibaba clang")},
    {XScanEngine::RECORD_NAME_ALIBABAPROTECTION, QString("Alibaba Protection")},
    {XScanEngine::RECORD_NAME_ALIENYZE, QString("Alienyze")},
    {XScanEngine::RECORD_NAME_ALIPAYCLANG, QString("Alipay clang")},
    {XScanEngine::RECORD_NAME_ALIPAYOBFUSCATOR, QString("Alipay Obfuscator")},
    {XScanEngine::RECORD_NAME_ALLATORIOBFUSCATOR, QString("Allatori Obfuscator")},
    {XScanEngine::RECORD_NAME_ALLOY, QString("Alloy")},
    {XScanEngine::RECORD_NAME_ALPINECLANG, QString("Alpine clang")},
    {XScanEngine::RECORD_NAME_ALPINELINUX, QString("Alpine Linux")},
    {XScanEngine::RECORD_NAME_AMIGA, QString("Amiga")},
    {XScanEngine::RECORD_NAME_ANDPAKK2, QString("ANDpakk2")},
    {XScanEngine::RECORD_NAME_ANDROID, QString("Android")},
    {XScanEngine::RECORD_NAME_ANDROIDAPKSIGNER, QString("Android apksigner")},
    {XScanEngine::RECORD_NAME_ANDROIDARSC, QString("Android ARSC")},
    {XScanEngine::RECORD_NAME_ANDROIDCLANG, QString("Android clang")},
    {XScanEngine::RECORD_NAME_ANDROIDGRADLE, QString("Android Gradle")},
    {XScanEngine::RECORD_NAME_ANDROIDJETPACK, QString("Android Jetpack")},
    {XScanEngine::RECORD_NAME_ANDROIDMAVENPLUGIN, QString("Android Maven Plugin")},
    {XScanEngine::RECORD_NAME_ANDROIDNDK, QString("Android NDK")},
    {XScanEngine::RECORD_NAME_ANDROIDSDK, QString("Android SDK")},
    {XScanEngine::RECORD_NAME_ANDROIDSIGNAPK, QString("Android SignApk")},
    {XScanEngine::RECORD_NAME_ANDROIDXML, QString("Android XML")},
    {XScanEngine::RECORD_NAME_ANSKYAPOLYMORPHICPACKER, QString("Anskya Polymorphic Packer")},
    {XScanEngine::RECORD_NAME_ANSLYMPACKER, QString("AnslymPacker")},
    {XScanEngine::RECORD_NAME_ANTIDOTE, QString("AntiDote")},
    {XScanEngine::RECORD_NAME_ANTILVL, QString("AntiLVL")},
    {XScanEngine::RECORD_NAME_APACHEANT, QString("Apache Ant")},
    {XScanEngine::RECORD_NAME_APACK, QString("aPACK")},
    {XScanEngine::RECORD_NAME_APKEDITOR, QString("ApkEditor")},
    {XScanEngine::RECORD_NAME_APKENCRYPTOR, QString("ApkEncryptor")},
    {XScanEngine::RECORD_NAME_APKMODIFIERSIGNAPK, QString("ApkModifier SignApk")},
    {XScanEngine::RECORD_NAME_APKPROTECT, QString("APKProtect")},
    {XScanEngine::RECORD_NAME_APKPROTECTOR, QString("ApkProtector")},
    {XScanEngine::RECORD_NAME_APKS, QString("APKS")},
    {XScanEngine::RECORD_NAME_APKSIGNATURESCHEME, QString("APK Signature Scheme")},
    {XScanEngine::RECORD_NAME_APKSIGNER, QString("ApkSigner")},
    {XScanEngine::RECORD_NAME_APKTOOLPLUS, QString("ApkToolPlus")},
    {XScanEngine::RECORD_NAME_APK_SIGNER, QString("apk-signer")},
    {XScanEngine::RECORD_NAME_APPGUARD, QString("AppGuard")},
    {XScanEngine::RECORD_NAME_APPIMAGE, QString("AppImage")},
    {XScanEngine::RECORD_NAME_APPLEJDK, QString("Apple JDK")},
    {XScanEngine::RECORD_NAME_APPLELLVM, QString("Apple LLVM")},
    {XScanEngine::RECORD_NAME_APPORTABLECLANG, QString("Apportable clang")},
    {XScanEngine::RECORD_NAME_APPSOLID, QString("AppSolid")},
    {XScanEngine::RECORD_NAME_AR, QString("ar")},
    {XScanEngine::RECORD_NAME_ARCRYPT, QString("AR Crypt")},
    {XScanEngine::RECORD_NAME_ARJ, QString("ARJ")},
    {XScanEngine::RECORD_NAME_ARMADILLO, QString("Armadillo")},
    {XScanEngine::RECORD_NAME_ARMASSEMBLER, QString("ARM Assembler")},
    {XScanEngine::RECORD_NAME_ARMC, QString("ARM C")},
    {XScanEngine::RECORD_NAME_ARMCCPP, QString("ARM C/C++")},
    {XScanEngine::RECORD_NAME_ARMLINKER, QString("ARM Linker")},
    {XScanEngine::RECORD_NAME_ARMNEONCCPP, QString("ARM NEON C/C++")},
    {XScanEngine::RECORD_NAME_ARMPROTECTOR, QString("ARM Protector")},
    {XScanEngine::RECORD_NAME_ARMTHUMBCCPP, QString("ARM/Thumb C/C++")},
    {XScanEngine::RECORD_NAME_ARMTHUMBMACROASSEMBLER, QString("ARM/Thumb Macro Assembler")},
    {XScanEngine::RECORD_NAME_AROS, QString("AROS")},
    {XScanEngine::RECORD_NAME_ARXAN, QString("Arxan")},
    {XScanEngine::RECORD_NAME_ASDPACK, QString("ASDPack")},
    {XScanEngine::RECORD_NAME_ASMGUARD, QString("ASM Guard")},
    {XScanEngine::RECORD_NAME_ASPACK, QString("ASPack")},
    {XScanEngine::RECORD_NAME_ASPLINUX, QString("ASPLinux")},
    {XScanEngine::RECORD_NAME_ASPROTECT, QString("ASProtect")},
    {XScanEngine::RECORD_NAME_ASSCRYPTER, QString("Ass Crypter")},
    {XScanEngine::RECORD_NAME_ASSEMBLER, QString("Assembler")},
    {XScanEngine::RECORD_NAME_ASSEMBLYINVOKE, QString("AssemblyInvoke")},
    {XScanEngine::RECORD_NAME_AU, QString("AU")},
    {XScanEngine::RECORD_NAME_AUTOIT, QString("AutoIt")},
    {XScanEngine::RECORD_NAME_AVASTANTIVIRUS, QString("Avast Antivirus")},
    {XScanEngine::RECORD_NAME_AVERCRYPTOR, QString("AverCryptor")},
    {XScanEngine::RECORD_NAME_AVI, QString("AVI")},
    {XScanEngine::RECORD_NAME_AVPACK, QString("AVPACK")},
    {XScanEngine::RECORD_NAME_AZPROTECT, QString("AZProtect")},
    {XScanEngine::RECORD_NAME_BABELNET, QString("Babel .NET")},
    {XScanEngine::RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR, QString("Backdoor PE Compress Protector")},
    {XScanEngine::RECORD_NAME_BAIDUPROTECTION, QString("Baidu Protection")},
    {XScanEngine::RECORD_NAME_BAIDUSIGNATUREPLATFORM, QString("Baidu Signature platform")},
    {XScanEngine::RECORD_NAME_BAMBAM, QString("bambam")},
    {XScanEngine::RECORD_NAME_BANGCLEPROTECTION, QString("Bangcle Protection")},
    {XScanEngine::RECORD_NAME_BASIC4ANDROID, QString("Basic4Android")},
    {XScanEngine::RECORD_NAME_BASIC, QString("BASIC")},
    {XScanEngine::RECORD_NAME_BAT2EXEC, QString("BAT2EXEC")},
    {XScanEngine::RECORD_NAME_BEAWEBLOGIC, QString("BEA WebLogic")},
    {XScanEngine::RECORD_NAME_BEROEXEPACKER, QString("BeRoEXEPacker")},
    {XScanEngine::RECORD_NAME_BIOHAZARDCRYPTER, QString("Biohazard Crypter")},
    {XScanEngine::RECORD_NAME_BITMAPINFOHEADER, QString("Bitmap Info Header")},
    {XScanEngine::RECORD_NAME_BITROCKINSTALLER, QString("BitRock Installer")},
    {XScanEngine::RECORD_NAME_BITSHAPEPECRYPT, QString("BitShape PE Crypt")},
    {XScanEngine::RECORD_NAME_BLADEJOINER, QString("Blade Joiner")},
    {XScanEngine::RECORD_NAME_BORLANDCCPP, QString("Borland C/C++")},
    {XScanEngine::RECORD_NAME_BORLANDCPP, QString("Borland C++")},
    {XScanEngine::RECORD_NAME_BORLANDCPPBUILDER, QString("Borland C++ Builder")},
    {XScanEngine::RECORD_NAME_BORLANDDEBUGINFO, QString("Borland Debug Info")},
    {XScanEngine::RECORD_NAME_BORLANDDELPHI, QString("Borland Delphi")},
    {XScanEngine::RECORD_NAME_BORLANDDELPHIDOTNET, QString("Borland Delphi .NET")},
    {XScanEngine::RECORD_NAME_BORLANDOBJECTPASCALDELPHI, QString("Borland Object Pascal(Delphi)")},
    {XScanEngine::RECORD_NAME_BORLANDOSSERVICES, QString("Borland OS Services")},
    {XScanEngine::RECORD_NAME_BREAKINTOPATTERN, QString("Break Into Pattern")},
    {XScanEngine::RECORD_NAME_BRIDGEOS, QString("bridgeOS")},
    {XScanEngine::RECORD_NAME_BRIDGEOSSDK, QString("bridgeOS SDK")},
    {XScanEngine::RECORD_NAME_BTWORKSCODEGUARD, QString("Btworks CodeGuard")},
    {XScanEngine::RECORD_NAME_BUNDLETOOL, QString("BundleTool")},
    {XScanEngine::RECORD_NAME_BURNEYE, QString("Burneye")},
    {XScanEngine::RECORD_NAME_BYTEDANCESECCOMPILER, QString("ByteDance-SecCompiler")},
    {XScanEngine::RECORD_NAME_BYTEGUARD, QString("ByteGuard")},
    {XScanEngine::RECORD_NAME_BZIP2, QString("bzip2")},
    {XScanEngine::RECORD_NAME_C, QString("C")},
    {XScanEngine::RECORD_NAME_CAB, QString("CAB")},
    {XScanEngine::RECORD_NAME_CARBON, QString("Carbon")},
    {XScanEngine::RECORD_NAME_CAUSEWAY, QString("CauseWay")},
    {XScanEngine::RECORD_NAME_CCBYUNIHACKERS, QString("CC by UniHackers")},
    {XScanEngine::RECORD_NAME_CCBYVORONTSOV, QString("CC by Vorontsov")},
    {XScanEngine::RECORD_NAME_CCPP, QString("C/C++")},
    {XScanEngine::RECORD_NAME_CELESTYFILEBINDER, QString("Celesty File Binder")},
    {XScanEngine::RECORD_NAME_CEXE, QString("CExe")},
    {XScanEngine::RECORD_NAME_CHROMIUMCRASHPAD, QString("Chromium Crashpad")},
    {XScanEngine::RECORD_NAME_CIGICIGICRYPTER, QString("Cigicigi Crypter")},
    {XScanEngine::RECORD_NAME_CIL, QString("cil")},
    {XScanEngine::RECORD_NAME_CLANG, QString("clang")},
    {XScanEngine::RECORD_NAME_CLICKTEAM, QString("ClickTeam")},
    {XScanEngine::RECORD_NAME_CLISECURE, QString("CliSecure")},
    {XScanEngine::RECORD_NAME_COCOA, QString("Cocoa")},
    {XScanEngine::RECORD_NAME_CODEGEARCPP, QString("CodeGear C++")},
    {XScanEngine::RECORD_NAME_CODEGEARCPPBUILDER, QString("CodeGear C++ Builder")},
    {XScanEngine::RECORD_NAME_CODEGEARDELPHI, QString("CodeGear Delphi")},
    {XScanEngine::RECORD_NAME_CODEGEAROBJECTPASCALDELPHI, QString("Codegear Object Pascal(Delphi)")},
    {XScanEngine::RECORD_NAME_CODESIGN, QString("codesign")},
    {XScanEngine::RECORD_NAME_CODEVEIL, QString("CodeVeil")},
    {XScanEngine::RECORD_NAME_CODEVIEWDEBUGINFO, QString("CodeView Debug Info")},
    {XScanEngine::RECORD_NAME_CODEWALL, QString("CodeWall")},
    {XScanEngine::RECORD_NAME_COFF, QString("COFF")},
    {XScanEngine::RECORD_NAME_COMEXSIGNAPK, QString("COMEX SignApk")},
    {XScanEngine::RECORD_NAME_COMICBOOKARCHIVE, QString("Comic Book Archive")},
    {XScanEngine::RECORD_NAME_COMPOUNDFILEBINARYFORMAT, QString("Compound File Binary Format")},
    {XScanEngine::RECORD_NAME_CONFUSER, QString("Confuser")},
    {XScanEngine::RECORD_NAME_CONFUSEREX, QString("ConfuserEx")},
    {XScanEngine::RECORD_NAME_COPYMINDER, QString("CopyMinder")},
    {XScanEngine::RECORD_NAME_CPP, QString("C++")},
    {XScanEngine::RECORD_NAME_CREATEINSTALL, QString("CreateInstall")},
    {XScanEngine::RECORD_NAME_CRINKLER, QString("Crinkler")},
    {XScanEngine::RECORD_NAME_CRUNCH, QString("Crunch")},
    {XScanEngine::RECORD_NAME_CRYEXE, QString("CryEXE")},
    {XScanEngine::RECORD_NAME_CRYPTABLESEDUCATION, QString("Cryptable Seduction")},
    {XScanEngine::RECORD_NAME_CRYPTCOM, QString("CryptCom")},
    {XScanEngine::RECORD_NAME_CRYPTDISMEMBER, QString("Crypt(Dismember)")},
    {XScanEngine::RECORD_NAME_CRYPTER, QString("Crypter")},
    {XScanEngine::RECORD_NAME_CRYPTIC, QString("Cryptic")},
    {XScanEngine::RECORD_NAME_CRYPTOCRACKPEPROTECTOR, QString("CrypToCrack Pe Protector")},
    {XScanEngine::RECORD_NAME_CRYPTOOBFUSCATORFORNET, QString("Crypto Obfuscator For .Net")},
    {XScanEngine::RECORD_NAME_CRYPTORBYDISMEMBER, QString("Cryptor by Dismember")},
    {XScanEngine::RECORD_NAME_CRYPTOZ, QString("CRyptOZ")},
    {XScanEngine::RECORD_NAME_CRYPTRROADS, QString("Crypt R.roads")},
    {XScanEngine::RECORD_NAME_CSHARP, QString("C#")},
    {XScanEngine::RECORD_NAME_CVTOMF, QString("CVTOMF")},
    {XScanEngine::RECORD_NAME_CVTPGD, QString("Cvtpgd")},
    {XScanEngine::RECORD_NAME_CVTRES, QString("CVTRES")},
    {XScanEngine::RECORD_NAME_CWSDPMI, QString("CWSDPMI")},
    {XScanEngine::RECORD_NAME_CYGWIN, QString("Cygwin")},
    {XScanEngine::RECORD_NAME_D2JAPKSIGN, QString("d2j-apk-sign")},
    {XScanEngine::RECORD_NAME_D, QString("D")},
    {XScanEngine::RECORD_NAME_DALKRYPT, QString("DalKrypt")},
    {XScanEngine::RECORD_NAME_DALVIK, QString("Dalvik")},
    {XScanEngine::RECORD_NAME_DBPE, QString("DBPE")},
    {XScanEngine::RECORD_NAME_DCRYPTPRIVATE, QString("DCrypt Private")},
    {XScanEngine::RECORD_NAME_DEB, QString("DEB")},
    {XScanEngine::RECORD_NAME_DEBIANCLANG, QString("Debian clang")},
    {XScanEngine::RECORD_NAME_DEBIANLINUX, QString("Debian Linux")},
    {XScanEngine::RECORD_NAME_DEEPSEA, QString("DeepSea")},
    {XScanEngine::RECORD_NAME_DEPACK, QString("dePack")},
    {XScanEngine::RECORD_NAME_DEPLOYMASTER, QString("DeployMaster")},
    {XScanEngine::RECORD_NAME_DEX2JAR, QString("dex2jar")},
    {XScanEngine::RECORD_NAME_DEX, QString("DEX")},
    {XScanEngine::RECORD_NAME_DEXGUARD, QString("DexGuard")},
    {XScanEngine::RECORD_NAME_DEXLIB2, QString("dexlib2")},
    {XScanEngine::RECORD_NAME_DEXLIB, QString("dexlib")},
    {XScanEngine::RECORD_NAME_DEXMERGE, QString("DexMerge")},
    {XScanEngine::RECORD_NAME_DEXPROTECTOR, QString("DexProtector")},
    {XScanEngine::RECORD_NAME_DIET, QString("DIET")},
    {XScanEngine::RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR, QString("Dingbaozeng native obfuscator")},
    {XScanEngine::RECORD_NAME_DIRTYCRYPTOR, QString("DirTy Cryptor")},
    {XScanEngine::RECORD_NAME_DJVU, QString("DjVu")},
    {XScanEngine::RECORD_NAME_DMD, QString("DMD")},
    {XScanEngine::RECORD_NAME_DMD32, QString("DMD32")},
    {XScanEngine::RECORD_NAME_DNGUARD, QString("DNGuard")},
    {XScanEngine::RECORD_NAME_DOS16M, QString("DOS/16M")},
    {XScanEngine::RECORD_NAME_DOS4G, QString("DOS/4G")},
    {XScanEngine::RECORD_NAME_DOTBJFNT, QString(".BJFnt")},
    {XScanEngine::RECORD_NAME_DOTFIXNICEPROTECT, QString("DotFix Nice Protect")},
    {XScanEngine::RECORD_NAME_DOTFUSCATOR, QString("Dotfuscator")},
    {XScanEngine::RECORD_NAME_DOTNET, QString(".NET")},
    {XScanEngine::RECORD_NAME_DOTNETREACTOR, QString(".NET Reactor")},
    {XScanEngine::RECORD_NAME_DOTNETSHRINK, QString(".netshrink")},
    {XScanEngine::RECORD_NAME_DOTNETSPIDER, QString(".NET Spider")},
    {XScanEngine::RECORD_NAME_DOTNETZ, QString(".NETZ")},
    {XScanEngine::RECORD_NAME_DOTOOLSSIGNAPK, QString("dotools sign apk")},
    {XScanEngine::RECORD_NAME_DRAGONARMOR, QString("DragonArmor")},
    {XScanEngine::RECORD_NAME_DROPBOX, QString("Dropbox")},
    {XScanEngine::RECORD_NAME_DVCLAL, QString("DVCLAL")},
    {XScanEngine::RECORD_NAME_DWARFDEBUGINFO, QString("DWARF Debug Info")},
    {XScanEngine::RECORD_NAME_DX, QString("dx")},
    {XScanEngine::RECORD_NAME_DXSHIELD, QString("DxShield")},
    {XScanEngine::RECORD_NAME_DYAMAR, QString("DYAMAR")},
    {XScanEngine::RECORD_NAME_DYNASM, QString("DynASM")},
    {XScanEngine::RECORD_NAME_EASYPROTECTOR, QString("EasyProtector")},
    {XScanEngine::RECORD_NAME_EAZFUSCATOR, QString("Eazfuscator")},
    {XScanEngine::RECORD_NAME_ECLIPSE, QString("Eclipse")},
    {XScanEngine::RECORD_NAME_ECMASCRIPT, QString("ECMAScript")},
    {XScanEngine::RECORD_NAME_ELECKEY, QString("ElecKey")},
    {XScanEngine::RECORD_NAME_EMBARCADEROCPP, QString("Embarcadero C++")},
    {XScanEngine::RECORD_NAME_EMBARCADEROCPPBUILDER, QString("Embarcadero C++ Builder")},
    {XScanEngine::RECORD_NAME_EMBARCADERODELPHI, QString("Embarcadero Delphi")},
    {XScanEngine::RECORD_NAME_EMBARCADERODELPHIDOTNET, QString("Embarcadero Delphi .NET")},
    {XScanEngine::RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI, QString("Embarcadero Object Pascal(Delphi)")},
    {XScanEngine::RECORD_NAME_EMPTYFILE, QString("Empty File")},
    {XScanEngine::RECORD_NAME_ENCRYPTPE, QString("EncryptPE")},
    {XScanEngine::RECORD_NAME_ENIGMA, QString("ENIGMA")},
    {XScanEngine::RECORD_NAME_ENIGMAVIRTUALBOX, QString("Enigma Virtual Box")},
    {XScanEngine::RECORD_NAME_EPEXEPACK, QString("!EP(EXE Pack)")},
    {XScanEngine::RECORD_NAME_EPROT, QString("!EProt")},
    {XScanEngine::RECORD_NAME_EXCELSIORJET, QString("Excelsior JET")},
    {XScanEngine::RECORD_NAME_EXE32PACK, QString("exe32pack")},
    {XScanEngine::RECORD_NAME_EXECRYPT, QString("EXECrypt")},
    {XScanEngine::RECORD_NAME_EXECRYPTOR, QString("EXECryptor")},
    {XScanEngine::RECORD_NAME_EXEFOG, QString("ExeFog")},
    {XScanEngine::RECORD_NAME_EXEJOINER, QString("ExeJoiner")},
    {XScanEngine::RECORD_NAME_EXEMPLARINSTALLER, QString("Exemplar Installer")},
    {XScanEngine::RECORD_NAME_EXEPACK, QString("EXEPACK")},
    {XScanEngine::RECORD_NAME_EXEPASSWORDPROTECTOR, QString("EXE Password Protector")},
    {XScanEngine::RECORD_NAME_EXESAX, QString("ExeSax")},
    {XScanEngine::RECORD_NAME_EXESHIELD, QString("Exe Shield")},
    {XScanEngine::RECORD_NAME_EXESTEALTH, QString("ExeStealth")},
    {XScanEngine::RECORD_NAME_EXPORT, QString("Export")},
    {XScanEngine::RECORD_NAME_EXPRESSOR, QString("eXPressor")},
    {XScanEngine::RECORD_NAME_EXPRESSOR_KERNEL32, QString("eXPressor[Kernel32]")},
    {XScanEngine::RECORD_NAME_EXPRESSOR_USER32, QString("eXPressor[User32]")},
    {XScanEngine::RECORD_NAME_EZIP, QString("EZIP")},
    {XScanEngine::RECORD_NAME_FAKESIGNATURE, QString("Fake signature")},
    {XScanEngine::RECORD_NAME_FAKUSCRYPTOR, QString("Fakus Cryptor")},
    {XScanEngine::RECORD_NAME_FASM, QString("FASM")},
    {XScanEngine::RECORD_NAME_FASTFILECRYPT, QString("Fast File Crypt")},
    {XScanEngine::RECORD_NAME_FASTPROXY, QString("fast-proxy")},
    {XScanEngine::RECORD_NAME_FEARZCRYPTER, QString("fEaRz Crypter")},
    {XScanEngine::RECORD_NAME_FEARZPACKER, QString("fEaRz Packer")},
    {XScanEngine::RECORD_NAME_FENIXOS, QString("FenixOS")},
    {XScanEngine::RECORD_NAME_FILESHIELD, QString("FileShield")},
    {XScanEngine::RECORD_NAME_FISHNET, QString("FISH .NET")},
    {XScanEngine::RECORD_NAME_FISHPEPACKER, QString("Fish PE Packer")},
    {XScanEngine::RECORD_NAME_FISHPESHIELD, QString("FishPE Shield")},
    {XScanEngine::RECORD_NAME_FLASHVIDEO, QString("Flash Video")},
    {XScanEngine::RECORD_NAME_FLEXLM, QString("Flex License Manager")},
    {XScanEngine::RECORD_NAME_FLEXNET, QString("FlexNet Licensing")},
    {XScanEngine::RECORD_NAME_FORTRAN, QString("Fortran")},
    {XScanEngine::RECORD_NAME_FOUNDATION, QString("Foundation")},
    {XScanEngine::RECORD_NAME_FPC, QString("Free Pascal")},
    {XScanEngine::RECORD_NAME_FREEBSD, QString("FreeBSD")},
    {XScanEngine::RECORD_NAME_FREECRYPTOR, QString("FreeCryptor")},
    {XScanEngine::RECORD_NAME_FSG, QString("FSG")},
    {XScanEngine::RECORD_NAME_GCC, QString("GCC")},
    {XScanEngine::RECORD_NAME_GENERIC, QString("Generic")},
    {XScanEngine::RECORD_NAME_GENERICLINKER, QString("Generic Linker")},
    {XScanEngine::RECORD_NAME_GENTEEINSTALLER, QString("Gentee Installer")},
    {XScanEngine::RECORD_NAME_GENTOOLINUX, QString("Gentoo Linux")},
    {XScanEngine::RECORD_NAME_GHAZZACRYPTER, QString("GhaZza CryPter")},  // st
    {XScanEngine::RECORD_NAME_GHOSTINSTALLER, QString("Ghost Installer")},
    {XScanEngine::RECORD_NAME_GIF, QString("GIF")},
    {XScanEngine::RECORD_NAME_GIXPROTECTOR, QString("G!X Protector")},
    {XScanEngine::RECORD_NAME_GKRIPTO, QString("GKripto")},
    {XScanEngine::RECORD_NAME_GKSETUPSFX, QString("GkSetup SFX")},
    {XScanEngine::RECORD_NAME_GNUASSEMBLER, QString("GNU Assembler")},
    {XScanEngine::RECORD_NAME_GNULINKER, QString("GNU ld")},
    {XScanEngine::RECORD_NAME_GO, QString("Go")},
    {XScanEngine::RECORD_NAME_GOASM, QString("GoAsm")},
    {XScanEngine::RECORD_NAME_GOATSPEMUTILATOR, QString("Goat's PE Mutilator")},
    {XScanEngine::RECORD_NAME_GOLD, QString("gold")},
    {XScanEngine::RECORD_NAME_GOLIATHNET, QString("Goliath .NET")},
    {XScanEngine::RECORD_NAME_GOLINK, QString("GoLink")},
    {XScanEngine::RECORD_NAME_GOOGLE, QString("Google")},
    {XScanEngine::RECORD_NAME_GOOGLEPLAY, QString("Google Play")},
    {XScanEngine::RECORD_NAME_GPINSTALL, QString("GP-Install")},
    {XScanEngine::RECORD_NAME_GUARDIANSTEALTH, QString("Guardian Stealth")},
    {XScanEngine::RECORD_NAME_GZIP, QString("GZIP")},
    {XScanEngine::RECORD_NAME_H4CKY0UORGCRYPTER, QString("H4ck-y0u.org Crypter")},
    {XScanEngine::RECORD_NAME_HACCREWCRYPTER, QString("HAC Crew Crypter")},
    {XScanEngine::RECORD_NAME_HACKSTOP, QString("HackStop")},
    {XScanEngine::RECORD_NAME_HALVCRYPTER, QString("HaLV Crypter")},
    {XScanEngine::RECORD_NAME_HANCOMLINUX, QString("Hancom Linux")},
    {XScanEngine::RECORD_NAME_HDUS_WJUS, QString("Hdus-Wjus")},
    {XScanEngine::RECORD_NAME_HIAPKCOM, QString("www.HiAPK.com")},
    {XScanEngine::RECORD_NAME_HIDEANDPROTECT, QString("Hide&Protect")},
    {XScanEngine::RECORD_NAME_HIDEPE, QString("HidePE")},
    {XScanEngine::RECORD_NAME_HIKARIOBFUSCATOR, QString("HikariObfuscator")},
    {XScanEngine::RECORD_NAME_HMIMYSPACKER, QString("Hmimys Packer")},
    {XScanEngine::RECORD_NAME_HMIMYSPROTECTOR, QString("Hmimys's Protector")},
    {XScanEngine::RECORD_NAME_HOODLUM, QString("HOODLUM")},
    {XScanEngine::RECORD_NAME_HOUNDHACKCRYPTER, QString("Hound Hack Crypter")},
    {XScanEngine::RECORD_NAME_HPUX, QString("HP-UX")},
    {XScanEngine::RECORD_NAME_HTML, QString("HTML")},
    {XScanEngine::RECORD_NAME_HXS, QString("HXS")},
    {XScanEngine::RECORD_NAME_HYPERTECHCRACKPROOF, QString("HyperTech Crackproof")},
    {XScanEngine::RECORD_NAME_IBMJDK, QString("IBM JDK")},
    {XScanEngine::RECORD_NAME_IBMPCPASCAL, QString("IBM PC Pascal")},
    {XScanEngine::RECORD_NAME_ICE, QString("ICE")},
    {XScanEngine::RECORD_NAME_ICRYPT, QString("ICrypt")},
    {XScanEngine::RECORD_NAME_IJIAMI, QString("iJiami")},
    {XScanEngine::RECORD_NAME_IJIAMILLVM, QString("iJiami LLVM")},
    {XScanEngine::RECORD_NAME_IKVMDOTNET, QString("IKVM.NET")},
    {XScanEngine::RECORD_NAME_IL2CPP, QString("IL2CPP")},
    {XScanEngine::RECORD_NAME_ILASM, QString("ILAsm")},
    {XScanEngine::RECORD_NAME_IMPORT, QString("Import")},
    {XScanEngine::RECORD_NAME_INFCRYPTOR, QString("INF Cryptor")},
    {XScanEngine::RECORD_NAME_INNOSETUP, QString("Inno Setup")},
    {XScanEngine::RECORD_NAME_INQUARTOSOBFUSCATOR, QString("Inquartos Obfuscator")},
    {XScanEngine::RECORD_NAME_INSTALL4J, QString("install4j")},
    {XScanEngine::RECORD_NAME_INSTALLANYWHERE, QString("InstallAnywhere")},
    {XScanEngine::RECORD_NAME_INSTALLAWARE, QString("InstallAware")},
    {XScanEngine::RECORD_NAME_INSTALLSHIELD, QString("InstallShield")},
    {XScanEngine::RECORD_NAME_IOS, QString("iOS")},
    {XScanEngine::RECORD_NAME_IOSSDK, QString("iOS SDK")},
    {XScanEngine::RECORD_NAME_IPA, QString("iOS App Store Package")},
    {XScanEngine::RECORD_NAME_IPADOS, QString("iPadOS")},
    {XScanEngine::RECORD_NAME_IPHONEOS, QString("iPhoneOS")},
    {XScanEngine::RECORD_NAME_IPBPROTECT, QString("iPB Protect")},
    {XScanEngine::RECORD_NAME_IRIX, QString("IRIX")},
    {XScanEngine::RECORD_NAME_ISO9660, QString("ISO 9660")},
    {XScanEngine::RECORD_NAME_JACK, QString("Jack")},
    {XScanEngine::RECORD_NAME_JAM, QString("JAM")},
    {XScanEngine::RECORD_NAME_JAR, QString("JAR")},
    {XScanEngine::RECORD_NAME_JAVA, QString("Java")},
    {XScanEngine::RECORD_NAME_JAVACOMPILEDCLASS, QString("Java compiled class")},
    {XScanEngine::RECORD_NAME_JDK, QString("JDK")},
    {XScanEngine::RECORD_NAME_JDPACK, QString("JDPack")},
    {XScanEngine::RECORD_NAME_JETBRAINS, QString("JetBrains")},
    {XScanEngine::RECORD_NAME_JIAGU, QString("jiagu")},
    {XScanEngine::RECORD_NAME_JPEG, QString("JPEG")},
    {XScanEngine::RECORD_NAME_JSCRIPT, QString("JScript")},
    {XScanEngine::RECORD_NAME_JVM, QString("JVM")},
    {XScanEngine::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER, QString("KaOs PE-DLL eXecutable Undetecter")},
    {XScanEngine::RECORD_NAME_KBYS, QString("KByS")},
    {XScanEngine::RECORD_NAME_KCRYPTOR, QString("K!Cryptor")},
    {XScanEngine::RECORD_NAME_KGBCRYPTER, QString("KGB Crypter")},
    {XScanEngine::RECORD_NAME_KIAMSCRYPTOR, QString("KiAms Cryptor")},
    {XScanEngine::RECORD_NAME_KIRO, QString("Kiro")},
    {XScanEngine::RECORD_NAME_KIWIVERSIONOBFUSCATOR, QString("Kiwi Version Obfuscator")},
    {XScanEngine::RECORD_NAME_KKRUNCHY, QString("kkrunchy")},
    {XScanEngine::RECORD_NAME_KOTLIN, QString("Kotlin")},
    {XScanEngine::RECORD_NAME_KRATOSCRYPTER, QString("Kratos Crypter")},
    {XScanEngine::RECORD_NAME_KRYPTON, QString("Krypton")},
    {XScanEngine::RECORD_NAME_KUR0KX2TO, QString("Kur0k.X2.to")},
    {XScanEngine::RECORD_NAME_LAMECRYPT, QString("LameCrypt")},
    {XScanEngine::RECORD_NAME_LARP64, QString("lARP64")},
    {XScanEngine::RECORD_NAME_LAYHEYFORTRAN90, QString("Lahey Fortran 90")},
    {XScanEngine::RECORD_NAME_LAZARUS, QString("Lazarus")},
    {XScanEngine::RECORD_NAME_LCCLNK, QString("lcclnk")},
    {XScanEngine::RECORD_NAME_LCCWIN, QString("lcc-win")},
    {XScanEngine::RECORD_NAME_LDC, QString("ldc")},
    {XScanEngine::RECORD_NAME_LGLZ, QString("LGLZ")},
    {XScanEngine::RECORD_NAME_LHA, QString("LHA")},
    {XScanEngine::RECORD_NAME_LHASSFX, QString("LHA's SFX")},
    {XScanEngine::RECORD_NAME_LIAPP, QString("LIAPP")},
    {XScanEngine::RECORD_NAME_LIGHTNINGCRYPTERPRIVATE, QString("Lightning Crypter Private")},
    {XScanEngine::RECORD_NAME_LIGHTNINGCRYPTERSCANTIME, QString("Lightning Crypter ScanTime")},
    {XScanEngine::RECORD_NAME_LINUX, QString("Linux")},
    {XScanEngine::RECORD_NAME_LLD, QString("LDD")},
    {XScanEngine::RECORD_NAME_LOCKTITE, QString("LockTite+")},
    {XScanEngine::RECORD_NAME_LSCRYPRT, QString("LSCRYPT")},
    {XScanEngine::RECORD_NAME_LUACOMPILED, QString("Lua compiled")},
    {XScanEngine::RECORD_NAME_LUCYPHER, QString("LuCypher")},
    {XScanEngine::RECORD_NAME_LZEXE, QString("LZEXE")},
    {XScanEngine::RECORD_NAME_LZFSE, QString("LZFSE")},
    {XScanEngine::RECORD_NAME_MACHOFAT, QString("Mach-O FAT")},
    {XScanEngine::RECORD_NAME_MAC_OS, QString("Mac OS")},
    {XScanEngine::RECORD_NAME_MAC_OS_X, QString("Mac OS X")},
    {XScanEngine::RECORD_NAME_MACCATALYST, QString("Mac Catalyst")},
    {XScanEngine::RECORD_NAME_MACDRIVERKIT, QString("Mac DriverKit")},
    {XScanEngine::RECORD_NAME_MACFIRMWARE, QString("Mac Firmware")},
    {XScanEngine::RECORD_NAME_MACOS, QString("macOS")},
    {XScanEngine::RECORD_NAME_MACOSSDK, QString("macOS SDK")},
    {XScanEngine::RECORD_NAME_MACROBJECT, QString("Macrobject")},
    {XScanEngine::RECORD_NAME_MALPACKER, QString("Mal Packer")},
    {XScanEngine::RECORD_NAME_MANDRAKELINUX, QString("Mandrake Linux")},
    {XScanEngine::RECORD_NAME_MASKPE, QString("MaskPE")},
    {XScanEngine::RECORD_NAME_MASM32, QString("MASM32")},
    {XScanEngine::RECORD_NAME_MASM, QString("MASM")},
    {XScanEngine::RECORD_NAME_MAXTOCODE, QString("MaxtoCode")},
    {XScanEngine::RECORD_NAME_MCLINUX, QString("mClinux")},
    {XScanEngine::RECORD_NAME_MEDUSAH, QString("Medusah")},
    {XScanEngine::RECORD_NAME_MEW10, QString("MEW10")},
    {XScanEngine::RECORD_NAME_MEW11SE, QString("MEW11 SE")},
    {XScanEngine::RECORD_NAME_MFC, QString("MFC")},
    {XScanEngine::RECORD_NAME_MICROSOFTACCESS, QString("Microsoft Access")},
    {XScanEngine::RECORD_NAME_MICROSOFTC, QString("Microsoft C")},
    {XScanEngine::RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP, QString("Microsoft Compiled HTML Help")},
    {XScanEngine::RECORD_NAME_MICROSOFTCOMPOUND, QString("Microsoft Compound")},
    {XScanEngine::RECORD_NAME_MICROSOFTCPP, QString("Microsoft C++")},
    {XScanEngine::RECORD_NAME_MICROSOFTDOTNETFRAMEWORK, QString("Microsoft .NET Framework")},
    {XScanEngine::RECORD_NAME_MICROSOFTEXCEL, QString("Microsoft Excel")},
    {XScanEngine::RECORD_NAME_MICROSOFTINSTALLER, QString("Microsoft Installer(MSI)")},
    {XScanEngine::RECORD_NAME_MICROSOFTLINKER, QString("Microsoft linker")},
    {XScanEngine::RECORD_NAME_MICROSOFTLINKERDATABASE, QString("Microsoft Linker Database")},
    {XScanEngine::RECORD_NAME_MICROSOFTOFFICE, QString("Microsoft Office")},
    {XScanEngine::RECORD_NAME_MICROSOFTOFFICEWORD, QString("Microsoft Office Word")},
    {XScanEngine::RECORD_NAME_MICROSOFTPHOENIX, QString("Microsoft Phoenix")},
    {XScanEngine::RECORD_NAME_MICROSOFTVISIO, QString("Microsoft Visio")},
    {XScanEngine::RECORD_NAME_MICROSOFTVISUALSTUDIO, QString("Microsoft Visual Studio")},
    {XScanEngine::RECORD_NAME_MICROSOFTWINHELP, QString("Microsoft WinHelp")},
    {XScanEngine::RECORD_NAME_MINGW, QString("MinGW")},
    {XScanEngine::RECORD_NAME_MINIX, QString("Minix")},
    {XScanEngine::RECORD_NAME_MINKE, QString("Minke")},
    {XScanEngine::RECORD_NAME_MKFPACK, QString("MKFPack")},
    {XScanEngine::RECORD_NAME_MOBILETENCENTPROTECT, QString("Mobile Tencent Protect")},
    {XScanEngine::RECORD_NAME_MODESTO, QString("Modesto")},
    {XScanEngine::RECORD_NAME_MODGUARD, QString("ModGuard")},
    {XScanEngine::RECORD_NAME_MOLD, QString("mold")},
    {XScanEngine::RECORD_NAME_MOLEBOX, QString("MoleBox")},
    {XScanEngine::RECORD_NAME_MOLEBOXULTRA, QString("MoleBox Ultra")},
    {XScanEngine::RECORD_NAME_MONEYCRYPTER, QString("Money Crypter")},
    {XScanEngine::RECORD_NAME_MORPHNAH, QString("Morphnah")},
    {XScanEngine::RECORD_NAME_MORTALTEAMCRYPTER2, QString("Mortal Team Crypter 2")},
    {XScanEngine::RECORD_NAME_MORTALTEAMCRYPTER, QString("Mortal Team Crypter")},
    {XScanEngine::RECORD_NAME_MORUKCREWCRYPTERPRIVATE, QString("MoruK creW Crypter Private")},
    {XScanEngine::RECORD_NAME_MOTODEVSTUDIOFORANDROID, QString("MOTODEV Studio for Android")},
    {XScanEngine::RECORD_NAME_MP3, QString("MP3")},
    {XScanEngine::RECORD_NAME_MP4, QString("MP4")},
    {XScanEngine::RECORD_NAME_MPACK, QString("mPack")},
    {XScanEngine::RECORD_NAME_MPRESS, QString("MPRESS")},
    {XScanEngine::RECORD_NAME_MRUNDECTETABLE, QString("Mr Undectetable")},
    {XScanEngine::RECORD_NAME_MSDOS, QString("MS-DOS")},
    {XScanEngine::RECORD_NAME_MSLRH, QString("MSLRH")},
    {XScanEngine::RECORD_NAME_MSYS2, QString("MSYS2")},
    {XScanEngine::RECORD_NAME_MSYS, QString("Msys")},
    {XScanEngine::RECORD_NAME_MZ0OPE, QString("MZ0oPE")},
    {XScanEngine::RECORD_NAME_NAGAINLLVM, QString("Nagain LLVM")},
    {XScanEngine::RECORD_NAME_NAGAPTPROTECTION, QString("Nagapt Protection")},
    {XScanEngine::RECORD_NAME_NAKEDPACKER, QString("NakedPacker")},
    {XScanEngine::RECORD_NAME_NASM, QString("NASM")},
    {XScanEngine::RECORD_NAME_NATIVECRYPTORBYDOSX, QString("NativeCryptor by DosX")},
    {XScanEngine::RECORD_NAME_NCODE, QString("N-Code")},
    {XScanEngine::RECORD_NAME_NEOLITE, QString("NeoLite")},
    {XScanEngine::RECORD_NAME_NETBSD, QString("NetBSD")},
    {XScanEngine::RECORD_NAME_NETEASEAPKSIGNER, QString("NetEase ApkSigner")},
    {XScanEngine::RECORD_NAME_NIDHOGG, QString("Nidhogg")},
    {XScanEngine::RECORD_NAME_NIM, QString("Nim")},
    {XScanEngine::RECORD_NAME_NJOINER, QString("N-Joiner")},
    {XScanEngine::RECORD_NAME_NJOY, QString("N-Joy")},
    {XScanEngine::RECORD_NAME_NME, QString("NME")},
    {XScanEngine::RECORD_NAME_NOOBYPROTECT, QString("NoobyProtect")},
    {XScanEngine::RECORD_NAME_NOODLECRYPT, QString("NoodleCrypt")},
    {XScanEngine::RECORD_NAME_NORTHSTARPESHRINKER, QString("North Star PE Shrinker")},
    {XScanEngine::RECORD_NAME_NOSINSTALLER, QString("NOS Installer")},
    {XScanEngine::RECORD_NAME_NOSTUBLINKER, QString("NOSTUBLINKER")},
    {XScanEngine::RECORD_NAME_NOXCRYPT, QString("noX Crypt")},
    {XScanEngine::RECORD_NAME_NPACK, QString("nPack")},
    {XScanEngine::RECORD_NAME_NQSHIELD, QString("NQ Shield")},
    {XScanEngine::RECORD_NAME_NSIS, QString("Nullsoft Scriptable Install System")},
    {XScanEngine::RECORD_NAME_NSK, QString("NSK")},
    {XScanEngine::RECORD_NAME_NSPACK, QString("NsPack")},
    {XScanEngine::RECORD_NAME_OBFUSCAR, QString("Obfuscar")},
    {XScanEngine::RECORD_NAME_OBFUSCATORLLVM, QString("Obfuscator-LLVM")},
    {XScanEngine::RECORD_NAME_OBFUSCATORNET2009, QString("Obfuscator.NET 2009")},
    {XScanEngine::RECORD_NAME_OBJECTIVEC, QString("Objective-C")},
    {XScanEngine::RECORD_NAME_OBJECTPASCAL, QString("Object Pascal")},
    {XScanEngine::RECORD_NAME_OBJECTPASCALDELPHI, QString("Object Pascal(Delphi)")},
    {XScanEngine::RECORD_NAME_OBSIDIUM, QString("Obsidium")},
    {XScanEngine::RECORD_NAME_OLLVMTLL, QString("ollvm-tll(LLVM 6.0+Ollvm+Armariris)")},
    {XScanEngine::RECORD_NAME_ONESPANPROTECTION, QString("OneSpan Protection")},
    {XScanEngine::RECORD_NAME_OPENBSD, QString("OpenBSD")},
    {XScanEngine::RECORD_NAME_OPENDOCUMENT, QString("Open Document")},
    {XScanEngine::RECORD_NAME_OPENJDK, QString("OpenJDK")},
    {XScanEngine::RECORD_NAME_OPENSOURCECODECRYPTER, QString("Open Source Code Crypter")},
    {XScanEngine::RECORD_NAME_OPENVMS, QString("Open VMS")},
    {XScanEngine::RECORD_NAME_OPENVOS, QString("Open VOS")},
    {XScanEngine::RECORD_NAME_OPENWATCOMCCPP, QString("Open Watcom C/C++")},
    {XScanEngine::RECORD_NAME_OPERA, QString("Opera")},
    {XScanEngine::RECORD_NAME_ORACLESOLARISLINKEDITORS, QString("Oracle Solaris Link Editors")},
    {XScanEngine::RECORD_NAME_OREANSCODEVIRTUALIZER, QString("Oreans CodeVirtualizer")},
    {XScanEngine::RECORD_NAME_ORIEN, QString("ORiEN")},
    {XScanEngine::RECORD_NAME_OS2, QString("OS/2")},
    {XScanEngine::RECORD_NAME_OSCCRYPTER, QString("OSC-Crypter")},
    {XScanEngine::RECORD_NAME_OS_X, QString("OS X")},
    {XScanEngine::RECORD_NAME_P0KESCRAMBLER, QString("p0ke Scrambler")},
    {XScanEngine::RECORD_NAME_PACKMAN, QString("Packman")},
    {XScanEngine::RECORD_NAME_PACKWIN, QString("PACKWIN")},
    {XScanEngine::RECORD_NAME_PANDORA, QString("Pandora")},
    {XScanEngine::RECORD_NAME_PANGXIE, QString("PangXie")},
    {XScanEngine::RECORD_NAME_PCGUARD, QString("PC Guard")},
    {XScanEngine::RECORD_NAME_PCOM, QString("PCOM")},
    {XScanEngine::RECORD_NAME_PCSHRINK, QString("PCShrink")},
    {XScanEngine::RECORD_NAME_PDB, QString("PDB")},
    {XScanEngine::RECORD_NAME_PDBFILELINK, QString("PDB file link")},
    {XScanEngine::RECORD_NAME_PDF, QString("PDF")},
    {XScanEngine::RECORD_NAME_PEARMOR, QString("PE-Armor")},
    {XScanEngine::RECORD_NAME_PEBUNDLE, QString("PEBundle")},
    {XScanEngine::RECORD_NAME_PECOMPACT, QString("PECompact")},
    {XScanEngine::RECORD_NAME_PECRYPT32, QString("PECRYPT32")},
    {XScanEngine::RECORD_NAME_PEDIMINISHER, QString("PE Diminisher")},
    {XScanEngine::RECORD_NAME_PEENCRYPT, QString("PE Encrypt")},
    {XScanEngine::RECORD_NAME_PELOCK, QString("PELock")},
    {XScanEngine::RECORD_NAME_PELOCKNT, QString("PELOCKnt")},
    {XScanEngine::RECORD_NAME_PENGUINCRYPT, QString("PEnguinCrypt")},  // TODO Check name
    {XScanEngine::RECORD_NAME_PEPACK, QString("PE-PACK")},
    {XScanEngine::RECORD_NAME_PEPACKSPROTECT, QString("pepack's Protect")},
    {XScanEngine::RECORD_NAME_PEQUAKE, QString("PE Quake")},
    {XScanEngine::RECORD_NAME_PERL, QString("Perl")},
    {XScanEngine::RECORD_NAME_PESHIELD, QString("PE-SHiELD")},  // TODO Check name
    {XScanEngine::RECORD_NAME_PESPIN, QString("PESpin")},
    {XScanEngine::RECORD_NAME_PETITE, QString("Petite")},
    {XScanEngine::RECORD_NAME_PETITE_KERNEL32, QString("Petite.kernel32")},
    {XScanEngine::RECORD_NAME_PETITE_USER32, QString("Petite.user32")},
    {XScanEngine::RECORD_NAME_PEX, QString("PeX")},
    {XScanEngine::RECORD_NAME_PFECX, QString("PFE CX")},
    {XScanEngine::RECORD_NAME_PGMPAK, QString("PGMPAK")},
    {XScanEngine::RECORD_NAME_PHOENIXPROTECTOR, QString("Phoenix Protector")},
    {XScanEngine::RECORD_NAME_PHP, QString("PHP")},
    {XScanEngine::RECORD_NAME_PICRYPTOR, QString("PI Cryptor")},
    {XScanEngine::RECORD_NAME_PKLITE32, QString("PKLITE32")},
    {XScanEngine::RECORD_NAME_PKLITE, QString("PKLITE")},
    {XScanEngine::RECORD_NAME_PKZIPMINISFX, QString("PKZIP mini-sfx")},
    {XScanEngine::RECORD_NAME_PLAIN, QString("Plain")},
    {XScanEngine::RECORD_NAME_PLEXCLANG, QString("Plex clang")},
    {XScanEngine::RECORD_NAME_PMODEW, QString("PMODE/W")},
    {XScanEngine::RECORD_NAME_PNG, QString("PNG")},
    {XScanEngine::RECORD_NAME_POKECRYPTER, QString("Poke Crypter")},
    {XScanEngine::RECORD_NAME_POLYCRYPTPE, QString("PolyCrypt PE")},
    {XScanEngine::RECORD_NAME_POSIX, QString("POSIX")},
    {XScanEngine::RECORD_NAME_POWERBASIC, QString("PowerBASIC")},
    {XScanEngine::RECORD_NAME_PRIVATEEXEPROTECTOR, QString("Private EXE Protector")},
    {XScanEngine::RECORD_NAME_PROGUARD, QString("ProGuard")},
    {XScanEngine::RECORD_NAME_PROPACK, QString("PRO-PACK")},
    {XScanEngine::RECORD_NAME_PROTECTEXE, QString("PROTECT! EXE")},
    {XScanEngine::RECORD_NAME_PSEUDOAPKSIGNER, QString("PseudoApkSigner")},
    {XScanEngine::RECORD_NAME_PUBCRYPTER, QString("Pub Crypter")},
    {XScanEngine::RECORD_NAME_PUNISHER, QString("PUNiSHER")},
    {XScanEngine::RECORD_NAME_PUREBASIC, QString("PureBasic")},
    {XScanEngine::RECORD_NAME_PUSSYCRYPTER, QString("PussyCrypter")},
    {XScanEngine::RECORD_NAME_PYINSTALLER, QString("PyInstaller")},
    {XScanEngine::RECORD_NAME_PYTHON, QString("Python")},
    {XScanEngine::RECORD_NAME_QDBH, QString("qdbh")},
    {XScanEngine::RECORD_NAME_QIHOO360PROTECTION, QString("Qihoo 360 Protection")},
    {XScanEngine::RECORD_NAME_QML, QString("QML")},
    {XScanEngine::RECORD_NAME_QNX, QString("QNX")},
    {XScanEngine::RECORD_NAME_QRYPT0R, QString("QrYPt0r")},
    {XScanEngine::RECORD_NAME_QT, QString("Qt")},
    {XScanEngine::RECORD_NAME_QTINSTALLER, QString("Qt Installer")},
    {XScanEngine::RECORD_NAME_QUICKPACKNT, QString("QuickPack NT")},
    {XScanEngine::RECORD_NAME_R8, QString("R8")},
    {XScanEngine::RECORD_NAME_RADIALIX, QString("Radialix")},
    {XScanEngine::RECORD_NAME_RAR, QString("RAR")},
    {XScanEngine::RECORD_NAME_RCRYPTOR, QString("RCryptor(Russian Cryptor)")},
    {XScanEngine::RECORD_NAME_RDGTEJONCRYPTER, QString("RDG Tejon Crypter")},
    {XScanEngine::RECORD_NAME_REDHATLINUX, QString("Red Hat Linux")},
    {XScanEngine::RECORD_NAME_RELPACK, QString("Relpack")},
    {XScanEngine::RECORD_NAME_RENETPACK, QString("ReNET-pack")},
    {XScanEngine::RECORD_NAME_RESOURCE, QString("Resource")},
    {XScanEngine::RECORD_NAME_RESOURCE_CURSOR, QString("Resource Cursor")},
    {XScanEngine::RECORD_NAME_RESOURCE_DIALOG, QString("Resource Dialog")},
    {XScanEngine::RECORD_NAME_RESOURCE_ICON, QString("Resource Icon")},
    {XScanEngine::RECORD_NAME_RESOURCE_MENU, QString("Resource Menu")},
    {XScanEngine::RECORD_NAME_RESOURCE_STRINGTABLE, QString("Resource String Table")},
    {XScanEngine::RECORD_NAME_RESOURCE_VERSIONINFO, QString("Resource Version Info")},
    {XScanEngine::RECORD_NAME_REVPROT, QString("REVProt")},
    {XScanEngine::RECORD_NAME_RJCRUSH, QString("RJcrush")},
    {XScanEngine::RECORD_NAME_RLP, QString("RLP")},
    {XScanEngine::RECORD_NAME_RLPACK, QString("RLPack")},
    {XScanEngine::RECORD_NAME_ROGUEPACK, QString("RoguePack")},
    {XScanEngine::RECORD_NAME_ROSASM, QString("RosAsm")},
    {XScanEngine::RECORD_NAME_RTF, QString("Rich Text Format")},
    {XScanEngine::RECORD_NAME_RUBY, QString("Ruby")},
    {XScanEngine::RECORD_NAME_RUST, QString("Rust")},
    {XScanEngine::RECORD_NAME_SAFEENGINELLVM, QString("Safengine LLVM")},
    {XScanEngine::RECORD_NAME_SAFEENGINESHIELDEN, QString("Safengine Shielden")},
    {XScanEngine::RECORD_NAME_SANDHOOK, QString("SandHook")},
    {XScanEngine::RECORD_NAME_SCOBFUSCATOR, QString("SC Obfuscator")},
    {XScanEngine::RECORD_NAME_SCPACK, QString("SC Pack")},
    {XScanEngine::RECORD_NAME_SCRNCH, QString("SCRNCH")},
    {XScanEngine::RECORD_NAME_SDPROTECTORPRO, QString("SDProtector Pro")},
    {XScanEngine::RECORD_NAME_SECNEO, QString("SecNeo")},
    {XScanEngine::RECORD_NAME_SECSHELL, QString("SecShell")},
    {XScanEngine::RECORD_NAME_SECURESHADE, QString("Secure Shade")},
    {XScanEngine::RECORD_NAME_SECUROM, QString("SecuROM")},
    {XScanEngine::RECORD_NAME_SEPOS, QString("sepOS")},
    {XScanEngine::RECORD_NAME_SERGREENAPPACKER, QString("SerGreen Appacker")},
    {XScanEngine::RECORD_NAME_SETUPFACTORY, QString("Setup Factory")},
    {XScanEngine::RECORD_NAME_SEXECRYPTER, QString("Sexe Crypter")},
    {XScanEngine::RECORD_NAME_SHELL, QString("Shell")},
    {XScanEngine::RECORD_NAME_SHRINKER, QString("Shrinker")},
    {XScanEngine::RECORD_NAME_SIGNATORY, QString("signatory")},
    {XScanEngine::RECORD_NAME_SIGNUPDATE, QString("signupdate")},
    {XScanEngine::RECORD_NAME_SIMBIOZ, QString("SimbiOZ")},
    {XScanEngine::RECORD_NAME_SIMCRYPTER, QString("Sim Crypter")},
    {XScanEngine::RECORD_NAME_SIMPLECRYPTER, QString("Simple Crypter")},
    {XScanEngine::RECORD_NAME_SIMPLEPACK, QString("Simple Pack")},
    {XScanEngine::RECORD_NAME_SINGLEJAR, QString("SingleJar")},
    {XScanEngine::RECORD_NAME_SIXXPACK, QString("Sixxpack")},
    {XScanEngine::RECORD_NAME_SKATER, QString("Skater")},
    {XScanEngine::RECORD_NAME_SMARTASSEMBLY, QString("Smart Assembly")},
    {XScanEngine::RECORD_NAME_SMARTINSTALLMAKER, QString("Smart Install Maker")},
    {XScanEngine::RECORD_NAME_SMOKESCREENCRYPTER, QString("SmokeScreen Crypter")},
    {XScanEngine::RECORD_NAME_SNAPDRAGONLLVMARM, QString("Snapdragon LLVM ARM")},
    {XScanEngine::RECORD_NAME_SNAPPROTECT, QString("SnapProtect")},
    {XScanEngine::RECORD_NAME_SNOOPCRYPT, QString("Snoop Crypt")},
    {XScanEngine::RECORD_NAME_SOFTDEFENDER, QString("Soft Defender")},
    {XScanEngine::RECORD_NAME_SOFTSENTRY, QString("SoftSentry")},
    {XScanEngine::RECORD_NAME_SOFTWARECOMPRESS, QString("Software Compress")},
    {XScanEngine::RECORD_NAME_SOFTWAREZATOR, QString("SoftwareZator")},
    {XScanEngine::RECORD_NAME_SOLARIS, QString("Solaris")},
    {XScanEngine::RECORD_NAME_SOURCERYCODEBENCH, QString("Sourcery CodeBench")},
    {XScanEngine::RECORD_NAME_SOURCERYCODEBENCHLITE, QString("Sourcery CodeBench Lite")},
    {XScanEngine::RECORD_NAME_SPICESNET, QString("Spices.Net")},
    {XScanEngine::RECORD_NAME_SPIRIT, QString("$pirit")},
    {XScanEngine::RECORD_NAME_SPOONINSTALLER, QString("Spoon Installer")},
    {XScanEngine::RECORD_NAME_SPOONSTUDIO2011, QString("Spoon Studio 2011")},
    {XScanEngine::RECORD_NAME_SPOONSTUDIO, QString("Spoon Studio")},
    {XScanEngine::RECORD_NAME_SQUIRRELINSTALLER, QString("Squirrel Installer")},
    {XScanEngine::RECORD_NAME_SQUEEZSFX, QString("Squeez Self Extractor")},
    {XScanEngine::RECORD_NAME_STABSDEBUGINFO, QString("STABS Debug Info")},
    {XScanEngine::RECORD_NAME_STARFORCE, QString("StarForce")},
    {XScanEngine::RECORD_NAME_STARTOSLINUX, QString("StartOS Linux")},
    {XScanEngine::RECORD_NAME_STASFODIDOCRYPTOR, QString("StasFodidoCryptor")},
    {XScanEngine::RECORD_NAME_STONESPEENCRYPTOR, QString("Stone's PE Encryptor")},
    {XScanEngine::RECORD_NAME_SUNOS, QString("SunOS")},
    {XScanEngine::RECORD_NAME_SUNWORKSHOP, QString("Sun WorkShop")},
    {XScanEngine::RECORD_NAME_SUNWORKSHOPCOMPILERS, QString("Sun WorkShop Compilers")},
    {XScanEngine::RECORD_NAME_SUSELINUX, QString("SUSE Linux")},
    {XScanEngine::RECORD_NAME_SVKPROTECTOR, QString("SVK Protector")},
    {XScanEngine::RECORD_NAME_SYLLABLE, QString("Syllable")},
    {XScanEngine::RECORD_NAME_SYMBOLTABLE, QString("Symbol Table")},
    {XScanEngine::RECORD_NAME_SWF, QString("SWF")},
    {XScanEngine::RECORD_NAME_SWIFT, QString("Swift")},
    {XScanEngine::RECORD_NAME_TAR, QString("tar")},
    {XScanEngine::RECORD_NAME_TARMAINSTALLER, QString("Tarma Installer")},
    {XScanEngine::RECORD_NAME_TELOCK, QString("tElock")},
    {XScanEngine::RECORD_NAME_TENCENTLEGU, QString("Tencent Legu")},
    {XScanEngine::RECORD_NAME_TENCENTPROTECTION, QString("Tencent Protection")},
    {XScanEngine::RECORD_NAME_TGRCRYPTER, QString("TGR Crypter")},
    {XScanEngine::RECORD_NAME_THEBESTCRYPTORBYFSK, QString("The Best Cryptor [by FsK]")},
    {XScanEngine::RECORD_NAME_THEMIDAWINLICENSE, QString("Themida/Winlicense")},
    {XScanEngine::RECORD_NAME_THEZONECRYPTER, QString("The Zone Crypter")},
    {XScanEngine::RECORD_NAME_THINSTALL, QString("Thinstall(VMware ThinApp)")},
    {XScanEngine::RECORD_NAME_THUMBC, QString("Thumb C")},
    {XScanEngine::RECORD_NAME_TIFF, QString("TIFF")},
    {XScanEngine::RECORD_NAME_TINYC, QString("Tiny C")},
    {XScanEngine::RECORD_NAME_TINYPROG, QString("TinyProg")},
    {XScanEngine::RECORD_NAME_TINYSIGN, QString("tiny-sign")},
    {XScanEngine::RECORD_NAME_TOTALCOMMANDERINSTALLER, QString("Total Commander Installer")},
    {XScanEngine::RECORD_NAME_TPPPACK, QString("TTP Pack")},
    {XScanEngine::RECORD_NAME_TRU64, QString("Tru64")},
    {XScanEngine::RECORD_NAME_TSTCRYPTER, QString("TsT Crypter")},
    {XScanEngine::RECORD_NAME_TTF, QString("True Type Font")},
    {XScanEngine::RECORD_NAME_TTPROTECT, QString("TTprotect")},
    {XScanEngine::RECORD_NAME_TURBOBASIC, QString("Turbo Basic")},
    {XScanEngine::RECORD_NAME_TURBOC, QString("Turbo C")},
    {XScanEngine::RECORD_NAME_TURBOCPP, QString("Turbo C++")},
    {XScanEngine::RECORD_NAME_TURBOLINKER, QString("Turbo linker")},
    {XScanEngine::RECORD_NAME_TURBOLINUX, QString("Turbo Linux")},
    {XScanEngine::RECORD_NAME_TURBOSTUDIO, QString("Turbo Studio")},
    {XScanEngine::RECORD_NAME_TURKISHCYBERSIGNATURE, QString("Turkish Cyber Signature")},
    {XScanEngine::RECORD_NAME_TURKOJANCRYPTER, QString("Turkojan Crypter")},
    {XScanEngine::RECORD_NAME_TVOS, QString("tvOS")},
    {XScanEngine::RECORD_NAME_TVOSSDK, QString("tvOS SDK")},
    {XScanEngine::RECORD_NAME_UBUNTUCLANG, QString("Ubuntu clang")},
    {XScanEngine::RECORD_NAME_UBUNTULINUX, QString("Ubuntu Linux")},
    {XScanEngine::RECORD_NAME_UCEXE, QString("UCEXE")},
    {XScanEngine::RECORD_NAME_UNDERGROUNDCRYPTER, QString("UnderGround Crypter")},
    {XScanEngine::RECORD_NAME_UNDOCRYPTER, QString("UnDo Crypter")},
    {XScanEngine::RECORD_NAME_UNICODE, QString("Unicode")},
    {XScanEngine::RECORD_NAME_UNICOMSDK, QString("Unicom SDK")},
    {XScanEngine::RECORD_NAME_UNILINK, QString("UniLink")},
    {XScanEngine::RECORD_NAME_UNITY, QString("Unity")},
    {XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER, QString("Universal Tuple Compiler")},
    {XScanEngine::RECORD_NAME_UNIX, QString("Unix")},
    {XScanEngine::RECORD_NAME_UNKOWNCRYPTER, QString("unkOwn Crypter")},
    {XScanEngine::RECORD_NAME_UNK_UPXLIKE, QString("(Unknown)UPX-like")},
    {XScanEngine::RECORD_NAME_UNOPIX, QString("Unopix")},
    {XScanEngine::RECORD_NAME_UPX, QString("UPX")},
    {XScanEngine::RECORD_NAME_UTF8, QString("UTF-8")},
    {XScanEngine::RECORD_NAME_VALVE, QString("Valve")},
    {XScanEngine::RECORD_NAME_VBNET, QString("VB .NET")},
    {XScanEngine::RECORD_NAME_VBSTOEXE, QString("Vbs To Exe")},
    {XScanEngine::RECORD_NAME_VCASMPROTECTOR, QString("VCasm-Protector")},
    {XScanEngine::RECORD_NAME_VCL, QString("Visual Component Library")},
    {XScanEngine::RECORD_NAME_VCLPACKAGEINFO, QString("VCL PackageInfo")},
    {XScanEngine::RECORD_NAME_VDOG, QString("VDog")},
    {XScanEngine::RECORD_NAME_VERACRYPT, QString("VeraCrypt")},
    {XScanEngine::RECORD_NAME_VINELINUX, QString("Vine Linux")},
    {XScanEngine::RECORD_NAME_VIRBOXPROTECTOR, QString("Virbox Protector")},
    {XScanEngine::RECORD_NAME_VIRTUALIZEPROTECT, QString("VirtualizeProtect")},
    {XScanEngine::RECORD_NAME_VIRTUALPASCAL, QString("Virtual Pascal")},
    {XScanEngine::RECORD_NAME_VISE, QString("Vise")},
    {XScanEngine::RECORD_NAME_VISUALBASIC, QString("Visual Basic")},
    {XScanEngine::RECORD_NAME_VISUALCCPP, QString("Visual C/C++")},
    {XScanEngine::RECORD_NAME_VISUALCSHARP, QString("Visual C#")},
    {XScanEngine::RECORD_NAME_VISUALOBJECTS, QString("Visual Objects")},
    {XScanEngine::RECORD_NAME_VMPROTECT, QString("VMProtect")},
    {XScanEngine::RECORD_NAME_VMUNPACKER, QString("VMUnpacker")},
    {XScanEngine::RECORD_NAME_VMWARE, QString("VMware")},
    {XScanEngine::RECORD_NAME_VPACKER, QString("VPacker")},
    {XScanEngine::RECORD_NAME_WALLE, QString("Walle")},
    {XScanEngine::RECORD_NAME_WANGZEHUALLVM, QString("wangzehua LLVM")},
    {XScanEngine::RECORD_NAME_WATCHOS, QString("watchOS")},
    {XScanEngine::RECORD_NAME_WATCHOSSDK, QString("watchOS SDK")},
    {XScanEngine::RECORD_NAME_WATCOMC, QString("Watcom C")},
    {XScanEngine::RECORD_NAME_WATCOMCCPP, QString("Watcom C/C++")},
    {XScanEngine::RECORD_NAME_WATCOMDEBUGINFO, QString("Watcom Debug Info")},
    {XScanEngine::RECORD_NAME_WATCOMLINKER, QString("Watcom linker")},
    {XScanEngine::RECORD_NAME_WAV, QString("WAV")},
    {XScanEngine::RECORD_NAME_WDOSX, QString("WDOSX")},
    {XScanEngine::RECORD_NAME_WEBP, QString("WebP")},
    {XScanEngine::RECORD_NAME_WHITELLCRYPT, QString("Whitell Crypt")},
    {XScanEngine::RECORD_NAME_WINACE, QString("WinACE")},
    {XScanEngine::RECORD_NAME_WINAUTH, QString("Windows Authenticode")},
    {XScanEngine::RECORD_NAME_WINDOFCRYPT, QString("WindOfCrypt")},
    {XScanEngine::RECORD_NAME_WINDOWS, QString("Windows")},
    {XScanEngine::RECORD_NAME_WINDOWSBITMAP, QString("Windows Bitmap")},
    {XScanEngine::RECORD_NAME_WINDOWSCE, QString("Windows CE")},
    {XScanEngine::RECORD_NAME_WINDOWSCURSOR, QString("Windows Cursor")},
    {XScanEngine::RECORD_NAME_WINDOWSICON, QString("Windows Icon")},
    {XScanEngine::RECORD_NAME_WINDOWSINSTALLER, QString("Windows Installer")},
    {XScanEngine::RECORD_NAME_WINDOWSMEDIA, QString("Windows Media")},
    {XScanEngine::RECORD_NAME_WINDRIVERLINUX, QString("Wind River Linux")},
    {XScanEngine::RECORD_NAME_WINGSCRYPT, QString("WingsCrypt")},
    {XScanEngine::RECORD_NAME_WINKRIPT, QString("WinKript")},
    {XScanEngine::RECORD_NAME_WINRAR, QString("WinRAR")},
    {XScanEngine::RECORD_NAME_WINUPACK, QString("(Win)Upack")},
    {XScanEngine::RECORD_NAME_WINZIP, QString("WinZip")},
    {XScanEngine::RECORD_NAME_WISE, QString("Wise")},
    {XScanEngine::RECORD_NAME_WIXTOOLSET, QString("WiX Toolset")},
    {XScanEngine::RECORD_NAME_WLCRYPT, QString("WL-Crypt")},
    {XScanEngine::RECORD_NAME_WLGROUPCRYPTER, QString("WL-Group Crypter")},
    {XScanEngine::RECORD_NAME_WOUTHRSEXECRYPTER, QString("WouThrs EXE Crypter")},
    {XScanEngine::RECORD_NAME_WWPACK32, QString("WWPack32")},
    {XScanEngine::RECORD_NAME_WWPACK, QString("WWPack")},
    {XScanEngine::RECORD_NAME_WXWIDGETS, QString("wxWidgets")},
    {XScanEngine::RECORD_NAME_X86ASSEMBLER, QString("x86 Assembler")},
    {XScanEngine::RECORD_NAME_XAR, QString("xar")},
    {XScanEngine::RECORD_NAME_XBOX, QString("XBOX")},
    {XScanEngine::RECORD_NAME_XCODE, QString("Xcode")},
    {XScanEngine::RECORD_NAME_XCODELINKER, QString("Xcode ld")},
    {XScanEngine::RECORD_NAME_XCOMP, QString("XComp")},
    {XScanEngine::RECORD_NAME_XENOCODE, QString("Xenocode")},
    {XScanEngine::RECORD_NAME_XENOCODEPOSTBUILD2009FORDOTNET, QString("Xenocode Postbuild 2009 for .NET")},
    {XScanEngine::RECORD_NAME_XENOCODEPOSTBUILD2010FORDOTNET, QString("Xenocode Postbuild 2010 for .NET")},
    {XScanEngine::RECORD_NAME_XENOCODEPOSTBUILD, QString("Xenocode Postbuild")},
    {XScanEngine::RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2009, QString("Xenocode Virtual Application Studio 2009")},
    {XScanEngine::RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010, QString("Xenocode Virtual Application Studio 2010")},
    {XScanEngine::RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010ISVEDITION, QString("Xenocode Virtual Application Studio 2010 ISV Edition")},
    {XScanEngine::RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2012ISVEDITION, QString("Xenocode Virtual Application Studio 2012 ISV Edition")},
    {XScanEngine::RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2013ISVEDITION, QString("Xenocode Virtual Application Studio 2013 ISV Edition")},
    {XScanEngine::RECORD_NAME_XML, QString("XML")},
    {XScanEngine::RECORD_NAME_XPACK, QString("XPack")},
    {XScanEngine::RECORD_NAME_XTREAMLOK, QString("Xtreamlok")},
    {XScanEngine::RECORD_NAME_XTREMEPROTECTOR, QString("Xtreme-Protector")},
    {XScanEngine::RECORD_NAME_XVOLKOLAK, QString("XVolkolak")},
    {XScanEngine::RECORD_NAME_XZ, QString("XZ")},
    {XScanEngine::RECORD_NAME_YANDEX, QString("Yandex")},
    {XScanEngine::RECORD_NAME_YANO, QString("Yano")},
    {XScanEngine::RECORD_NAME_YIDUN, QString("yidun")},
    {XScanEngine::RECORD_NAME_YODASCRYPTER, QString("Yoda's Crypter")},
    {XScanEngine::RECORD_NAME_YODASPROTECTOR, QString("Yoda's Protector")},
    {XScanEngine::RECORD_NAME_YZPACK, QString("YZPack")},
    {XScanEngine::RECORD_NAME_ZELDACRYPT, QString("ZeldaCrypt")},
    {XScanEngine::RECORD_NAME_ZIG, QString("Zig")},
    {XScanEngine::RECORD_NAME_ZIP, QString("ZIP")},
    {XScanEngine::RECORD_NAME_ZLIB, QString("zlib")},
    {XScanEngine::RECORD_NAME_ZPROTECT, QString("ZProtect")},
    {XScanEngine::RECORD_NAME_UNKNOWN0, QString("_Unknown")},
    {XScanEngine::RECORD_NAME_UNKNOWN1, QString("_Unknown")},
    {XScanEngine::RECORD_NAME_UNKNOWN2, QString("_Unknown")},
    {XScanEngine::RECORD_NAME_UNKNOWN3, QString("_Unknown")},
    {XScanEngine::RECORD_NAME_UNKNOWN4, QString("_Unknown")},
    {XScanEngine::RECORD_NAME_UNKNOWN5, QString("_Unknown")},
    {XScanEngine::RECORD_NAME_UNKNOWN6, QString("_Unknown")},
    {XScanEngine::RECORD_NAME_UNKNOWN7, QString("_Unknown")},
    {XScanEngine::RECORD_NAME_UNKNOWN8, QString("_Unknown")},
    {XScanEngine::RECORD_NAME_UNKNOWN9, QString("_Unknown")}};

bool _sortItems(const XScanEngine::SCANSTRUCT &v1, const XScanEngine::SCANSTRUCT &v2)
{
    bool bResult = false;

    bResult = (v1.nPrio < v2.nPrio);

    return bResult;
}

XScanEngine::XScanEngine(QObject *pParent) : XThreadObject(pParent)
{
}

XScanEngine::XScanEngine(const XScanEngine &other) : XThreadObject(other.parent())
{
    m_sFileName = other.m_sFileName;
    m_sDirectoryName = other.m_sDirectoryName;
    m_pDevice = other.m_pDevice;
    m_pData = other.m_pData;
    m_nDataSize = other.m_nDataSize;
    m_pScanOptions = other.m_pScanOptions;
    m_pScanResult = other.m_pScanResult;
    m_scanType = other.m_scanType;
    m_pPdStruct = other.m_pPdStruct;
}

void XScanEngine::setData(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct)
{
    m_sFileName = sFileName;
    m_pScanOptions = pScanOptions;
    m_pScanResult = pScanResult;
    m_pPdStruct = pPdStruct;

    m_scanType = SCAN_TYPE_FILE;
}

void XScanEngine::setData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct)
{
    m_pDevice = pDevice;
    m_pScanOptions = pOptions;
    m_pScanResult = pScanResult;
    m_pPdStruct = pPdStruct;

    m_scanType = SCAN_TYPE_DEVICE;
}

void XScanEngine::setData(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct)
{
    m_pData = pData;
    m_nDataSize = nDataSize;
    m_pScanOptions = pOptions;
    m_pScanResult = pScanResult;
    m_pPdStruct = pPdStruct;

    m_scanType = SCAN_TYPE_MEMORY;
}

void XScanEngine::setData(const QString &sDirectoryName, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    m_sDirectoryName = sDirectoryName;
    m_pScanOptions = pOptions;
    m_pPdStruct = pPdStruct;

    m_scanType = SCAN_TYPE_DIRECTORY;
}

// void XScanEngine::enableDebugLog(bool bState)
// {
//     if (bState) {
//         QLoggingCategory::installFilter(debugLogFilter);
//     }
// }

// void XScanEngine::debugLogFilter(QLoggingCategory *category)
// {
//     qDebug("%s", category->categoryName());
// }

QString XScanEngine::createTypeString(SCAN_OPTIONS *pOptions, const SCANSTRUCT *pScanStruct)
{
    QString sResult;

    if (pScanStruct->parentId.filePart != XBinary::FILEPART_HEADER) {
        sResult += XBinary::recordFilePartIdToString(pScanStruct->parentId.filePart);

        if (pScanStruct->parentId.sVersion != "") {
            if (pOptions->bFormatResult) {
                sResult += " ";
            }
            sResult += QString("(%1)").arg(pScanStruct->parentId.sVersion);
        }

        if (pScanStruct->parentId.sInfo != "") {
            if (pOptions->bFormatResult) {
                sResult += " ";
            }
            sResult += QString("[%1]").arg(pScanStruct->parentId.sInfo);
        }

        sResult += ": ";
    }

    sResult += XBinary::fileTypeIdToString(pScanStruct->id.fileType);

    if (pScanStruct->parentId.filePart != XBinary::FILEPART_HEADER) {
        QString sVersion;

        if (pScanStruct->parentId.compressMethod != XBinary::COMPRESS_METHOD_UNKNOWN) {
            sVersion = XBinary::appendText(sVersion, XBinary::compressMethodToString(pScanStruct->parentId.compressMethod), ", ");
        }

        if (pScanStruct->parentId.sOriginalName != "") {
            sVersion = XBinary::appendText(sVersion, QString("\"%1\"").arg(pScanStruct->parentId.sOriginalName), ", ");
        }

        if (sVersion != "") {
            if (pOptions->bFormatResult) {
                sResult += " ";
            }

            sResult += QString("(%1)").arg(sVersion);
        }

        if (pOptions->bFormatResult) {
            sResult += QString(" [%1 = 0x%2, %3 = 0x%4]")
                           .arg(tr("Offset"), XBinary::valueToHexEx(pScanStruct->parentId.nOffset), tr("Size"), XBinary::valueToHexEx(pScanStruct->parentId.nSize));
        } else {
            sResult += QString("[%1=0x%2,%3=0x%4]")
                           .arg(tr("Offset"), XBinary::valueToHexEx(pScanStruct->parentId.nOffset), tr("Size"), XBinary::valueToHexEx(pScanStruct->parentId.nSize));
        }
    }

    return sResult;
}

XScanEngine::SCANSTRUCT XScanEngine::createHeaderScanStruct(const SCANSTRUCT *pScanStruct)
{
    SCANSTRUCT result = *pScanStruct;

    result.id.sUuid = XBinary::generateUUID();
    result.sType = "";
    result.sName = "";
    result.sVersion = "";
    result.sInfo = "";
    result.varInfo.clear();
    result.varInfo2.clear();
    result.globalColorRecord.colorMain = Qt::transparent;
    result.globalColorRecord.colorBackground = Qt::transparent;

    return result;
}

QString XScanEngine::createResultStringEx(SCAN_OPTIONS *pOptions, const SCANSTRUCT *pScanStruct)
{
    QString sResult;

    if (pScanStruct->bIsHeuristic) {
        sResult += "(Heur)";
        if (pOptions->bFormatResult) {
            sResult += " ";
        }
    } else if (pScanStruct->bIsAHeuristic) {
        sResult += "(A-Heur)";
        if (pOptions->bFormatResult) {
            sResult += " ";
        }
    }

    if (pOptions->bShowType) {
        sResult += QString("%1: ").arg(pScanStruct->sType);
    }

    sResult += pScanStruct->sName;

    if ((pOptions->bShowVersion) && (pScanStruct->sVersion != "")) {
        if (pOptions->bFormatResult) {
            sResult += " ";
        }
        sResult += QString("(%1)").arg(pScanStruct->sVersion);
    }

    if ((pOptions->bShowInfo) && (pScanStruct->sInfo != "")) {
        if (pOptions->bFormatResult) {
            sResult += " ";
        }
        sResult += QString("[%1]").arg(pScanStruct->sInfo);
    }

    return sResult;
}

QString XScanEngine::createShortResultString(XScanEngine::SCAN_OPTIONS *pOptions, const SCAN_RESULT &scanResult)
{
    QString sResult;

    qint64 nNumberOfRecords = scanResult.listRecords.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        SCANSTRUCT scanStruct = scanResult.listRecords.at(i);

        if (scanStruct.id.fileType != XBinary::FT_BINARY) {
            // sResult = createFullResultString2(&scanStruct);
            sResult = QString("%1: %2").arg(XBinary::fileTypeIdToString(scanStruct.id.fileType), createResultStringEx(pOptions, &scanStruct));
            break;
        } else if (!scanStruct.bIsUnknown) {
            sResult = createResultStringEx(pOptions, &scanStruct);
            break;
        }
    }

    return sResult;
}

XOptions::GLOBAL_COLOR_RECORD XScanEngine::typeToGlobalColorRecord(const QString &sType)
{
    XOptions::GLOBAL_COLOR_RECORD result = {};
    result.colorMain = Qt::transparent;
    result.colorBackground = Qt::transparent;

    QString _sType = sType;
    _sType = _sType.toLower().remove("~");
    _sType = _sType.toLower().remove("!");

    // TODO more
    if ((_sType == "installer") || (_sType == "sfx") || (_sType == "archive")) {
        result.colorMain = Qt::blue;
    } else if (isProtection(_sType)) {
        result.colorMain = Qt::red;
    } else if ((_sType == "pe tool") || (_sType == "apk tool")) {
        result.colorMain = Qt::green;
    } else if ((_sType == "operation system") || (_sType == "virtual machine") || (_sType == "platform") || (_sType == "dos extender")) {
        result.colorMain = Qt::darkYellow;
    } else if (_sType == "format") {
        result.colorMain = Qt::darkGreen;
    } else if ((_sType == "sign tool") || (_sType == "certificate") || (_sType == "licensing")) {
        result.colorMain = Qt::darkMagenta;
    } else if (_sType == "language") {
        result.colorMain = Qt::darkCyan;
    } else if ((_sType == "corrupted data") || (_sType == "personal data") || (_sType == "author")) {
        result.colorMain = Qt::darkRed;
    } else if ((_sType == "virus") || (_sType == "trojan") || (_sType == "malware")) {
        result.colorMain = Qt::white;
        result.colorBackground = Qt::darkRed;
    } else if ((_sType == "debug") || (_sType == "debug data")) {
        result.colorMain = Qt::darkBlue;
    } else {
        result.colorMain = Qt::transparent;
    }

    return result;
}

qint32 XScanEngine::typeToPrio(const QString &sType)
{
    qint32 nResult = 0;
    QString _sType = sType;
    _sType = _sType.toLower().remove("~");
    _sType = _sType.toLower().remove("!");

    if ((_sType == "operation system") || (_sType == "virtual machine")) nResult = 10;
    else if (_sType == "format") nResult = 12;
    else if ((_sType == "platform") || (_sType == "dos extender")) nResult = 14;
    else if (_sType == "linker") nResult = 20;
    else if (_sType == "compiler") nResult = 30;
    else if (_sType == "language") nResult = 40;
    else if (_sType == "library") nResult = 50;
    else if ((_sType == "tool") || (_sType == "pe tool") || (_sType == "sign tool") || (_sType == "apk tool")) nResult = 60;
    else if ((_sType == "protector") || (_sType == "cryptor") || (_sType == "crypter")) nResult = 70;
    else if ((_sType == ".net obfuscator") || (_sType == "apk obfuscator") || (_sType == "jar obfuscator")) nResult = 80;
    else if ((_sType == "dongle protection") || (_sType == "protection")) nResult = 90;
    else if ((_sType == "packer") || (_sType == ".net compressor")) nResult = 100;
    else if (_sType == "joiner") nResult = 110;
    else if ((_sType == "sfx") || (_sType == "installer")) nResult = 120;
    else if ((_sType == "virus") || (_sType == "malware") || (_sType == "trojan") || (_sType == "corrupted data") || (_sType == "personal data") || (_sType == "author"))
        nResult = 70;
    else if ((_sType == "debug data") || (_sType == "installer")) nResult = 200;
    else nResult = 1000;

    return nResult;
}

QString XScanEngine::translateType(const QString &sType)
{
    QString sResult;

    QString _sType = sType;

    if (_sType.size() > 1) {
        if (_sType[0] == QChar('~')) {
            _sType.remove(0, 1);
        }
    }

    if (_sType.size() > 1) {
        if (_sType[0] == QChar('!')) {
            _sType.remove(0, 1);
        }
    }

    sResult = _translate(_sType);

    if (sResult.size()) {
        sResult[0] = sResult.at(0).toUpper();
    }

    return sResult;
}

bool XScanEngine::isHeurType(const QString &sType)
{
    bool bResult = false;

    if (sType.size() > 1) {
        if (sType[0] == QChar('~')) {
            bResult = true;
        }
    }

    return bResult;
}

bool XScanEngine::isAHeurType(const QString &sType)
{
    bool bResult = false;

    if (sType.size() > 1) {
        if (sType[0] == QChar('!')) {
            bResult = true;
        }
    }

    return bResult;
}

QString XScanEngine::_translate(const QString &sString)
{
    return XBinary::XCONVERT_translate(sString, _TABLE_XScanEngine_RECORD_TYPE, sizeof(_TABLE_XScanEngine_RECORD_TYPE) / sizeof(XBinary::XCONVERT));
}

void XScanEngine::sortRecords(QList<SCANSTRUCT> *pListRecords)
{
    std::sort(pListRecords->begin(), pListRecords->end(), _sortItems);
}

QString XScanEngine::getProtection(SCAN_OPTIONS *pScanOptions, QList<SCANSTRUCT> *pListRecords)
{
    QString sResult;

    qint32 nNumberOfRecords = pListRecords->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if (pListRecords->at(i).bIsProtection) {
            SCANSTRUCT scanStruct = pListRecords->at(i);
            sResult = createResultStringEx(pScanOptions, &scanStruct);
            break;
        }
    }

    return sResult;
}

bool XScanEngine::isProtection(const QString &sType)
{
    bool bResult = false;

    QString _sType = sType;
    _sType = _sType.toLower();

    if ((_sType == "protector") || (_sType == "apk obfuscator") || (_sType == "jar obfuscator") || (_sType == ".net obfuscator") || (_sType == ".net compressor") ||
        (_sType == "dongle protection") || (_sType == "joiner") || (_sType == "packer") || (_sType == "protection") || (_sType == "crypter") || (_sType == "cryptor")) {
        bResult = true;
    }

    return bResult;
}

bool XScanEngine::isScanable(const QSet<XBinary::FT> &stFT)
{
    return (stFT.contains(XBinary::FT_MSDOS) || stFT.contains(XBinary::FT_NE) || stFT.contains(XBinary::FT_LE) || stFT.contains(XBinary::FT_LX) ||
            stFT.contains(XBinary::FT_PE) || stFT.contains(XBinary::FT_ELF) || stFT.contains(XBinary::FT_MACHO) || stFT.contains(XBinary::FT_DEX) ||
            stFT.contains(XBinary::FT_PDF) || stFT.contains(XBinary::FT_ARCHIVE));
}

XScanEngine::SCAN_RESULT XScanEngine::scanDevice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};

    XScanEngine::SCANID parentId = {};
    parentId.fileType = XBinary::FT_UNKNOWN;

    if (pOptions->initFilePart == XBinary::FILEPART_UNKNOWN) {
        parentId.filePart = XBinary::FILEPART_HEADER;
    } else {
        parentId.filePart = pOptions->initFilePart;
    }

    scanProcess(pDevice, &result, 0, pDevice->size(), parentId, pOptions, true, pPdStruct);

    return result;
}

XScanEngine::SCAN_RESULT XScanEngine::scanFile(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};

    if (sFileName != "") {
        QFile file;
        file.setFileName(sFileName);

        if (file.open(QIODevice::ReadOnly)) {
            result = scanDevice(&file, pOptions, pPdStruct);
            file.close();
        }
    }

    return result;
}

XScanEngine::SCAN_RESULT XScanEngine::scanMemory(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};

    QBuffer buffer;

    buffer.setData(pData, nDataSize);

    if (buffer.open(QIODevice::ReadOnly)) {
        result = scanDevice(&buffer, pOptions, pPdStruct);

        buffer.close();
    }

    return result;
}

XScanEngine::SCAN_RESULT XScanEngine::scanSubdevice(QIODevice *pDevice, qint64 nOffset, qint64 nSize, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};

    if (XBinary::isOffsetAndSizeValid(pDevice, nOffset, nSize)) {
        SubDevice sd(pDevice, nOffset, nSize);

        if (sd.open(QIODevice::ReadOnly)) {
            result = scanDevice(&sd, pOptions, pPdStruct);

            sd.close();
        }
    }

    return result;
}

void XScanEngine::scanProcess(QIODevice *pDevice, SCAN_RESULT *pScanResult, qint64 nOffset, qint64 nSize, SCANID parentId, SCAN_OPTIONS *pScanOptions, bool bInit,
                              XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer *pScanTimer = nullptr;

    if (bInit) {
        pScanTimer = new QElapsedTimer;
        pScanTimer->start();
        pScanResult->sFileName = XBinary::getDeviceFileName(pDevice);
        pScanResult->nSize = nSize;
    }

    QIODevice *_pDevice = nullptr;
    SubDevice *pSd = nullptr;
    char *pBuffer = nullptr;
    QBuffer *bufDevice = nullptr;

    if ((nOffset == 0) && (pDevice->size() == nSize)) {
        _pDevice = pDevice;
    } else {
        pSd = new SubDevice(pDevice, nOffset, nSize);
        pSd->open(QIODevice::ReadOnly);
        _pDevice = pSd;
    }

    bool bMemory = false;

    if (pScanOptions->nBufferSize) {
        if (nSize <= pScanOptions->nBufferSize) {
            bool bIsBuffer = _pDevice->property("Memory").toBool();

            if (!bIsBuffer) {
                bMemory = true;
            }
        }
    }

    // TODO Check if not in memory already
    if (bMemory) {
        bufDevice = new QBuffer;

        pBuffer = new char[nSize];

        if (nSize) {
            XBinary::read_array_process(_pDevice, 0, pBuffer, nSize, pPdStruct);
        }

        bufDevice->setData(pBuffer, nSize);
        bufDevice->open(QIODevice::ReadOnly);

        bufDevice->setProperty("Memory", true);
        bufDevice->setProperty("FileName", XBinary::getDeviceFileName(_pDevice));

        _pDevice = bufDevice;
    }

    QSet<XBinary::FT> stFT = XFormats::getFileTypes(_pDevice, true, pPdStruct);
    QSet<XBinary::FT> stFTOriginal = stFT;

    if (bInit || (pScanOptions->fileType == XBinary::FT_BINARY)) {
        if (pScanOptions->fileType != XBinary::FT_UNKNOWN) {
            XBinary::filterFileTypes(&stFT, pScanOptions->fileType);
        }
    }

    if (pScanOptions->bIsAllTypesScan) {
        if (stFT.contains(XBinary::FT_PE32) || stFT.contains(XBinary::FT_PE64) || stFT.contains(XBinary::FT_LE) || stFT.contains(XBinary::FT_LX) ||
            stFT.contains(XBinary::FT_NE)) {
            _processDetect(0, pScanResult, _pDevice, parentId, XBinary::FT_MSDOS, pScanOptions, true, pPdStruct);
        }

        if (stFT.contains(XBinary::FT_APK) || stFT.contains(XBinary::FT_IPA)) {
            _processDetect(0, pScanResult, _pDevice, parentId, XBinary::FT_JAR, pScanOptions, true, pPdStruct);
            _processDetect(0, pScanResult, _pDevice, parentId, XBinary::FT_ZIP, pScanOptions, true, pPdStruct);
        }

        if (stFT.contains(XBinary::FT_JAR)) {
            _processDetect(0, pScanResult, _pDevice, parentId, XBinary::FT_ZIP, pScanOptions, true, pPdStruct);
        }

        if (stFT.contains(XBinary::FT_DOS4G)) {
            _processDetect(0, pScanResult, _pDevice, parentId, XBinary::FT_DOS16M, pScanOptions, true, pPdStruct);
        }
    }

    XScanEngine::SCANID scanIdMain = {};

    if (stFT.contains(XBinary::FT_PE32)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_PE32, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_PE32;
    } else if (stFT.contains(XBinary::FT_PE64)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_PE64, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_PE64;
    } else if (stFT.contains(XBinary::FT_ELF32)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_ELF32, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_ELF32;
    } else if (stFT.contains(XBinary::FT_ELF64)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_ELF64, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_ELF64;
    } else if (stFT.contains(XBinary::FT_MACHO32)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_MACHO32, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_MACHO32;
    } else if (stFT.contains(XBinary::FT_MACHO64)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_MACHO64, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_MACHO64;
    } else if (stFT.contains(XBinary::FT_LX)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_LX, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_LX;
    } else if (stFT.contains(XBinary::FT_LE)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_LE, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_LE;
    } else if (stFT.contains(XBinary::FT_NE)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_NE, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_NE;
    } else if (stFT.contains(XBinary::FT_DOS16M)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_DOS16M, pScanOptions, false, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_DOS16M;
    } else if (stFT.contains(XBinary::FT_DOS4G)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_DOS4G, pScanOptions, false, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_DOS4G;
    } else if (stFT.contains(XBinary::FT_MSDOS)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_MSDOS, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_MSDOS;
    } else if (stFT.contains(XBinary::FT_APK)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_APK, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_APK;
    } else if (stFT.contains(XBinary::FT_IPA)) {
        // _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_IPA, pScanOptions, true, pPdStruct);
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_BINARY, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_IPA;
    } else if (stFT.contains(XBinary::FT_JAR)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_JAR, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_JAR;
    } else if (stFT.contains(XBinary::FT_ZIP)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_ZIP, pScanOptions, true, pPdStruct);
        //_processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_BINARY, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_ZIP;
    } else if (stFT.contains(XBinary::FT_DEX)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_DEX, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_DEX;
    } else if (stFT.contains(XBinary::FT_NPM)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_NPM, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_NPM;
    } else if (stFT.contains(XBinary::FT_MACHOFAT)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_MACHOFAT, pScanOptions, false, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_MACHOFAT;
    } else if (stFT.contains(XBinary::FT_BWDOS16M)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_BWDOS16M, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_BWDOS16M;
    } else if (stFT.contains(XBinary::FT_AMIGAHUNK)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_AMIGAHUNK, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_AMIGAHUNK;
    } else if (stFT.contains(XBinary::FT_PDF)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_PDF, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_PDF;
    } else if (stFT.contains(XBinary::FT_CFBF)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_CFBF, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_CFBF;
    } else if (stFT.contains(XBinary::FT_RAR)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_RAR, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_RAR;
    } else if (stFT.contains(XBinary::FT_ISO9660)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_ISO9660, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_ISO9660;
    } else if (stFT.contains(XBinary::FT_JPEG)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_JPEG, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_JPEG;
    } else if (stFT.contains(XBinary::FT_PNG)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_PNG, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_PNG;
    } else if (stFT.contains(XBinary::FT_JAVACLASS)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_JAVACLASS, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_JAVACLASS;
    } else if (stFT.contains(XBinary::FT_PYC)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_PYC, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_PYC;
    } else if (stFT.contains(XBinary::FT_COM)) {
        XScanEngine::SCAN_RESULT _scanResultCOM = {};
        XScanEngine::SCAN_RESULT _scanResultBinary = {};

        if (pScanOptions->bIsDeepScan) {
            _processDetect(&scanIdMain, &_scanResultBinary, _pDevice, parentId, XBinary::FT_BINARY, pScanOptions, false, pPdStruct);
        }

        bool bIsBinary = _scanResultBinary.listRecords.count();

        {
            XCOM xcom(_pDevice);

            if (xcom.isValid(pPdStruct)) {
                _processDetect(&scanIdMain, &_scanResultCOM, _pDevice, parentId, XBinary::FT_COM, pScanOptions, !bIsBinary, pPdStruct);
            }
        }

        pScanResult->listRecords.append(_scanResultBinary.listRecords);
        pScanResult->listErrors.append(_scanResultBinary.listErrors);
        pScanResult->listDebugRecords.append(_scanResultBinary.listDebugRecords);

        pScanResult->listRecords.append(_scanResultCOM.listRecords);
        pScanResult->listErrors.append(_scanResultCOM.listErrors);
        pScanResult->listDebugRecords.append(_scanResultCOM.listDebugRecords);

        if (bInit) pScanResult->ftInit = XBinary::FT_COM;
    } else if (stFT.contains(XBinary::FT_ARCHIVE) && (stFT.size() == 1)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_ARCHIVE, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_ARCHIVE;
    } else if (stFT.contains(XBinary::FT_IMAGE) && (stFT.size() == 1)) {
        _processDetect(&scanIdMain, pScanResult, _pDevice, parentId, XBinary::FT_IMAGE, pScanOptions, true, pPdStruct);
        if (bInit) pScanResult->ftInit = XBinary::FT_IMAGE;
    } else {
        XScanEngine::SCAN_RESULT _scanResultCOM = {};
        XScanEngine::SCAN_RESULT _scanResultBinary = {};

        {
            XCOM xcom(_pDevice);

            if (xcom.isValid(pPdStruct)) {
                XScanEngine::SCAN_OPTIONS _options = *pScanOptions;
                _options.bIsVerbose = false;  // do not show Operation System

                _processDetect(&scanIdMain, &_scanResultCOM, _pDevice, parentId, XBinary::FT_COM, &_options, false, pPdStruct);
            }
        }

        bool bIsCOM = _scanResultCOM.listRecords.count();

        _processDetect(&scanIdMain, &_scanResultBinary, _pDevice, parentId, XBinary::FT_BINARY, pScanOptions, !bIsCOM, pPdStruct);

        pScanResult->listRecords.append(_scanResultBinary.listRecords);
        pScanResult->listErrors.append(_scanResultBinary.listErrors);
        pScanResult->listDebugRecords.append(_scanResultBinary.listDebugRecords);

        pScanResult->listRecords.append(_scanResultCOM.listRecords);
        pScanResult->listErrors.append(_scanResultCOM.listErrors);
        pScanResult->listDebugRecords.append(_scanResultCOM.listDebugRecords);

        pScanResult->ftInit = XBinary::FT_BINARY;
    }

    if (pScanOptions->bIsRecursiveScan) {
        // {
        //     QList<XArchive::RECORD> listRecords;
        //     XBinary::FT _fileType = XBinary::FT_UNKNOWN;

        //     if (stFTOriginal.contains(XBinary::FT_ARCHIVE) && (!stFTOriginal.contains(XBinary::FT_ZIP))) {
        //         _fileType = XBinary::_getPrefFileType(&stFT);
        //         listRecords = XArchives::getRecords(_pDevice, _fileType, 20000, pPdStruct);
        //     }

        //     if (listRecords.count()) {
        //         qint32 nNumberOfRecords = listRecords.count();
        //         qint32 nMaxCount = 20;
        //         // qint32 nMaxCount = -1;
        //         qint32 nCount = 0;

        //         bool bScanAll = false;
        //         bool bShowFileName = true;

        //         if (((_fileType == XBinary::FT_ZLIB) || (_fileType == XBinary::FT_BZIP2) || (_fileType == XBinary::FT_LHA) || (_fileType == XBinary::FT_GZIP) ||
        //              (_fileType == XBinary::FT_SZDD) || (_fileType == XBinary::FT_XZ)) &&
        //             (nNumberOfRecords == 1)) {
        //             bScanAll = true;
        //             bShowFileName = false;
        //         } else if ((_fileType == XBinary::FT_MACHOFAT) || (_fileType == XBinary::FT_DOS16M) || (_fileType == XBinary::FT_DOS4G)) {
        //             bScanAll = true;
        //         }

        //         qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
        //         XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nNumberOfRecords);

        //         for (qint32 i = 0; (i < nNumberOfRecords) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        //             XArchive::RECORD _record = listRecords.at(i);
        //             QByteArray baRecordData = XArchives::decompress(_pDevice, &_record, pPdStruct, 0, 0x200);

        //             QSet<XBinary::FT> _stFT = XFormats::getFileTypes(&baRecordData, true);

        //             if (bScanAll || isScanable(_stFT)) {
        //                 if ((nCount < nMaxCount) || (nMaxCount == -1)) {
        //                     XScanEngine::SCANID scanIdArchiveRecord = scanIdMain;
        //                     scanIdArchiveRecord.filePart = XBinary::FILEPART_STREAM;
        //                     scanIdArchiveRecord.fileType = _fileType;

        //                     XScanEngine::SCAN_OPTIONS _options = *pScanOptions;
        //                     _options.fileType = XBinary::FT_UNKNOWN;
        //                     _options.bIsRecursiveScan = false;

        //                     if (bShowFileName) {
        //                         scanIdArchiveRecord.sInfo = listRecords.at(i).spInfo.sRecordName;
        //                     }

        //                     qint64 _nUncompressedSize = listRecords.at(i).spInfo.nUncompressedSize;
        //                     qint64 _nRecordDataSize = baRecordData.size();

        //                     if (_nUncompressedSize && _nRecordDataSize) {
        //                         if (_nUncompressedSize > _nRecordDataSize) {
        //                             bool _bMemory = false;

        //                             if (pScanOptions->nBufferSize) {
        //                                 if (_nUncompressedSize <= pScanOptions->nBufferSize) {
        //                                     _bMemory = true;
        //                                 }
        //                             }

        //                             if (_bMemory) {
        //                                 char *pArchBuffer = new char[_nUncompressedSize];

        //                                 QBuffer buffer;
        //                                 buffer.setData(pArchBuffer, _nUncompressedSize);

        //                                 if (buffer.open(QIODevice::ReadWrite)) {
        //                                     if (XArchives::decompressToDevice(_pDevice, &_record, &buffer, pPdStruct)) {
        //                                         scanProcess(&buffer, pScanResult, 0, buffer.size(), scanIdArchiveRecord, &_options, false, pPdStruct);
        //                                     }

        //                                     buffer.close();
        //                                 }

        //                                 delete[] pArchBuffer;
        //                             } else {
        //                                 QTemporaryFile fileTemp;

        //                                 if (fileTemp.open()) {
        //                                     QString sTempFileName = fileTemp.fileName();

        //                                     if (XArchives::decompressToFile(_pDevice, &_record, sTempFileName, pPdStruct)) {
        //                                         QFile file;
        //                                         file.setFileName(sTempFileName);

        //                                         if (file.open(QIODevice::ReadOnly)) {
        //                                             scanProcess(&file, pScanResult, 0, file.size(), scanIdArchiveRecord, &_options, false, pPdStruct);
        //                                             file.close();
        //                                         }
        //                                     }
        //                                 }
        //                             }
        //                         } else {
        //                             QBuffer buffer(&baRecordData);

        //                             if (buffer.open(QIODevice::ReadOnly)) {
        //                                 scanProcess(&buffer, pScanResult, 0, buffer.size(), scanIdArchiveRecord, &_options, false, pPdStruct);

        //                                 buffer.close();
        //                             }
        //                         }
        //                     }
        //                     nCount++;
        //                 } else {
        //                     break;
        //                 }
        //             }

        //             XBinary::setPdStructCurrentIncrement(pPdStruct, _nFreeIndex);
        //             XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, listRecords.at(i).spInfo.sRecordName);
        //         }

        //         XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
        //     }
        // }

        {
            QList<XBinary::FPART> listFileParts = XFormats::getFileParts(
                pScanResult->ftInit, _pDevice, XBinary::FILEPART_RESOURCE | XBinary::FILEPART_OVERLAY | XBinary::FILEPART_STREAM | XBinary::FILEPART_DEBUGDATA, 20000,
                false, -1, pPdStruct);

            qint32 nMaxCount = 20;
            qint32 nCount = 0;

            qint32 nNumberOfFileParts = listFileParts.count();

            if (nNumberOfFileParts > 0) {
                for (qint32 i = 0; i < nNumberOfFileParts; i++) {
                    XBinary::FPART filePart = listFileParts.at(i);

                    if (XBinary::isOffsetAndSizeValid(_pDevice, filePart.nFileOffset, filePart.nFileSize)) {
                        XCompressedDevice compDevice;

                        if (compDevice.setData(_pDevice, filePart, pPdStruct)) {
                            if (compDevice.open(QIODevice::ReadOnly)) {
                                bool bProcess = false;

                                if (filePart.filePart == XBinary::FILEPART_OVERLAY) {
                                    bProcess = true;  // always scan overlay
                                } else if (filePart.filePart == XBinary::FILEPART_DEBUGDATA) {
                                    bProcess = true;  // always scan debug data
                                } else if ((filePart.filePart == XBinary::FILEPART_RESOURCE) || (filePart.filePart == XBinary::FILEPART_STREAM)) {
                                    QSet<XBinary::FT> _stFT = XFormats::getFileTypes(&compDevice, 0, -1, true, pPdStruct);
                                    bProcess = isScanable(_stFT);
                                }

                                if (bProcess) {
                                    XScanEngine::SCANID scanIdSub = scanIdMain;
                                    scanIdSub.filePart = filePart.filePart;
                                    scanIdSub.nOffset = filePart.nFileOffset;
                                    scanIdSub.nSize = filePart.nFileSize;
                                    scanIdSub.sOriginalName = filePart.mapProperties.value(XBinary::FPART_PROP_ORIGINALNAME).toString();
                                    scanIdSub.compressMethod =
                                        (XBinary::COMPRESS_METHOD)filePart.mapProperties.value(XBinary::FPART_PROP_COMPRESSMETHOD, XBinary::COMPRESS_METHOD_STORE)
                                            .toUInt();

                                    XScanEngine::SCAN_OPTIONS _options = *pScanOptions;
                                    _options.fileType = XBinary::FT_UNKNOWN;
                                    _options.bIsRecursiveScan = false;

                                    compDevice.setProperty("FileName", filePart.mapProperties.value(XBinary::FPART_PROP_ORIGINALNAME).toString());
                                    scanProcess(&compDevice, pScanResult, 0, compDevice.size(), scanIdSub, &_options, false, pPdStruct);
                                    nCount++;
                                }

                                compDevice.close();
                            }
                        }
                    }

                    if (nCount >= nMaxCount) {
                        break;
                    }
                }
            }
        }
    }

    if (bufDevice) {
        bufDevice->close();
        delete bufDevice;
    }

    if (pBuffer) {
        delete[] pBuffer;
    }

    if (pSd) {
        pSd->close();

        delete pSd;
    }

    if (pScanTimer) {
        pScanResult->nScanTime = pScanTimer->elapsed();

        delete pScanTimer;
    }
}

QMap<quint64, QString> XScanEngine::getScanFlags()
{
    QMap<quint64, QString> mapResult;

    mapResult.insert(SF_RECURSIVESCAN, tr("Recursive scan"));
    mapResult.insert(SF_DEEPSCAN, tr("Deep scan"));
    mapResult.insert(SF_HEURISTICSCAN, tr("Heuristic scan"));
#ifdef QT_DEBUG
    mapResult.insert(SF_AGGRESSIVESCAN, tr("Aggressive scan"));
#endif
    mapResult.insert(SF_VERBOSE, tr("Verbose"));
    mapResult.insert(SF_ALLTYPESSCAN, tr("All types"));

    return mapResult;
}

quint64 XScanEngine::getScanFlags(SCAN_OPTIONS *pScanOptions)
{
    quint64 nResult = 0;

    if (pScanOptions->bIsRecursiveScan) {
        nResult |= SF_RECURSIVESCAN;
    }

    if (pScanOptions->bIsDeepScan) {
        nResult |= SF_DEEPSCAN;
    }

    if (pScanOptions->bIsHeuristicScan) {
        nResult |= SF_HEURISTICSCAN;
    }

    if (pScanOptions->bIsAggressiveScan) {
        nResult |= SF_AGGRESSIVESCAN;
    }

    if (pScanOptions->bIsVerbose) {
        nResult |= SF_VERBOSE;
    }

    if (pScanOptions->bIsAllTypesScan) {
        nResult |= SF_ALLTYPESSCAN;
    }

    if (pScanOptions->bResultAsJSON) {
        nResult |= SF_RESULTASJSON;
    }

    if (pScanOptions->bResultAsXML) {
        nResult |= SF_RESULTASXML;
    }

    if (pScanOptions->bResultAsCSV) {
        nResult |= SF_RESULTASCSV;
    }

    if (pScanOptions->bUseCache) {
        nResult |= SF_USECACHE;
    }

    if (pScanOptions->bFormatResult) {
        nResult |= SF_FORMATRESULT;
    }

    return nResult;
}

void XScanEngine::setScanFlags(SCAN_OPTIONS *pScanOptions, quint64 nFlags)
{
    pScanOptions->bIsRecursiveScan = nFlags & SF_RECURSIVESCAN;
    pScanOptions->bIsDeepScan = nFlags & SF_DEEPSCAN;
    pScanOptions->bIsHeuristicScan = nFlags & SF_HEURISTICSCAN;
    pScanOptions->bIsAggressiveScan = nFlags & SF_AGGRESSIVESCAN;
    pScanOptions->bIsVerbose = nFlags & SF_VERBOSE;
    pScanOptions->bIsAllTypesScan = nFlags & SF_ALLTYPESSCAN;
    pScanOptions->bResultAsJSON = nFlags & SF_RESULTASJSON;
    pScanOptions->bResultAsXML = nFlags & SF_RESULTASXML;
    pScanOptions->bResultAsCSV = nFlags & SF_RESULTASCSV;
    pScanOptions->bUseCache = nFlags & SF_USECACHE;
    pScanOptions->bFormatResult = nFlags & SF_FORMATRESULT;
}

quint64 XScanEngine::getScanFlagsFromGlobalOptions(XOptions *pGlobalOptions)
{
    quint64 nResult = 0;

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FLAG_RECURSIVE).toBool()) {
        nResult |= SF_RECURSIVESCAN;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FLAG_DEEP).toBool()) {
        nResult |= SF_DEEPSCAN;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FLAG_HEURISTIC).toBool()) {
        nResult |= SF_HEURISTICSCAN;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FLAG_AGGRESSIVE).toBool()) {
        nResult |= SF_AGGRESSIVESCAN;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FLAG_VERBOSE).toBool()) {
        nResult |= SF_VERBOSE;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FLAG_ALLTYPES).toBool()) {
        nResult |= SF_ALLTYPESSCAN;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_USECACHE).toBool()) {
        nResult |= SF_USECACHE;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_FORMATRESULT).toBool()) {
        nResult |= SF_FORMATRESULT;
    }

    return nResult;
}

void XScanEngine::setScanFlagsToGlobalOptions(XOptions *pGlobalOptions, quint64 nFlags)
{
    pGlobalOptions->setValue(XOptions::ID_SCAN_FLAG_RECURSIVE, nFlags & SF_RECURSIVESCAN);
    pGlobalOptions->setValue(XOptions::ID_SCAN_FLAG_DEEP, nFlags & SF_DEEPSCAN);
    pGlobalOptions->setValue(XOptions::ID_SCAN_FLAG_HEURISTIC, nFlags & SF_HEURISTICSCAN);
    pGlobalOptions->setValue(XOptions::ID_SCAN_FLAG_AGGRESSIVE, nFlags & SF_AGGRESSIVESCAN);
    pGlobalOptions->setValue(XOptions::ID_SCAN_FLAG_VERBOSE, nFlags & SF_VERBOSE);
    pGlobalOptions->setValue(XOptions::ID_SCAN_FLAG_ALLTYPES, nFlags & SF_ALLTYPESSCAN);
    pGlobalOptions->setValue(XOptions::ID_SCAN_USECACHE, nFlags & SF_USECACHE);
    pGlobalOptions->setValue(XOptions::ID_SCAN_FORMATRESULT, nFlags & SF_FORMATRESULT);
}

XScanEngine::SCAN_OPTIONS XScanEngine::getDefaultOptions(quint64 nFlags)
{
    XScanEngine::SCAN_OPTIONS result = {};

    result.bShowType = true;
    result.bShowVersion = true;
    result.bShowInfo = true;
    result.nBufferSize = 2 * 1024 * 1024;

    setScanFlags(&result, nFlags);

    return result;
}

QMap<quint64, QString> XScanEngine::getDatabases()
{
    QMap<quint64, QString> mapResult;

    mapResult.insert(DATABASE_MAIN, tr("Main"));
    mapResult.insert(DATABASE_EXTRA, tr("Extra"));
    mapResult.insert(DATABASE_CUSTOM, tr("Custom"));

    return mapResult;
}

quint64 XScanEngine::getDatabases(SCAN_OPTIONS *pScanOptions)
{
    quint64 nResult = DATABASE_MAIN;

    if (pScanOptions->bUseExtraDatabase) {
        nResult |= DATABASE_EXTRA;
    }

    if (pScanOptions->bUseCustomDatabase) {
        nResult |= DATABASE_CUSTOM;
    }

    return nResult;
}

void XScanEngine::setDatabases(SCAN_OPTIONS *pScanOptions, quint64 nDatabases)
{
    pScanOptions->bUseExtraDatabase = (nDatabases & DATABASE_EXTRA);
    pScanOptions->bUseCustomDatabase = (nDatabases & DATABASE_CUSTOM);
}

quint64 XScanEngine::getDatabasesFromGlobalOptions(XOptions *pGlobalOptions)
{
    quint64 nResult = DATABASE_MAIN;

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_DATABASE_EXTRA_ENABLED).toBool()) {
        nResult |= DATABASE_EXTRA;
    }

    if (pGlobalOptions->getValue(XOptions::ID_SCAN_DATABASE_CUSTOM_ENABLED).toBool()) {
        nResult |= DATABASE_CUSTOM;
    }

    return nResult;
}

void XScanEngine::setDatabasesToGlobalOptions(XOptions *pGlobalOptions, quint64 nDatabases)
{
    pGlobalOptions->setValue(XOptions::ID_SCAN_DATABASE_EXTRA_ENABLED, nDatabases & DATABASE_EXTRA);
    pGlobalOptions->setValue(XOptions::ID_SCAN_DATABASE_CUSTOM_ENABLED, nDatabases & DATABASE_CUSTOM);
}

void XScanEngine::process()
{
    XBinary::PDSTRUCT *pPdStruct = m_pPdStruct;

    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);

    if (m_scanType == SCAN_TYPE_FILE) {
        if ((m_pScanResult) && (m_sFileName != "")) {
            XBinary::setPdStructInit(pPdStruct, _nFreeIndex, 0);
            XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, tr("File scan"));

            emit scanFileStarted(m_sFileName);

            *m_pScanResult = scanFile(m_sFileName, m_pScanOptions, pPdStruct);

            emit scanResult(*m_pScanResult);
        }
    } else if (m_scanType == SCAN_TYPE_DEVICE) {
        if (m_pDevice) {
            XBinary::setPdStructInit(pPdStruct, _nFreeIndex, 0);
            XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, tr("Device scan"));

            *m_pScanResult = scanDevice(m_pDevice, m_pScanOptions, pPdStruct);

            emit scanResult(*m_pScanResult);
        }
    } else if (m_scanType == SCAN_TYPE_MEMORY) {
        XBinary::setPdStructInit(pPdStruct, _nFreeIndex, 0);
        XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, tr("Memory scan"));

        *m_pScanResult = scanMemory(m_pData, m_nDataSize, m_pScanOptions, pPdStruct);

        emit scanResult(*m_pScanResult);
    } else if (m_scanType == SCAN_TYPE_DIRECTORY) {
        if (m_sDirectoryName != "") {
            XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, tr("Directory scan"));
            QList<QString> listFileNames;

            XBinary::findFiles(m_sDirectoryName, &listFileNames, m_pScanOptions->bSubdirectories, 0, pPdStruct);

            qint32 nTotal = listFileNames.count();

            XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nTotal);

            for (qint32 i = 0; (i < nTotal) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
                QString sFileName = listFileNames.at(i);

                XBinary::setPdStructCurrent(pPdStruct, _nFreeIndex, i);
                XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, sFileName);

                emit scanFileStarted(sFileName);

                XScanEngine::SCAN_RESULT _scanResult = scanFile(sFileName, m_pScanOptions, pPdStruct);

                emit scanResult(_scanResult);
            }
        }
    }

    XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
}

void XScanEngine::_errorMessage(SCAN_OPTIONS *pOptions, const QString &sErrorMessage)
{
    Q_UNUSED(pOptions)
    // g_bIsErrorLogEnable = true;
    // g_bIsWarningLogEnable = false;
    // g_bIsInfoLogEnable = false;

    // if ((pOptions->bResultAsCSV) || (pOptions->bResultAsJSON) || (pOptions->bResultAsTSV) || (pOptions->bResultAsXML)) {
    //     g_bIsErrorLogEnable = false;
    //     g_bIsWarningLogEnable = false;
    //     g_bIsInfoLogEnable = false;
    // }

    // if (pOptions->bLogProfiling) {
    //     g_bIsInfoLogEnable = true;
    //     g_bIsWarningLogEnable = true;
    // }

    emit errorMessage(sErrorMessage);
}

void XScanEngine::_warningMessage(SCAN_OPTIONS *pOptions, const QString &sWarningMessage)
{
    Q_UNUSED(pOptions)
    emit errorMessage(sWarningMessage);
}

void XScanEngine::_infoMessage(SCAN_OPTIONS *pOptions, const QString &sInfoMessage)
{
    Q_UNUSED(pOptions)
    emit errorMessage(sInfoMessage);
}

QString XScanEngine::recordTypeIdToString(qint32 nId)
{
    return XBinary::XCONVERT_idToTransString(nId, _TABLE_XScanEngine_RECORD_TYPE, sizeof(_TABLE_XScanEngine_RECORD_TYPE) / sizeof(XBinary::XCONVERT));
}

QString XScanEngine::recordNameIdToString(qint32 nId)
{
    return XBinary::XIDSTRING_idToString(nId, _TABLE_XScanEngine_RECORD_NAME, sizeof(_TABLE_XScanEngine_RECORD_NAME) / sizeof(XBinary::XIDSTRING));
}

bool XScanEngine::isScanStructPresent(QList<XScanEngine::SCANSTRUCT> *pListScanStructs, XBinary::FT fileType, RECORD_TYPE type, RECORD_NAME name, const QString &sVersion,
                                      const QString &sInfo)
{
    bool bResult = false;

    if (pListScanStructs) {
        for (int i = 0; i < pListScanStructs->count(); i++) {
            const XScanEngine::SCANSTRUCT &ss = pListScanStructs->at(i);
            if ((ss.nType == (quint32)type) && (ss.nName == (quint32)name) && (ss.sVersion == sVersion) && (ss.sInfo == sInfo)) {
                bResult = true;
                break;
            }
        }
    }

    return bResult;
}

XScanEngine::TEST_RESULT XScanEngine::test(const QString &sDirectoryName)
{
    TEST_RESULT result = {};
    result.nTotal = 0;
    result.nErrors = 0;

    QString sJsonFileName = sDirectoryName + QDir::separator() + "tests.json";
    QFile jsonFile(sJsonFileName);

    if (!jsonFile.exists()) {
        _errorMessage(nullptr, QString("JSON file not found: %1").arg(sJsonFileName));
        result.nErrors++;
        return result;
    }

    if (!jsonFile.open(QIODevice::ReadOnly)) {
        _errorMessage(nullptr, QString("Cannot open JSON file: %1").arg(sJsonFileName));
        result.nErrors++;
        return result;
    }

    QByteArray baJsonData = jsonFile.readAll();
    jsonFile.close();

    QJsonDocument jsonDoc = QJsonDocument::fromJson(baJsonData);

    if (jsonDoc.isNull() || !jsonDoc.isObject()) {
        _errorMessage(nullptr, QString("Invalid JSON format in: %1").arg(sJsonFileName));
        result.nErrors++;
        return result;
    }

    QJsonObject jsonObject = jsonDoc.object();
    QJsonArray testCases = jsonObject.value("testCases").toArray();

    if (testCases.isEmpty()) {
        _errorMessage(nullptr, QString("No test cases found in: %1").arg(sJsonFileName));
        result.nErrors++;
        return result;
    }

    quint64 nScanFlags = 0;
    if (jsonObject.contains("defaultScanFlags")) {
        QJsonObject defaultScanFlagsObj = jsonObject.value("defaultScanFlags").toObject();
        if (defaultScanFlagsObj.value("recursiveScan").toBool()) nScanFlags |= SF_RECURSIVESCAN;
        if (defaultScanFlagsObj.value("deepScan").toBool()) nScanFlags |= SF_DEEPSCAN;
        if (defaultScanFlagsObj.value("heuristicScan").toBool()) nScanFlags |= SF_HEURISTICSCAN;
        if (defaultScanFlagsObj.value("aggressiveScan").toBool()) nScanFlags |= SF_AGGRESSIVESCAN;
        if (defaultScanFlagsObj.value("verbose").toBool()) nScanFlags |= SF_VERBOSE;
        if (defaultScanFlagsObj.value("allTypes").toBool()) nScanFlags |= SF_ALLTYPESSCAN;
    }

    for (qint32 i = 0; i < testCases.size(); i++) {
        QJsonObject testCase = testCases.at(i).toObject();
        QString sZipPath = testCase.value("zipPath").toString();
        QString sExpectedDetect = testCase.value("expectedDetect").toString();

        if (sZipPath.isEmpty()) {
            TEST_FAILED_RECORD failedRecord = {};
            failedRecord.sZipPath = QString("<empty>");
            failedRecord.sExpectedDetect = sExpectedDetect;
            failedRecord.sErrorMessage = QString("Missing zipPath in test case");
            result.listFailed.append(failedRecord);

            _warningMessage(nullptr, QString("Test case %1: Missing zipPath").arg(i + 1));
            result.nErrors++;
            continue;
        }

        QString sFullZipPath = sDirectoryName + QDir::separator() + sZipPath;
        QFile zipFile(sFullZipPath);

        if (!zipFile.exists()) {
            TEST_FAILED_RECORD failedRecord = {};
            failedRecord.sZipPath = sZipPath;
            failedRecord.sExpectedDetect = sExpectedDetect;
            failedRecord.sErrorMessage = QString("ZIP file not found: %1").arg(sFullZipPath);
            result.listFailed.append(failedRecord);

            _errorMessage(nullptr, QString("Test case %1: ZIP file not found: %2").arg(i + 1).arg(sFullZipPath));
            result.nErrors++;
            result.nTotal++;
            continue;
        }

        // zipRecord.compressInfo.compressMethod = XArchive::COMPRESS_METHOD_DEFLATE;
        // zipRecord.sPassword = "DetectItEasy";

        // XBinary::createFileBuffer();

        // XZip xzip(&zipFile);

        // if (!xzip.isValid()) {
        //     _errorMessage(nullptr, QString("Test case %1: Cannot open ZIP file: %2").arg(i + 1).arg(sFullZipPath));
        //     result.nErrors++;
        //     result.nTotal++;
        //     continue;
        // }

        QByteArray baDecompressed;
        // QByteArray baDecompressed = xzip.decompress(&listArchiveRecords.first(), nullptr);
        // xzip.close();

        // if (baDecompressed.isEmpty()) {
        //     _errorMessage(nullptr, QString("Test case %1: Failed to decompress file from ZIP: %2").arg(i + 1).arg(sFullZipPath));
        //     result.nErrors++;
        //     result.nTotal++;
        //     continue;
        // }

        // Use per-test-case scan flags if available, otherwise use default
        quint64 nTestScanFlags = nScanFlags;
        if (testCase.contains("scanFlags")) {
            QJsonObject testScanFlagsObj = testCase.value("scanFlags").toObject();
            nTestScanFlags = 0;
            if (testScanFlagsObj.value("recursiveScan").toBool()) nTestScanFlags |= SF_RECURSIVESCAN;
            if (testScanFlagsObj.value("deepScan").toBool()) nTestScanFlags |= SF_DEEPSCAN;
            if (testScanFlagsObj.value("heuristicScan").toBool()) nTestScanFlags |= SF_HEURISTICSCAN;
            if (testScanFlagsObj.value("aggressiveScan").toBool()) nTestScanFlags |= SF_AGGRESSIVESCAN;
            if (testScanFlagsObj.value("verbose").toBool()) nTestScanFlags |= SF_VERBOSE;
            if (testScanFlagsObj.value("allTypes").toBool()) nTestScanFlags |= SF_ALLTYPESSCAN;
        }

        SCAN_OPTIONS scanOptions = getDefaultOptions(nTestScanFlags);
        QBuffer buffer(&baDecompressed);

        if (!buffer.open(QIODevice::ReadOnly)) {
            TEST_FAILED_RECORD failedRecord = {};
            failedRecord.sZipPath = sZipPath;
            failedRecord.sExpectedDetect = sExpectedDetect;
            failedRecord.sErrorMessage = QString("Cannot open decompressed buffer");
            result.listFailed.append(failedRecord);

            _errorMessage(nullptr, QString("Test case %1: Cannot open decompressed buffer").arg(i + 1));
            result.nErrors++;
            result.nTotal++;
            continue;
        }

        SCAN_RESULT scanResult = scanDevice(&buffer, &scanOptions, nullptr);
        buffer.close();

        QString sActualDetect = createShortResultString(&scanOptions, scanResult);

        if (sExpectedDetect.isEmpty() || sActualDetect.contains(sExpectedDetect, Qt::CaseInsensitive)) {
            TEST_SUCCESS_RECORD successRecord = {};
            successRecord.sZipPath = sZipPath;
            successRecord.sExpectedDetect = sExpectedDetect;
            successRecord.nScanTime = scanResult.nScanTime;
            result.listSuccess.append(successRecord);

            _infoMessage(nullptr, QString("Test case %1 PASSED: %2 -> %3 (Time: %4ms)").arg(i + 1).arg(sZipPath).arg(sActualDetect).arg(scanResult.nScanTime));
        } else {
            TEST_FAILED_RECORD failedRecord = {};
            failedRecord.sZipPath = sZipPath;
            failedRecord.sExpectedDetect = sExpectedDetect;
            failedRecord.sErrorMessage = QString("Detection mismatch: Expected '%1', Got '%2'").arg(sExpectedDetect).arg(sActualDetect);
            result.listFailed.append(failedRecord);

            _errorMessage(nullptr, QString("Test case %1 FAILED: %2\n  Expected: %3\n  Got: %4").arg(i + 1).arg(sZipPath).arg(sExpectedDetect).arg(sActualDetect));
            result.nErrors++;
        }

        result.nTotal++;
    }

    return result;
}

bool XScanEngine::addTestCase(const QString &sJsonPath, const QString &sFilePath, const QString &sExpectedDetect)
{
    // Validate input paths
    if (sJsonPath.isEmpty() || sFilePath.isEmpty()) {
        return false;
    }

    QFile sourceFile(sFilePath);
    if (!sourceFile.exists()) {
        return false;
    }

    QFileInfo jsonFileInfo(sJsonPath);
    QString sJsonDir = jsonFileInfo.absolutePath();
    QString sFilesDir = sJsonDir + QDir::separator() + "files";

    // Create files directory if it doesn't exist
    QDir dir;
    if (!dir.exists(sFilesDir)) {
        if (!dir.mkpath(sFilesDir)) {
            return false;
        }
    }

    // Calculate MD5 hash of the file
    if (!sourceFile.open(QIODevice::ReadOnly)) {
        return false;
    }

    QCryptographicHash hash(QCryptographicHash::Md5);
    hash.addData(&sourceFile);
    QString sMd5 = hash.result().toHex();
    sourceFile.close();

    // Get file extension
    QFileInfo sourceFileInfo(sFilePath);
    QString sExtension = sourceFileInfo.suffix();
    QString sFileNameInZip = sMd5;
    if (!sExtension.isEmpty()) {
        sFileNameInZip += "." + sExtension;
    }

    QString sZipFileName = sFilesDir + QDir::separator() + sMd5 + ".zip";

    // Create encrypted ZIP file with the source file
    QFile zipFile(sZipFileName);
    if (!zipFile.open(QIODevice::WriteOnly)) {
        return false;
    }

    XZip xzip;
    XBinary::PDSTRUCT pdStruct = {};
    pdStruct.bIsStop = false;

    XBinary::PACK_STATE state = {};

    // Configure pack properties with password
    QMap<XBinary::PACK_PROP, QVariant> mapProperties;
    mapProperties[XBinary::PACK_PROP_COMPRESSMETHOD] = XArchive::COMPRESS_METHOD_DEFLATE;
    mapProperties[XBinary::PACK_PROP_ENCRYPTIONMETHOD] = XBinary::CRYPTO_METHOD_ZIPCRYPTO;
    mapProperties[XBinary::PACK_PROP_PASSWORD] = "DetectItEasy";
    mapProperties[XBinary::PACK_PROP_PATHMODE] = XBinary::PATH_MODE_BASENAME;
    mapProperties[XBinary::PACK_PROP_COMPRESSIONLEVEL] = 9;

    // Initialize packing
    if (!xzip.initPack(&state, &zipFile, mapProperties, &pdStruct)) {
        zipFile.close();
        QFile::remove(sZipFileName);
        return false;
    }

    // Add the source file to the archive
    // Create a temporary copy with the MD5 name for adding to archive
    QString sTempFile = sFilesDir + QDir::separator() + sFileNameInZip;
    if (QFile::exists(sTempFile)) {
        QFile::remove(sTempFile);
    }

    if (!QFile::copy(sFilePath, sTempFile)) {
        xzip.finishPack(&state, &pdStruct);
        zipFile.close();
        QFile::remove(sZipFileName);
        return false;
    }

    // Add the file to the archive
    if (!xzip.addFile(&state, sTempFile, &pdStruct)) {
        QFile::remove(sTempFile);
        xzip.finishPack(&state, &pdStruct);
        zipFile.close();
        QFile::remove(sZipFileName);
        return false;
    }

    // Clean up temporary file
    QFile::remove(sTempFile);

    // Finish packing
    if (!xzip.finishPack(&state, &pdStruct)) {
        zipFile.close();
        QFile::remove(sZipFileName);
        return false;
    }

    zipFile.close();

    // Read existing JSON or create new one
    QJsonObject jsonObject;
    QFile jsonFile(sJsonPath);

    if (jsonFile.exists()) {
        if (!jsonFile.open(QIODevice::ReadOnly)) {
            QFile::remove(sZipFileName);
            return false;
        }

        QByteArray baJsonData = jsonFile.readAll();
        jsonFile.close();

        QJsonDocument jsonDoc = QJsonDocument::fromJson(baJsonData);
        if (!jsonDoc.isNull() && jsonDoc.isObject()) {
            jsonObject = jsonDoc.object();
        }
    }

    // Ensure testCases array exists
    QJsonArray testCases;
    if (jsonObject.contains("testCases") && jsonObject.value("testCases").isArray()) {
        testCases = jsonObject.value("testCases").toArray();
    }

    // Add new test case
    QJsonObject newTestCase;
    newTestCase["zipPath"] = "files/" + sMd5 + ".zip";
    newTestCase["expectedDetect"] = sExpectedDetect;

    testCases.append(newTestCase);
    jsonObject["testCases"] = testCases;

    // Add default description if not present
    if (!jsonObject.contains("description")) {
        jsonObject["description"] = "XScanEngine test configuration file";
    }

    // Write updated JSON
    if (!jsonFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return false;
    }

    QJsonDocument jsonDocOut(jsonObject);
    jsonFile.write(jsonDocOut.toJson(QJsonDocument::Indented));
    jsonFile.close();

    return true;
}
