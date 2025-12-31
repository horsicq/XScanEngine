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
#ifndef XSCANENGINE_H
#define XSCANENGINE_H

#include "binary_script.h"
#include "com_script.h"
#include "elf_script.h"
#include "le_script.h"
#include "lx_script.h"
#include "mach_script.h"
#include "msdos_script.h"
#include "ne_script.h"
#include "pe_script.h"
#include "archive_script.h"
#include "zip_script.h"
#include "jar_script.h"
#include "apk_script.h"
#include "ipa_script.h"
#include "dex_script.h"
#include "npm_script.h"
#include "rar_script.h"
#include "iso9660_script.h"
#include "machofat_script.h"
#include "amiga_script.h"
#include "atarist_script.h"
#include "dos16m_script.h"
#include "dos4g_script.h"
#include "javaclass_script.h"
#include "pdf_script.h"
#include "cfbf_script.h"
#include "image_script.h"
#include "jpeg_script.h"
#include "png_script.h"

#include "xformats.h"
#include "xoptions.h"
#include "xzip.h"
#include <QFutureWatcher>
#include <QLoggingCategory>
#include "xthreadobject.h"
#include "xcompresseddevice.h"

typedef bool (*SCAN_ENGINE_CALLBACK)(const QString &sCurrentSignature, qint32 nNumberOfSignatures, qint32 nCurrentIndex, void *pUserData);

// TODO pOptions -> pScanOptions
class XScanEngine : public XThreadObject {
    Q_OBJECT

    enum SCAN_TYPE {
        SCAN_TYPE_UNKNOWN = 0,
        SCAN_TYPE_DEVICE,
        SCAN_TYPE_DIRECTORY,
        SCAN_TYPE_FILE,
        SCAN_TYPE_MEMORY
    };

public:
    enum RECORD_TYPE {
        RECORD_TYPE_UNKNOWN = 0,
        RECORD_TYPE_APKOBFUSCATOR,
        RECORD_TYPE_APKTOOL,
        RECORD_TYPE_CERTIFICATE,
        RECORD_TYPE_COMPILER,
        RECORD_TYPE_COMPRESSOR,
        RECORD_TYPE_CONVERTER,
        RECORD_TYPE_CRYPTER,
        RECORD_TYPE_DATABASE,
        RECORD_TYPE_DEBUGDATA,
        RECORD_TYPE_DOCUMENT,
        RECORD_TYPE_DONGLEPROTECTION,
        RECORD_TYPE_DOSEXTENDER,
        RECORD_TYPE_FORMAT,
        RECORD_TYPE_GENERIC,
        RECORD_TYPE_IMAGE,
        RECORD_TYPE_INSTALLER,
        RECORD_TYPE_INSTALLERDATA,
        RECORD_TYPE_JAROBFUSCATOR,
        RECORD_TYPE_JOINER,
        RECORD_TYPE_LANGUAGE,
        RECORD_TYPE_LIBRARY,
        RECORD_TYPE_LINKER,
        RECORD_TYPE_LOADER,
        RECORD_TYPE_NETCOMPRESSOR,
        RECORD_TYPE_NETOBFUSCATOR,
        RECORD_TYPE_OBFUSCATOR,
        RECORD_TYPE_OPERATIONSYSTEM,
        RECORD_TYPE_PACKER,
        RECORD_TYPE_PETOOL,
        RECORD_TYPE_PROTECTION,
        RECORD_TYPE_PROTECTOR,
        RECORD_TYPE_PROTECTORDATA,
        RECORD_TYPE_SFX,
        RECORD_TYPE_SFXDATA,
        RECORD_TYPE_SIGNTOOL,
        RECORD_TYPE_SOURCECODE,
        RECORD_TYPE_STUB,
        RECORD_TYPE_TOOL,
        RECORD_TYPE_VIRTUALMACHINE,
        RECORD_TYPE_VIRUS,
        RECORD_TYPE_ARCHIVE,
        RECORD_TYPE_CRYPTOR,
        RECORD_TYPE_OVERLAY,
        RECORD_TYPE_PLATFORM,
        RECORD_TYPE_PLAYER,
        RECORD_TYPE_TROJAN,
        RECORD_TYPE_MALWARE,
        RECORD_TYPE_PACKAGE,
        RECORD_TYPE_LICENSING,
        RECORD_TYPE_ROM,
        RECORD_TYPE_CORRUPTEDDATA,
        RECORD_TYPE_PERSONALDATA,
        RECORD_TYPE_AUTHOR,
        RECORD_TYPE_CREATOR,
        RECORD_TYPE_PRODUCER,

        // TODO more
    };

    static QString recordTypeIdToString(qint32 nId);
    static QString heurTypeIdToString(qint32 nId);

    enum RECORD_NAME {
        RECORD_NAME_UNKNOWN = 0,
        RECORD_NAME_12311134,
        RECORD_NAME_1337EXECRYPTER,
        RECORD_NAME_32LITE,
        RECORD_NAME_7Z,
        RECORD_NAME_AASE,
        RECORD_NAME_ABCCRYPTOR,
        RECORD_NAME_ACPROTECT,
        RECORD_NAME_ACTIVEMARK,
        RECORD_NAME_ACTUALINSTALLER,
        RECORD_NAME_ADVANCEDINSTALLER,
        RECORD_NAME_ADVANCEDUPXSCRAMMBLER,
        RECORD_NAME_AESOBFUSCATOR,
        RECORD_NAME_AFFILLIATEEXE,
        RECORD_NAME_AGAINNATIVITYCRYPTER,
        RECORD_NAME_AGILENET,
        RECORD_NAME_AHPACKER,
        RECORD_NAME_AHTEAMEPPROTECTOR,
        RECORD_NAME_AINEXE,
        RECORD_NAME_AIX,
        RECORD_NAME_ALCHEMYMINDWORKS,
        RECORD_NAME_ALEXPROTECTOR,
        RECORD_NAME_ALIASOBJ,
        RECORD_NAME_ALIBABACLANG,
        RECORD_NAME_ALIBABAPROTECTION,
        RECORD_NAME_ALIENYZE,
        RECORD_NAME_ALIPAYCLANG,
        RECORD_NAME_ALIPAYOBFUSCATOR,
        RECORD_NAME_ALLATORIOBFUSCATOR,
        RECORD_NAME_ALLOY,
        RECORD_NAME_ALPINECLANG,
        RECORD_NAME_ALPINELINUX,
        RECORD_NAME_AMIGA,
        RECORD_NAME_ANDPAKK2,
        RECORD_NAME_ANDROID,
        RECORD_NAME_ANDROIDAPKSIGNER,
        RECORD_NAME_ANDROIDARSC,
        RECORD_NAME_ANDROIDCLANG,
        RECORD_NAME_ANDROIDGRADLE,
        RECORD_NAME_ANDROIDJETPACK,
        RECORD_NAME_ANDROIDMAVENPLUGIN,
        RECORD_NAME_ANDROIDNDK,
        RECORD_NAME_ANDROIDSDK,
        RECORD_NAME_ANDROIDSIGNAPK,
        RECORD_NAME_ANDROIDXML,
        RECORD_NAME_ANSKYAPOLYMORPHICPACKER,
        RECORD_NAME_ANSLYMPACKER,
        RECORD_NAME_ANTIDOTE,
        RECORD_NAME_ANTILVL,
        RECORD_NAME_APACHEANT,
        RECORD_NAME_APACK,
        RECORD_NAME_APKEDITOR,
        RECORD_NAME_APKENCRYPTOR,
        RECORD_NAME_APKMODIFIERSIGNAPK,
        RECORD_NAME_APKPROTECT,
        RECORD_NAME_APKPROTECTOR,
        RECORD_NAME_APKS,
        RECORD_NAME_APKSIGNATURESCHEME,
        RECORD_NAME_APKSIGNER,
        RECORD_NAME_APKTOOLPLUS,
        RECORD_NAME_APK_SIGNER,
        RECORD_NAME_APPGUARD,
        RECORD_NAME_APPIMAGE,
        RECORD_NAME_APPLEJDK,
        RECORD_NAME_APPLELLVM,
        RECORD_NAME_APPORTABLECLANG,
        RECORD_NAME_APPSOLID,
        RECORD_NAME_AR,
        RECORD_NAME_ARCRYPT,
        RECORD_NAME_ARJ,
        RECORD_NAME_ARMADILLO,
        RECORD_NAME_ARMASSEMBLER,
        RECORD_NAME_ARMC,
        RECORD_NAME_ARMCCPP,
        RECORD_NAME_ARMLINKER,
        RECORD_NAME_ARMNEONCCPP,
        RECORD_NAME_ARMPROTECTOR,
        RECORD_NAME_ARMTHUMBCCPP,
        RECORD_NAME_ARMTHUMBMACROASSEMBLER,
        RECORD_NAME_AROS,
        RECORD_NAME_ARXAN,
        RECORD_NAME_ASDPACK,
        RECORD_NAME_ASMGUARD,
        RECORD_NAME_ASPACK,
        RECORD_NAME_ASPLINUX,
        RECORD_NAME_ASPROTECT,
        RECORD_NAME_ASSCRYPTER,
        RECORD_NAME_ASSEMBLER,
        RECORD_NAME_ASSEMBLYINVOKE,
        RECORD_NAME_AU,
        RECORD_NAME_AUTOIT,
        RECORD_NAME_AVASTANTIVIRUS,
        RECORD_NAME_AVERCRYPTOR,
        RECORD_NAME_AVI,
        RECORD_NAME_AVPACK,
        RECORD_NAME_AZPROTECT,
        RECORD_NAME_BABELNET,
        RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR,
        RECORD_NAME_BAIDUPROTECTION,
        RECORD_NAME_BAIDUSIGNATUREPLATFORM,
        RECORD_NAME_BAMBAM,
        RECORD_NAME_BANGCLEPROTECTION,
        RECORD_NAME_BASIC,
        RECORD_NAME_BASIC4ANDROID,
        RECORD_NAME_BAT2EXEC,
        RECORD_NAME_BEAWEBLOGIC,
        RECORD_NAME_BEROEXEPACKER,
        RECORD_NAME_BIOHAZARDCRYPTER,
        RECORD_NAME_BITMAPINFOHEADER,
        RECORD_NAME_BITROCKINSTALLER,
        RECORD_NAME_BITSHAPEPECRYPT,
        RECORD_NAME_BLADEJOINER,
        RECORD_NAME_BORLANDCCPP,
        RECORD_NAME_BORLANDCPP,
        RECORD_NAME_BORLANDCPPBUILDER,
        RECORD_NAME_BORLANDDEBUGINFO,
        RECORD_NAME_BORLANDDELPHI,
        RECORD_NAME_BORLANDDELPHIDOTNET,
        RECORD_NAME_BORLANDOBJECTPASCALDELPHI,
        RECORD_NAME_BORLANDOSSERVICES,
        RECORD_NAME_BREAKINTOPATTERN,
        RECORD_NAME_BRIDGEOS,
        RECORD_NAME_BRIDGEOSSDK,
        RECORD_NAME_BTWORKSCODEGUARD,
        RECORD_NAME_BUNDLETOOL,
        RECORD_NAME_BURNEYE,
        RECORD_NAME_BYTEDANCESECCOMPILER,
        RECORD_NAME_BYTEGUARD,
        RECORD_NAME_BZIP2,
        RECORD_NAME_C,
        RECORD_NAME_CAB,
        RECORD_NAME_CARBON,
        RECORD_NAME_CAUSEWAY,
        RECORD_NAME_CCBYUNIHACKERS,
        RECORD_NAME_CCBYVORONTSOV,
        RECORD_NAME_CCPP,
        RECORD_NAME_CELESTYFILEBINDER,
        RECORD_NAME_CEXE,
        RECORD_NAME_CHROMIUMCRASHPAD,
        RECORD_NAME_CIGICIGICRYPTER,
        RECORD_NAME_CIL,
        RECORD_NAME_CLANG,
        RECORD_NAME_CLICKTEAM,
        RECORD_NAME_CLISECURE,
        RECORD_NAME_COCOA,
        RECORD_NAME_CODEGEARCPP,
        RECORD_NAME_CODEGEARCPPBUILDER,
        RECORD_NAME_CODEGEARDELPHI,
        RECORD_NAME_CODEGEAROBJECTPASCALDELPHI,
        RECORD_NAME_CODESIGN,
        RECORD_NAME_CODEVEIL,
        RECORD_NAME_CODEVIEWDEBUGINFO,
        RECORD_NAME_CODEWALL,
        RECORD_NAME_COFF,
        RECORD_NAME_COMEXSIGNAPK,
        RECORD_NAME_COMICBOOKARCHIVE,
        RECORD_NAME_COMPOUNDFILEBINARYFORMAT,
        RECORD_NAME_CONFUSER,
        RECORD_NAME_CONFUSEREX,
        RECORD_NAME_COPYMINDER,
        RECORD_NAME_CPP,
        RECORD_NAME_CREATEINSTALL,
        RECORD_NAME_CRINKLER,
        RECORD_NAME_CRUNCH,
        RECORD_NAME_CRYEXE,
        RECORD_NAME_CRYPTABLESEDUCATION,
        RECORD_NAME_CRYPTCOM,
        RECORD_NAME_CRYPTDISMEMBER,
        RECORD_NAME_CRYPTER,
        RECORD_NAME_CRYPTIC,
        RECORD_NAME_CRYPTOCRACKPEPROTECTOR,
        RECORD_NAME_CRYPTOOBFUSCATORFORNET,
        RECORD_NAME_CRYPTORBYDISMEMBER,
        RECORD_NAME_CRYPTOZ,
        RECORD_NAME_CRYPTRROADS,
        RECORD_NAME_CSHARP,
        RECORD_NAME_CVTOMF,
        RECORD_NAME_CVTPGD,
        RECORD_NAME_CVTRES,
        RECORD_NAME_CWSDPMI,
        RECORD_NAME_CYGWIN,
        RECORD_NAME_D,
        RECORD_NAME_D2JAPKSIGN,
        RECORD_NAME_DALKRYPT,
        RECORD_NAME_DALVIK,
        RECORD_NAME_DBPE,
        RECORD_NAME_DCRYPTPRIVATE,
        RECORD_NAME_DEB,
        RECORD_NAME_DEBIANCLANG,
        RECORD_NAME_DEBIANLINUX,
        RECORD_NAME_DEEPSEA,
        RECORD_NAME_DEPACK,
        RECORD_NAME_DEPLOYMASTER,
        RECORD_NAME_DEX,
        RECORD_NAME_DEX2JAR,
        RECORD_NAME_DEXGUARD,
        RECORD_NAME_DEXLIB,
        RECORD_NAME_DEXLIB2,
        RECORD_NAME_DEXMERGE,
        RECORD_NAME_DEXPROTECTOR,
        RECORD_NAME_DIET,
        RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR,
        RECORD_NAME_DIRTYCRYPTOR,
        RECORD_NAME_DJVU,
        RECORD_NAME_DMD,
        RECORD_NAME_DMD32,
        RECORD_NAME_DNGUARD,
        RECORD_NAME_DOS16M,
        RECORD_NAME_DOS4G,
        RECORD_NAME_DOTBJFNT,
        RECORD_NAME_DOTFIXNICEPROTECT,
        RECORD_NAME_DOTFUSCATOR,
        RECORD_NAME_DOTNET,
        RECORD_NAME_DOTNETREACTOR,
        RECORD_NAME_DOTNETSHRINK,
        RECORD_NAME_DOTNETSPIDER,
        RECORD_NAME_DOTNETZ,
        RECORD_NAME_DOTOOLSSIGNAPK,
        RECORD_NAME_DRAGONARMOR,
        RECORD_NAME_DROPBOX,
        RECORD_NAME_DVCLAL,
        RECORD_NAME_DWARFDEBUGINFO,
        RECORD_NAME_DX,
        RECORD_NAME_DXSHIELD,
        RECORD_NAME_DYAMAR,
        RECORD_NAME_DYNASM,
        RECORD_NAME_EASYPROTECTOR,
        RECORD_NAME_EAZFUSCATOR,
        RECORD_NAME_ECLIPSE,
        RECORD_NAME_ECMASCRIPT,
        RECORD_NAME_ELECKEY,
        RECORD_NAME_EMBARCADEROCPP,
        RECORD_NAME_EMBARCADEROCPPBUILDER,
        RECORD_NAME_EMBARCADERODELPHI,
        RECORD_NAME_EMBARCADERODELPHIDOTNET,
        RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI,
        RECORD_NAME_EMPTYFILE,
        RECORD_NAME_ENCRYPTPE,
        RECORD_NAME_ENIGMA,
        RECORD_NAME_ENIGMAVIRTUALBOX,
        RECORD_NAME_EPEXEPACK,
        RECORD_NAME_EPROT,
        RECORD_NAME_EXCELSIORJET,
        RECORD_NAME_EXE32PACK,
        RECORD_NAME_EXECRYPT,
        RECORD_NAME_EXECRYPTOR,
        RECORD_NAME_EXEFOG,
        RECORD_NAME_EXEJOINER,
        RECORD_NAME_EXEMPLARINSTALLER,
        RECORD_NAME_EXEPACK,
        RECORD_NAME_EXEPASSWORDPROTECTOR,
        RECORD_NAME_EXESAX,
        RECORD_NAME_EXESHIELD,
        RECORD_NAME_EXESTEALTH,
        RECORD_NAME_EXPORT,
        RECORD_NAME_EXPRESSOR,
        RECORD_NAME_EXPRESSOR_KERNEL32,
        RECORD_NAME_EXPRESSOR_USER32,
        RECORD_NAME_EZIP,
        RECORD_NAME_FAKESIGNATURE,
        RECORD_NAME_FAKUSCRYPTOR,
        RECORD_NAME_FASM,
        RECORD_NAME_FASTFILECRYPT,
        RECORD_NAME_FASTPROXY,
        RECORD_NAME_FEARZCRYPTER,
        RECORD_NAME_FEARZPACKER,
        RECORD_NAME_FENIXOS,
        RECORD_NAME_FILESHIELD,
        RECORD_NAME_FISHNET,
        RECORD_NAME_FISHPEPACKER,
        RECORD_NAME_FISHPESHIELD,
        RECORD_NAME_FLASHVIDEO,
        RECORD_NAME_FLEXLM,
        RECORD_NAME_FLEXNET,
        RECORD_NAME_FORTRAN,
        RECORD_NAME_FOUNDATION,
        RECORD_NAME_FPC,
        RECORD_NAME_FREEBSD,
        RECORD_NAME_FREECRYPTOR,
        RECORD_NAME_FSG,
        RECORD_NAME_GCC,
        RECORD_NAME_GENERIC,
        RECORD_NAME_GENERICLINKER,
        RECORD_NAME_GENTEEINSTALLER,
        RECORD_NAME_GENTOOLINUX,
        RECORD_NAME_GHAZZACRYPTER,
        RECORD_NAME_GHOSTINSTALLER,
        RECORD_NAME_GIF,
        RECORD_NAME_GIXPROTECTOR,
        RECORD_NAME_GKRIPTO,
        RECORD_NAME_GKSETUPSFX,
        RECORD_NAME_GNUASSEMBLER,
        RECORD_NAME_GNULINKER,
        RECORD_NAME_GO,
        RECORD_NAME_GOASM,
        RECORD_NAME_GOATSPEMUTILATOR,
        RECORD_NAME_GOLD,
        RECORD_NAME_GOLIATHNET,
        RECORD_NAME_GOLINK,
        RECORD_NAME_GOOGLE,
        RECORD_NAME_GOOGLEPLAY,
        RECORD_NAME_GPINSTALL,
        RECORD_NAME_GUARDIANSTEALTH,
        RECORD_NAME_GZIP,
        RECORD_NAME_H4CKY0UORGCRYPTER,
        RECORD_NAME_HACCREWCRYPTER,
        RECORD_NAME_HACKSTOP,
        RECORD_NAME_HALVCRYPTER,
        RECORD_NAME_HANCOMLINUX,
        RECORD_NAME_HDUS_WJUS,
        RECORD_NAME_HIAPKCOM,
        RECORD_NAME_HIDEANDPROTECT,
        RECORD_NAME_HIDEPE,
        RECORD_NAME_HIKARIOBFUSCATOR,
        RECORD_NAME_HMIMYSPACKER,
        RECORD_NAME_HMIMYSPROTECTOR,
        RECORD_NAME_HOODLUM,
        RECORD_NAME_HOUNDHACKCRYPTER,
        RECORD_NAME_HPUX,
        RECORD_NAME_HTML,
        RECORD_NAME_HXS,
        RECORD_NAME_HYPERTECHCRACKPROOF,
        RECORD_NAME_IBMJDK,
        RECORD_NAME_IBMPCPASCAL,
        RECORD_NAME_ICE,
        RECORD_NAME_ICRYPT,
        RECORD_NAME_IJIAMI,
        RECORD_NAME_IJIAMILLVM,
        RECORD_NAME_IKVMDOTNET,
        RECORD_NAME_IL2CPP,
        RECORD_NAME_ILASM,
        RECORD_NAME_IMPORT,
        RECORD_NAME_INFCRYPTOR,
        RECORD_NAME_INNOSETUP,
        RECORD_NAME_INQUARTOSOBFUSCATOR,
        RECORD_NAME_INSTALL4J,
        RECORD_NAME_INSTALLANYWHERE,
        RECORD_NAME_INSTALLAWARE,
        RECORD_NAME_INSTALLSHIELD,
        RECORD_NAME_IOS,
        RECORD_NAME_IOSSDK,
        RECORD_NAME_IPA,
        RECORD_NAME_IPADOS,
        RECORD_NAME_IPHONEOS,
        RECORD_NAME_IPBPROTECT,
        RECORD_NAME_IRIX,
        RECORD_NAME_ISO9660,
        RECORD_NAME_JACK,
        RECORD_NAME_JAM,
        RECORD_NAME_JAR,
        RECORD_NAME_JAVA,
        RECORD_NAME_JAVACOMPILEDCLASS,
        RECORD_NAME_JDK,
        RECORD_NAME_JDPACK,
        RECORD_NAME_JETBRAINS,
        RECORD_NAME_JIAGU,
        RECORD_NAME_JPEG,
        RECORD_NAME_JSCRIPT,
        RECORD_NAME_JVM,
        RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER,
        RECORD_NAME_KBYS,
        RECORD_NAME_KCRYPTOR,
        RECORD_NAME_KGBCRYPTER,
        RECORD_NAME_KIAMSCRYPTOR,
        RECORD_NAME_KIRO,
        RECORD_NAME_KIWIVERSIONOBFUSCATOR,
        RECORD_NAME_KKRUNCHY,
        RECORD_NAME_KOTLIN,
        RECORD_NAME_KRATOSCRYPTER,
        RECORD_NAME_KRYPTON,
        RECORD_NAME_KUR0KX2TO,
        RECORD_NAME_LAMECRYPT,
        RECORD_NAME_LARP64,
        RECORD_NAME_LAYHEYFORTRAN90,
        RECORD_NAME_LAZARUS,
        RECORD_NAME_LCCLNK,
        RECORD_NAME_LCCWIN,
        RECORD_NAME_LDC,
        RECORD_NAME_LGLZ,
        RECORD_NAME_LHA,
        RECORD_NAME_LHASSFX,
        RECORD_NAME_LIAPP,
        RECORD_NAME_LIGHTNINGCRYPTERPRIVATE,
        RECORD_NAME_LIGHTNINGCRYPTERSCANTIME,
        RECORD_NAME_LINUX,
        RECORD_NAME_LLD,
        RECORD_NAME_LOCKTITE,
        RECORD_NAME_LSCRYPRT,
        RECORD_NAME_LUACOMPILED,
        RECORD_NAME_LUCYPHER,
        RECORD_NAME_LZEXE,
        RECORD_NAME_LZFSE,
        RECORD_NAME_MACHOFAT,
        RECORD_NAME_MAC_OS,
        RECORD_NAME_MAC_OS_X,
        RECORD_NAME_MACCATALYST,
        RECORD_NAME_MACDRIVERKIT,
        RECORD_NAME_MACFIRMWARE,
        RECORD_NAME_MACOS,
        RECORD_NAME_MACOSSDK,
        RECORD_NAME_MACROBJECT,
        RECORD_NAME_MALPACKER,
        RECORD_NAME_MANDRAKELINUX,
        RECORD_NAME_MASKPE,
        RECORD_NAME_MASM,
        RECORD_NAME_MASM32,
        RECORD_NAME_MAXTOCODE,
        RECORD_NAME_MCLINUX,
        RECORD_NAME_MEDUSAH,
        RECORD_NAME_MEW10,
        RECORD_NAME_MEW11SE,
        RECORD_NAME_MFC,
        RECORD_NAME_MICROSOFTACCESS,
        RECORD_NAME_MICROSOFTC,
        RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP,
        RECORD_NAME_MICROSOFTCOMPOUND,
        RECORD_NAME_MICROSOFTCPP,
        RECORD_NAME_MICROSOFTDOTNETFRAMEWORK,
        RECORD_NAME_MICROSOFTEXCEL,
        RECORD_NAME_MICROSOFTINSTALLER,
        RECORD_NAME_MICROSOFTLINKER,
        RECORD_NAME_MICROSOFTLINKERDATABASE,
        RECORD_NAME_MICROSOFTOFFICE,
        RECORD_NAME_MICROSOFTOFFICEWORD,
        RECORD_NAME_MICROSOFTPHOENIX,
        RECORD_NAME_MICROSOFTVISIO,
        RECORD_NAME_MICROSOFTVISUALSTUDIO,
        RECORD_NAME_MICROSOFTWINHELP,
        RECORD_NAME_MINGW,
        RECORD_NAME_MINIX,
        RECORD_NAME_MINKE,
        RECORD_NAME_MKFPACK,
        RECORD_NAME_MOBILETENCENTPROTECT,
        RECORD_NAME_MODESTO,
        RECORD_NAME_MODGUARD,
        RECORD_NAME_MOLD,
        RECORD_NAME_MOLEBOX,
        RECORD_NAME_MOLEBOXULTRA,
        RECORD_NAME_MONEYCRYPTER,
        RECORD_NAME_MORPHNAH,
        RECORD_NAME_MORTALTEAMCRYPTER,
        RECORD_NAME_MORTALTEAMCRYPTER2,
        RECORD_NAME_MORUKCREWCRYPTERPRIVATE,
        RECORD_NAME_MOTODEVSTUDIOFORANDROID,
        RECORD_NAME_MP3,
        RECORD_NAME_MP4,
        RECORD_NAME_MPACK,
        RECORD_NAME_MPRESS,
        RECORD_NAME_MRUNDECTETABLE,
        RECORD_NAME_MSDOS,
        RECORD_NAME_MSLRH,
        RECORD_NAME_MSYS,
        RECORD_NAME_MSYS2,
        RECORD_NAME_MZ0OPE,
        RECORD_NAME_NAGAINLLVM,
        RECORD_NAME_NAGAPTPROTECTION,
        RECORD_NAME_NAKEDPACKER,
        RECORD_NAME_NASM,  // The Netwide Assembler
        RECORD_NAME_NATIVECRYPTORBYDOSX,
        RECORD_NAME_NCODE,
        RECORD_NAME_NEOLITE,
        RECORD_NAME_NETBSD,
        RECORD_NAME_NETEASEAPKSIGNER,
        RECORD_NAME_NIDHOGG,
        RECORD_NAME_NIM,
        RECORD_NAME_NJOINER,
        RECORD_NAME_NJOY,
        RECORD_NAME_NME,
        RECORD_NAME_NOOBYPROTECT,
        RECORD_NAME_NOODLECRYPT,
        RECORD_NAME_NORTHSTARPESHRINKER,
        RECORD_NAME_NOSINSTALLER,
        RECORD_NAME_NOSTUBLINKER,
        RECORD_NAME_NOXCRYPT,
        RECORD_NAME_NPACK,
        RECORD_NAME_NQSHIELD,
        RECORD_NAME_NSIS,
        RECORD_NAME_NSK,
        RECORD_NAME_NSPACK,
        RECORD_NAME_OBFUSCAR,
        RECORD_NAME_OBFUSCATORLLVM,
        RECORD_NAME_OBFUSCATORNET2009,
        RECORD_NAME_OBJECTIVEC,
        RECORD_NAME_OBJECTPASCAL,
        RECORD_NAME_OBJECTPASCALDELPHI,
        RECORD_NAME_OBSIDIUM,
        RECORD_NAME_OLLVMTLL,
        RECORD_NAME_ONESPANPROTECTION,  // till 2018 Vasco !
        RECORD_NAME_OPENBSD,
        RECORD_NAME_OPENDOCUMENT,
        RECORD_NAME_OPENJDK,
        RECORD_NAME_OPENSOURCECODECRYPTER,
        RECORD_NAME_OPENVMS,
        RECORD_NAME_OPENVOS,
        RECORD_NAME_OPENWATCOMCCPP,
        RECORD_NAME_OPERA,
        RECORD_NAME_ORACLESOLARISLINKEDITORS,
        RECORD_NAME_OREANSCODEVIRTUALIZER,
        RECORD_NAME_ORIEN,
        RECORD_NAME_OS2,
        RECORD_NAME_OSCCRYPTER,
        RECORD_NAME_OS_X,
        RECORD_NAME_P0KESCRAMBLER,
        RECORD_NAME_PACKMAN,
        RECORD_NAME_PACKWIN,
        RECORD_NAME_PANDORA,
        RECORD_NAME_PANGXIE,
        RECORD_NAME_PCGUARD,
        RECORD_NAME_PCOM,
        RECORD_NAME_PCSHRINK,
        RECORD_NAME_PDB,
        RECORD_NAME_PDBFILELINK,
        RECORD_NAME_PDF,
        RECORD_NAME_PEARMOR,
        RECORD_NAME_PEBUNDLE,
        RECORD_NAME_PECOMPACT,
        RECORD_NAME_PECRYPT32,
        RECORD_NAME_PEDIMINISHER,
        RECORD_NAME_PEENCRYPT,
        RECORD_NAME_PELOCK,
        RECORD_NAME_PELOCKNT,
        RECORD_NAME_PENGUINCRYPT,
        RECORD_NAME_PEPACK,
        RECORD_NAME_PEPACKSPROTECT,
        RECORD_NAME_PEQUAKE,
        RECORD_NAME_PERL,
        RECORD_NAME_PESHIELD,
        RECORD_NAME_PESPIN,
        RECORD_NAME_PETITE,
        RECORD_NAME_PETITE_KERNEL32,
        RECORD_NAME_PETITE_USER32,
        RECORD_NAME_PEX,
        RECORD_NAME_PFECX,
        RECORD_NAME_PGMPAK,
        RECORD_NAME_PHOENIXPROTECTOR,
        RECORD_NAME_PHP,
        RECORD_NAME_PICRYPTOR,
        RECORD_NAME_PKLITE,
        RECORD_NAME_PKLITE32,
        RECORD_NAME_PKZIPMINISFX,
        RECORD_NAME_PLAIN,
        RECORD_NAME_PLEXCLANG,
        RECORD_NAME_PMODEW,
        RECORD_NAME_PNG,
        RECORD_NAME_POKECRYPTER,
        RECORD_NAME_POLYCRYPTPE,
        RECORD_NAME_POSIX,
        RECORD_NAME_POWERBASIC,
        RECORD_NAME_PRIVATEEXEPROTECTOR,
        RECORD_NAME_PROGUARD,
        RECORD_NAME_PROPACK,
        RECORD_NAME_PROTECTEXE,
        RECORD_NAME_PSEUDOAPKSIGNER,
        RECORD_NAME_PUBCRYPTER,
        RECORD_NAME_PUNISHER,
        RECORD_NAME_PUREBASIC,
        RECORD_NAME_PUSSYCRYPTER,
        RECORD_NAME_PYINSTALLER,
        RECORD_NAME_PYTHON,
        RECORD_NAME_QDBH,
        RECORD_NAME_QIHOO360PROTECTION,
        RECORD_NAME_QML,
        RECORD_NAME_QNX,
        RECORD_NAME_QRYPT0R,
        RECORD_NAME_QT,
        RECORD_NAME_QTINSTALLER,
        RECORD_NAME_QUICKPACKNT,
        RECORD_NAME_R8,
        RECORD_NAME_RADIALIX,
        RECORD_NAME_RAR,
        RECORD_NAME_RCRYPTOR,
        RECORD_NAME_RDGTEJONCRYPTER,
        RECORD_NAME_REDHATLINUX,
        RECORD_NAME_RELPACK,
        RECORD_NAME_RENETPACK,
        RECORD_NAME_RESOURCE,
        RECORD_NAME_RESOURCE_CURSOR,
        RECORD_NAME_RESOURCE_DIALOG,
        RECORD_NAME_RESOURCE_ICON,
        RECORD_NAME_RESOURCE_MENU,
        RECORD_NAME_RESOURCE_STRINGTABLE,
        RECORD_NAME_RESOURCE_VERSIONINFO,
        RECORD_NAME_REVPROT,
        RECORD_NAME_RJCRUSH,
        RECORD_NAME_RLP,
        RECORD_NAME_RLPACK,
        RECORD_NAME_ROGUEPACK,
        RECORD_NAME_ROSASM,
        RECORD_NAME_RTF,
        RECORD_NAME_RUBY,
        RECORD_NAME_RUST,
        RECORD_NAME_SAFEENGINELLVM,
        RECORD_NAME_SAFEENGINESHIELDEN,
        RECORD_NAME_SANDHOOK,
        RECORD_NAME_SCOBFUSCATOR,
        RECORD_NAME_SCPACK,
        RECORD_NAME_SCRNCH,
        RECORD_NAME_SDPROTECTORPRO,
        RECORD_NAME_SECNEO,
        RECORD_NAME_SECSHELL,
        RECORD_NAME_SECURESHADE,
        RECORD_NAME_SECUROM,
        RECORD_NAME_SEPOS,
        RECORD_NAME_SERGREENAPPACKER,
        RECORD_NAME_SETUPFACTORY,
        RECORD_NAME_SEXECRYPTER,
        RECORD_NAME_SHELL,
        RECORD_NAME_SHRINKER,
        RECORD_NAME_SIGNATORY,
        RECORD_NAME_SIGNUPDATE,
        RECORD_NAME_SIMBIOZ,
        RECORD_NAME_SIMCRYPTER,
        RECORD_NAME_SIMPLECRYPTER,
        RECORD_NAME_SIMPLEPACK,
        RECORD_NAME_SINGLEJAR,
        RECORD_NAME_SIXXPACK,
        RECORD_NAME_SKATER,
        RECORD_NAME_SMARTASSEMBLY,
        RECORD_NAME_SMARTINSTALLMAKER,
        RECORD_NAME_SMOKESCREENCRYPTER,
        RECORD_NAME_SNAPDRAGONLLVMARM,
        RECORD_NAME_SNAPPROTECT,
        RECORD_NAME_SNOOPCRYPT,
        RECORD_NAME_SOFTDEFENDER,
        RECORD_NAME_SOFTSENTRY,
        RECORD_NAME_SOFTWARECOMPRESS,
        RECORD_NAME_SOFTWAREZATOR,
        RECORD_NAME_SOLARIS,
        RECORD_NAME_SOURCERYCODEBENCH,
        RECORD_NAME_SOURCERYCODEBENCHLITE,
        RECORD_NAME_SPICESNET,
        RECORD_NAME_SPIRIT,
        RECORD_NAME_SPOONINSTALLER,
        RECORD_NAME_SPOONSTUDIO,
        RECORD_NAME_SPOONSTUDIO2011,
        RECORD_NAME_SQUEEZSFX,
        RECORD_NAME_SQUIRRELINSTALLER,
        RECORD_NAME_STABSDEBUGINFO,
        RECORD_NAME_STARFORCE,
        RECORD_NAME_STARTOSLINUX,
        RECORD_NAME_STASFODIDOCRYPTOR,
        RECORD_NAME_STONESPEENCRYPTOR,  // TODO Check name from .Stone Section // TODO EP !!!
        RECORD_NAME_SUNOS,
        RECORD_NAME_SUNWORKSHOP,
        RECORD_NAME_SUNWORKSHOPCOMPILERS,
        RECORD_NAME_SUSELINUX,
        RECORD_NAME_SVKPROTECTOR,
        RECORD_NAME_SYLLABLE,
        RECORD_NAME_SYMBOLTABLE,
        RECORD_NAME_SWF,
        RECORD_NAME_SWIFT,
        RECORD_NAME_TAR,
        RECORD_NAME_TARMAINSTALLER,
        RECORD_NAME_TELOCK,
        RECORD_NAME_TENCENTLEGU,
        RECORD_NAME_TENCENTPROTECTION,
        RECORD_NAME_TGRCRYPTER,
        RECORD_NAME_THEBESTCRYPTORBYFSK,
        RECORD_NAME_THEMIDAWINLICENSE,
        RECORD_NAME_THEZONECRYPTER,
        RECORD_NAME_THINSTALL,
        RECORD_NAME_THUMBC,
        RECORD_NAME_TIFF,
        RECORD_NAME_TINYC,
        RECORD_NAME_TINYPROG,
        RECORD_NAME_TINYSIGN,
        RECORD_NAME_TOTALCOMMANDERINSTALLER,
        RECORD_NAME_TPPPACK,
        RECORD_NAME_TRU64,
        RECORD_NAME_TSTCRYPTER,
        RECORD_NAME_TTF,
        RECORD_NAME_TTPROTECT,
        RECORD_NAME_TURBOBASIC,
        RECORD_NAME_TURBOC,
        RECORD_NAME_TURBOCPP,
        RECORD_NAME_TURBOLINKER,
        RECORD_NAME_TURBOLINUX,
        RECORD_NAME_TURBOSTUDIO,
        RECORD_NAME_TURKISHCYBERSIGNATURE,
        RECORD_NAME_TURKOJANCRYPTER,
        RECORD_NAME_TVOS,
        RECORD_NAME_TVOSSDK,
        RECORD_NAME_UBUNTUCLANG,
        RECORD_NAME_UBUNTULINUX,
        RECORD_NAME_UCEXE,
        RECORD_NAME_UNDERGROUNDCRYPTER,
        RECORD_NAME_UNDOCRYPTER,
        RECORD_NAME_UNICODE,
        RECORD_NAME_UNICOMSDK,
        RECORD_NAME_UNILINK,
        RECORD_NAME_UNITY,
        RECORD_NAME_UNIVERSALTUPLECOMPILER,
        RECORD_NAME_UNIX,
        RECORD_NAME_UNKOWNCRYPTER,
        RECORD_NAME_UNK_UPXLIKE,
        RECORD_NAME_UNOPIX,
        RECORD_NAME_UPX,
        RECORD_NAME_UTF8,
        RECORD_NAME_VALVE,
        RECORD_NAME_VBNET,
        RECORD_NAME_VBSTOEXE,
        RECORD_NAME_VCASMPROTECTOR,
        RECORD_NAME_VCL,
        RECORD_NAME_VCLPACKAGEINFO,
        RECORD_NAME_VDOG,
        RECORD_NAME_VERACRYPT,
        RECORD_NAME_VINELINUX,
        RECORD_NAME_VIRBOXPROTECTOR,
        RECORD_NAME_VIRTUALIZEPROTECT,
        RECORD_NAME_VIRTUALPASCAL,
        RECORD_NAME_VISE,
        RECORD_NAME_VISUALBASIC,
        RECORD_NAME_VISUALCCPP,
        RECORD_NAME_VISUALCSHARP,
        RECORD_NAME_VISUALOBJECTS,
        RECORD_NAME_VMPROTECT,
        RECORD_NAME_VMUNPACKER,
        RECORD_NAME_VMWARE,
        RECORD_NAME_VPACKER,
        RECORD_NAME_WALLE,
        RECORD_NAME_WANGZEHUALLVM,
        RECORD_NAME_WATCHOS,
        RECORD_NAME_WATCHOSSDK,
        RECORD_NAME_WATCOMC,
        RECORD_NAME_WATCOMCCPP,
        RECORD_NAME_WATCOMDEBUGINFO,
        RECORD_NAME_WATCOMLINKER,
        RECORD_NAME_WAV,
        RECORD_NAME_WDOSX,
        RECORD_NAME_WEBP,
        RECORD_NAME_WHITELLCRYPT,
        RECORD_NAME_WINACE,
        RECORD_NAME_WINAUTH,
        RECORD_NAME_WINDOFCRYPT,
        RECORD_NAME_WINDOWS,
        RECORD_NAME_WINDOWSBITMAP,
        RECORD_NAME_WINDOWSCE,
        RECORD_NAME_WINDOWSCURSOR,
        RECORD_NAME_WINDOWSICON,
        RECORD_NAME_WINDOWSINSTALLER,
        RECORD_NAME_WINDOWSMEDIA,
        RECORD_NAME_WINDRIVERLINUX,
        RECORD_NAME_WINGSCRYPT,
        RECORD_NAME_WINKRIPT,
        RECORD_NAME_WINRAR,
        RECORD_NAME_WINUPACK,
        RECORD_NAME_WINZIP,
        RECORD_NAME_WISE,
        RECORD_NAME_WIXTOOLSET,
        RECORD_NAME_WLCRYPT,
        RECORD_NAME_WLGROUPCRYPTER,
        RECORD_NAME_WOUTHRSEXECRYPTER,
        RECORD_NAME_WWPACK,
        RECORD_NAME_WWPACK32,
        RECORD_NAME_WXWIDGETS,
        RECORD_NAME_X86ASSEMBLER,
        RECORD_NAME_XAR,
        RECORD_NAME_XBOX,
        RECORD_NAME_XCODE,
        RECORD_NAME_XCODELINKER,
        RECORD_NAME_XCOMP,
        RECORD_NAME_XENOCODE,
        RECORD_NAME_XENOCODEPOSTBUILD,
        RECORD_NAME_XENOCODEPOSTBUILD2009FORDOTNET,
        RECORD_NAME_XENOCODEPOSTBUILD2010FORDOTNET,
        RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2009,
        RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010,
        RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010ISVEDITION,
        RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2012ISVEDITION,
        RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2013ISVEDITION,
        RECORD_NAME_XML,
        RECORD_NAME_XPACK,
        RECORD_NAME_XTREAMLOK,
        RECORD_NAME_XTREMEPROTECTOR,
        RECORD_NAME_XVOLKOLAK,
        RECORD_NAME_XZ,
        RECORD_NAME_YANDEX,
        RECORD_NAME_YANO,
        RECORD_NAME_YIDUN,
        RECORD_NAME_YODASCRYPTER,
        RECORD_NAME_YODASPROTECTOR,
        RECORD_NAME_YZPACK,
        RECORD_NAME_ZELDACRYPT,
        RECORD_NAME_ZIG,
        RECORD_NAME_ZIP,
        RECORD_NAME_ZLIB,
        RECORD_NAME_ZPROTECT,
        RECORD_NAME_UNKNOWN0,
        RECORD_NAME_UNKNOWN1,
        RECORD_NAME_UNKNOWN2,
        RECORD_NAME_UNKNOWN3,
        RECORD_NAME_UNKNOWN4,
        RECORD_NAME_UNKNOWN5,
        RECORD_NAME_UNKNOWN6,
        RECORD_NAME_UNKNOWN7,
        RECORD_NAME_UNKNOWN8,
        RECORD_NAME_UNKNOWN9
    };

    static QString recordNameIdToString(qint32 nId);

    struct SCANID {
        bool bVirtual;  // TODO remove
        QString sUuid;
        XBinary::FT fileType;
        XBinary::FILEPART filePart;
        QString sArch;  // TODO remove
        QString sVersion;
        QString sInfo;
        XBinary::MODE mode;
        XBinary::ENDIAN endian;
        QString sType;
        qint64 nSize;
        qint64 nOffset;
        XBinary::COMPRESS_METHOD compressMethod;
        QString sOriginalName;
    };

    struct SCANSTRUCT {
        bool bIsHeuristic;
        bool bIsAHeuristic;
        bool bIsUnknown;
        SCANID id;
        SCANID parentId;
        quint32 nType;
        quint32 nName;
        QString sType;
        QString sName;
        QString sVersion;
        QString sInfo;
        QString varInfo;   // Signature in die scripts
        QString varInfo2;  // Signature File in die scripts
        // QString sResult;   // TODO Check
        XOptions::GLOBAL_COLOR_RECORD globalColorRecord;
        qint32 nPrio;
        bool bIsProtection;
    };

    struct ERROR_RECORD {
        QString sScript;
        QString sErrorString;
    };

    struct DEBUG_RECORD {
        QString sScript;
        QString sType;
        QString sName;
        QString sValue;
        qint64 nElapsedTime;
    };

    struct SCAN_RESULT {
        qint64 nScanTime;
        QString sFileName;
        qint64 nSize;
        XBinary::FT ftInit;
        QList<SCANSTRUCT> listRecords;
        QList<ERROR_RECORD> listErrors;
        QList<DEBUG_RECORD> listDebugRecords;
    };

    enum SF {
        SF_DEEPSCAN = 0x00000001,
        SF_HEURISTICSCAN = 0x00000002,
        SF_ALLTYPESSCAN = 0x00000004,
        SF_RECURSIVESCAN = 0x00000008,
        SF_VERBOSE = 0x00000010,
        SF_AGGRESSIVESCAN = 0x00000020,
        SF_RESULTASXML = 0x00010000,
        SF_RESULTASJSON = 0x00020000,
        SF_RESULTASTSV = 0x00040000,
        SF_RESULTASCSV = 0x00080000,
        SF_USECACHE = 0x01000000,
        SF_FORMATRESULT = 0x10000000,
    };

    enum DATABASE {
        DATABASE_MAIN = 1,
        DATABASE_EXTRA = 2,
        DATABASE_CUSTOM = 4,
    };

    struct SCAN_OPTIONS {
        //        bool bEmulate; // TODO Check
        bool bIsDeepScan;
        bool bIsHeuristicScan;
        bool bIsVerbose;
        bool bIsRecursiveScan;
        bool bIsAggressiveScan;
        bool bIsAllTypesScan;
        qint64 nBufferSize;  // TODO use global in pdstruct
        bool bUseCache;
        bool bShowInternalDetects;
        bool bResultAsXML;
        bool bResultAsJSON;
        bool bResultAsCSV;
        bool bResultAsTSV;
        bool bResultAsPlainText;
        bool bSubdirectories;
        bool bIsImage;
        bool bIsTest;
        bool bHandleInfo;
        XBinary::FT fileType;            // Optional
        XBinary::FILEPART initFilePart;  // Optional
        QVariant varInfo;                // Optional
        bool bLog;                       // TODO options
        bool bLogProfiling;
        bool bShowScanTime;
        bool bShowType;
        bool bShowVersion;
        bool bShowInfo;
        bool bFormatResult;
        bool bHideUnknown;
        bool bShowEntropy;
        bool bShowFileInfo;
        QString sSpecial;        // Special info
        QString sSignatureName;  // Optional
        QString sDetectFunction;
        bool bIsHighlight;
        bool bIsSort;
        bool bUseExtraDatabase;
        bool bUseCustomDatabase;
        SCAN_ENGINE_CALLBACK scanEngineCallback;
        void *pUserData;
    };

    struct SCAN_DATA {
        QString sSignaturePath;
    };

    struct TEST_SUCCESS_RECORD {
        QString sZipPath;
        QString sExpectedDetect;
        qint64 nScanTime;
    };

    struct TEST_FAILED_RECORD {
        QString sZipPath;
        QString sExpectedDetect;
        QString sErrorMessage;
    };

    struct TEST_RESULT {
        qint32 nTotal;
        qint32 nErrors;
        QList<TEST_SUCCESS_RECORD> listSuccess;
        QList<TEST_FAILED_RECORD> listFailed;
    };

    XScanEngine(QObject *pParent = nullptr);
    XScanEngine(const XScanEngine &other);  // Copy constructor declaration

    void setData(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pScanOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct);
    void setData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct);
    void setData(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct);
    void setData(const QString &sDirectoryName, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    // void enableDebugLog(bool bState);
    // static void debugLogFilter(QLoggingCategory *category);

    static QString createTypeString(SCAN_OPTIONS *pOptions, const SCANSTRUCT *pScanStruct);
    static SCANSTRUCT createHeaderScanStruct(const SCANSTRUCT *pScanStruct);
    static QString createResultStringEx(XScanEngine::SCAN_OPTIONS *pOptions, const SCANSTRUCT *pScanStruct);
    static QString createShortResultString(XScanEngine::SCAN_OPTIONS *pOptions, const SCAN_RESULT &scanResult);
    static XOptions::GLOBAL_COLOR_RECORD typeToGlobalColorRecord(const QString &sType);
    static qint32 typeToPrio(const QString &sType);
    static QString translateType(const QString &sType);
    static bool isHeurType(const QString &sType);
    static bool isAHeurType(const QString &sType);
    static QString _translate(const QString &sString);
    static void sortRecords(QList<SCANSTRUCT> *pListRecords);
    static QString getProtection(XScanEngine::SCAN_OPTIONS *pScanOptions, QList<SCANSTRUCT> *pListRecords);
    static bool isProtection(const QString &sType);
    static bool isScanable(const QSet<XBinary::FT> &stFT);

    XScanEngine::SCAN_RESULT scanDevice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct = nullptr);
    XScanEngine::SCAN_RESULT scanFile(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct = nullptr);
    XScanEngine::SCAN_RESULT scanMemory(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct = nullptr);
    XScanEngine::SCAN_RESULT scanSubdevice(QIODevice *pDevice, qint64 nOffset, qint64 nSize, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct = nullptr);

    void scanProcess(QIODevice *pDevice, XScanEngine::SCAN_RESULT *pScanResult, qint64 nOffset, qint64 nSize, XScanEngine::SCANID parentId,
                     XScanEngine::SCAN_OPTIONS *pScanOptions, bool bInit, XBinary::PDSTRUCT *pPdStruct);

    static QMap<quint64, QString> getScanFlags();
    static quint64 getScanFlags(SCAN_OPTIONS *pScanOptions);
    static void setScanFlags(SCAN_OPTIONS *pScanOptions, quint64 nFlags);
    static quint64 getScanFlagsFromGlobalOptions(XOptions *pGlobalOptions);
    static void setScanFlagsToGlobalOptions(XOptions *pGlobalOptions, quint64 nFlags);
    static SCAN_OPTIONS getDefaultOptions(quint64 nFlags);

    static QMap<quint64, QString> getDatabases();
    static quint64 getDatabases(SCAN_OPTIONS *pScanOptions);
    static void setDatabases(SCAN_OPTIONS *pScanOptions, quint64 nDatabases);
    static quint64 getDatabasesFromGlobalOptions(XOptions *pGlobalOptions);
    static void setDatabasesToGlobalOptions(XOptions *pGlobalOptions, quint64 nDatabases);

    static bool isScanStructPresent(QList<XScanEngine::SCANSTRUCT> *pListScanStructs, XBinary::FT fileType, RECORD_TYPE type = RECORD_TYPE_UNKNOWN,
                                    RECORD_NAME name = RECORD_NAME_UNKNOWN, const QString &sVersion = "", const QString &sInfo = "");

    TEST_RESULT test(const QString &sDirectoryName);
    static bool addTestCase(const QString &sJsonPath, const QString &sFilePath, const QString &sExpectedDetect);

    virtual void process();

protected:
    virtual void _processDetect(SCANID *pScanID, SCAN_RESULT *pScanResult, QIODevice *pDevice, const SCANID &parentId, XBinary::FT fileType, SCAN_OPTIONS *pOptions,
                                bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct) = 0;
    void _errorMessage(SCAN_OPTIONS *pOptions, const QString &sErrorMessage);
    void _warningMessage(SCAN_OPTIONS *pOptions, const QString &sWarningMessage);
    void _infoMessage(SCAN_OPTIONS *pOptions, const QString &sInfoMessage);

signals:
    void scanFileStarted(const QString &sFileName);
    void scanResult(const XScanEngine::SCAN_RESULT &scanResult);

private:
    QString m_sFileName;
    QString m_sDirectoryName;
    QIODevice *m_pDevice;
    char *m_pData;
    qint32 m_nDataSize;
    XScanEngine::SCAN_OPTIONS *m_pScanOptions;
    XScanEngine::SCAN_RESULT *m_pScanResult;
    SCAN_TYPE m_scanType;
    XBinary::PDSTRUCT *m_pPdStruct;
};

#endif  // XSCANENGINE_H
