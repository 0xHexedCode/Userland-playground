#pragma once

/*
   Author : 0xHexedCode Copyright (C) 2023
   0xHexedCode. All Rights Reserved.

   The definition types below come from my personal reversed stuff or link below.
   This header aims to provide definitions for most symbols used in reverse & security in Windows world.
   This header may be incomplete, incorrect or outdated.
   More definions will come in the future (and existing could be updated) and will be sorted.

   OS :         21h2 (Windows 10)
   Build :      19044.2486
   Verision :   10.0.19044

   Sources :
    * https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types
    * https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
    * https://github.com/processhacker/phnt
    * https://github.com/winsiderss/systeminformer/tree/master/phnt/include
    * https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html
    * https://github.com/reactos/reactos
    * https://github.com/adamhlt/Manual-DLL-Loader
    * https://github.com/vxunderground/VX-API
    * https://github.com/arbiter34/GetProcAddress/blob/master/GetProcAddress/GetProcAddress.cpp
    * Sektor7 PE Madness
*/

#define NULL_PTR                                    ((void *)0)
#define NULL                                        ((void *)0)
#define far
#define near
#define FAR                 far
#define NEAR                near
#define DUMMYSTRUCTNAME
#define DUMMYUNIONNAME
#define DUMMYUNIONNAME2
//#define __nullterminated
#define NTAPI __stdcall

#ifdef FALSE
#undef FALSE
#endif
#define FALSE 0

#ifdef TRUE
#undef TRUE
#endif
#define TRUE  1

typedef void* PVOID;
typedef PVOID HANDLE;
typedef unsigned long DWORD;
typedef HANDLE HICON;
typedef unsigned short WORD;
typedef long LONG;
typedef long NTSTATUS;

#ifdef NT_SUCCESS
#undef NT_SUCCESS
#endif
#define NT_SUCCESS                          ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH         ((NTSTATUS)0xC0000004L)
#define STATUS_PORT_NOT_SET                 ((NTSTATUS)0xC0000353L)

typedef unsigned short WCHAR;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;

typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK* PACCESS_MASK;

#ifdef UNICODE
typedef WCHAR TBYTE;
#else
typedef unsigned char TBYTE;
#endif

#ifdef UNICODE
typedef WCHAR TCHAR;
#else
typedef char TCHAR;
#endif

#if !defined(_M_IX86)
typedef unsigned __int64 ULONGLONG;
#else
typedef double ULONGLONG;
#endif

#if defined(_WIN64)
typedef unsigned __int64 ULONG_PTR;
#else
typedef unsigned long ULONG_PTR;
#endif

#if !defined(_M_IX86)
typedef __int64 LONGLONG;
#else
typedef double LONGLONG;
#endif

#if defined(_WIN64)
typedef __int64 LONG_PTR;
#else
typedef long LONG_PTR;
#endif

#ifdef _WIN64
typedef unsigned int UHALF_PTR;
#else
typedef unsigned short UHALF_PTR;
#endif

typedef int BOOL;
typedef unsigned char BYTE;
typedef BYTE BOOLEAN;
#define CALLBACK __stdcall
typedef char CCHAR;
typedef char CHAR;
typedef DWORD COLORREF;
#define CONST const

typedef unsigned __int64 DWORDLONG;
typedef ULONG_PTR DWORD_PTR;
typedef unsigned int DWORD32;
typedef unsigned __int64 DWORD64;
typedef float FLOAT;
typedef HANDLE HACCEL;
typedef float FLOAT;

#ifdef _WIN64
typedef int HALF_PTR;
#else
typedef short HALF_PTR;
#endif

typedef HANDLE HBITMAP;
typedef HANDLE HBRUSH;
typedef HANDLE HCOLORSPACE;
typedef HANDLE HCONV;
typedef HANDLE HCONVLIST;
typedef HICON HCURSOR;
typedef HANDLE HDC;
typedef HANDLE HDDEDATA;
typedef HANDLE HDESK;
typedef HANDLE HDROP;
typedef HANDLE HDWP;
typedef HANDLE HENHMETAFILE;
typedef int HFILE;
typedef HANDLE HFONT;
typedef HANDLE HGDIOBJ;
typedef HANDLE HGLOBAL;
typedef HANDLE HHOOK;
typedef HANDLE HINSTANCE;
typedef HANDLE HKEY;
typedef HANDLE HKL;
typedef HANDLE HLOCAL;
typedef HANDLE HMENU;
typedef HANDLE HMETAFILE;
typedef HINSTANCE HMODULE;
typedef HANDLE HMONITOR;   //if (WINVER >= 0x0500) 
typedef HANDLE HPALETTE;
typedef HANDLE HPEN;
typedef LONG HRESULT;
typedef HANDLE HRGN;
typedef HANDLE HRSRC;
typedef HANDLE HSZ;
typedef HANDLE WINSTA;
typedef HANDLE HWND;
typedef int INT;

#if defined(_WIN64) 
typedef __int64 INT_PTR;
#else 
typedef int INT_PTR;
#endif

typedef signed char INT8;
typedef signed short INT16;
typedef signed int INT32;
typedef signed __int64 INT64;
typedef WORD LANGID;
typedef DWORD LCID;
typedef DWORD LCTYPE;
typedef DWORD LGRPID;

typedef signed int LONG32;
typedef __int64 LONG64;
typedef LONG_PTR LPARAM;
typedef BOOL far* LPBOOL;
typedef BYTE far* LPBYTE;
typedef DWORD* LPCOLORREF;
typedef CONST CHAR* LPCSTR;     //__nullterminated

typedef CONST WCHAR* LPCWSTR;

#ifdef UNICODE
typedef LPCWSTR LPCTSTR;
#else
typedef LPCSTR LPCTSTR;
#endif

typedef CONST void* LPCVOID;
typedef DWORD* LPDWORD;
typedef HANDLE* LPHANDLE;
typedef int* LPINT;
typedef long* LPLONG;
typedef CHAR* LPSTR;

typedef WCHAR* LPWSTR;

#ifdef UNICODE
typedef LPWSTR LPTSTR;
#else
typedef LPSTR LPTSTR;
#endif

typedef void* LPVOID;
typedef WORD* LPWORD;
typedef LONG_PTR LRESULT;
typedef BOOL* PBOOL;
typedef BOOLEAN* PBOOLEAN;
typedef BYTE* PBYTE;
typedef CHAR* PCHAR;
typedef CONST CHAR* PCSTR;

#ifdef UNICODE
typedef LPCWSTR PCTSTR;
#else
typedef LPCSTR PCTSTR;
#endif

typedef CONST WCHAR* PCWSTR;
typedef DWORD* PDWORD;
typedef DWORDLONG* PDWORDLONG;
typedef DWORD_PTR* PDWORD_PTR;
typedef DWORD32* PDWORD32;
typedef DWORD64* PDWORD64;
typedef FLOAT* PFLOAT;

#ifdef _WIN64
typedef HALF_PTR* PHALF_PTR;
#else
typedef HALF_PTR* PHALF_PTR;
#endif

typedef HANDLE* PHANDLE;
typedef HKEY* PHKEY;
typedef int* PINT;
typedef INT_PTR* PINT_PTR;
typedef INT8* PINT8;
typedef INT16* PINT16;
typedef INT32* PINT32;
typedef INT64* PINT64;
typedef PDWORD PLCID;
typedef LONG* PLONG;
typedef LONGLONG* PLONGLONG;
typedef LONG_PTR* PLONG_PTR;
typedef LONG32* PLONG32;
typedef LONG64* PLONG64;

#if defined(_WIN64)
#define POINTER_32 __ptr32
#else
#define POINTER_32
#endif

#if (_MSC_VER >= 1300)
#define POINTER_64 __ptr64
#else
#define POINTER_64
#endif

#define POINTER_SIGNED __sptr
#define POINTER_UNSIGNED __uptr

#if (_MSC_VER >= 1300) && !defined(MIDL_PASS)
#define DECLSPEC_ALIGN(x)   __declspec(align(x))
#endif
#if (_MSC_VER >= 1915) && !defined(MIDL_PASS) && !defined(SORTPP_PASS) && !defined(RC_INVOKED)
#define DECLSPEC_NOINITALL __pragma(warning(push)) __pragma(warning(disable:4845)) __declspec(no_init_all) __pragma(warning(pop))
#endif

#ifdef UNICODE
typedef LPWSTR PTSTR;
#else typedef LPSTR PTSTR;
#endif

typedef UCHAR* PUCHAR;

#ifdef _WIN64
typedef UHALF_PTR* PUHALF_PTR;
#else
typedef UHALF_PTR* PUHALF_PTR;
#endif

typedef unsigned __int64 QWORD;
typedef HANDLE SC_HANDLE;
typedef LPVOID SC_LOCK;
typedef HANDLE SERVICE_STATUS_HANDLE;
typedef short SHORT;
typedef ULONG_PTR SIZE_T;
typedef LONG_PTR SSIZE_T;

typedef SHORT* PSHORT;
typedef SIZE_T* PSIZE_T;
typedef SSIZE_T* PSSIZE_T;
typedef CHAR* PSTR;
typedef TBYTE* PTBYTE;
typedef TCHAR* PTCHAR;

typedef unsigned int UINT;

#if defined(_WIN64)
typedef unsigned __int64 UINT_PTR;
#else
typedef unsigned int UINT_PTR;
#endif

typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned __int64 UINT64;
typedef unsigned long ULONG;

typedef unsigned int ULONG32;
typedef unsigned __int64 ULONG64;

typedef UINT* PUINT;
typedef UINT_PTR* PUINT_PTR;
typedef UINT8* PUINT8;
typedef UINT16* PUINT16;
typedef UINT32* PUINT32;
typedef UINT64* PUINT64;
typedef ULONG* PULONG;
typedef ULONGLONG* PULONGLONG;
typedef ULONG_PTR* PULONG_PTR;
typedef ULONG32* PULONG32;
typedef ULONG64* PULONG64;
typedef USHORT* PUSHORT;
typedef WCHAR* PWCHAR;
typedef WORD* PWORD;
typedef WCHAR* PWSTR;

typedef CHAR* LPCH, * PCH;
typedef const CHAR* LPCCH, * PCCH;
typedef char* BSTR;

typedef struct _UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef LONGLONG USN;
#define VOID void
#define WINAPI __stdcall
typedef UINT_PTR WPARAM;

#define APIENTRY WINAPI
typedef WORD ATOM;
typedef int (FAR WINAPI* FARPROC)();

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG  HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        LONG  HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER;
typedef LARGE_INTEGER* PLARGE_INTEGER;


typedef union _ULARGE_INTEGER {
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER;
typedef ULARGE_INTEGER* PULARGE_INTEGER;

typedef struct _FILETIME
{
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
}FILETIME, * PFILETIME;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _GUID
{
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    UCHAR Data4[0x8];
}GUID, * PGUID;

typedef struct _LUID
{
    DWORD LowPart;
    LONG HighPart;
}LUID, * PLUID;

typedef struct _ROOT_INFO_LUID
{
    DWORD LowPart;
    LONG HighPart;
}ROOT_INFO_LUID, * PROOT_INFO_LUID;

typedef struct DECLSPEC_ALIGN(16) _M128A {
    ULONGLONG Low;
    LONGLONG High;
} M128A, * PM128A;

typedef struct _FILE_ID_128 {
    BYTE Identifier[16];
} FILE_ID_128, * PFILE_ID_128;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} STRING, * PSTRING;

typedef struct _STRING32
{
    USHORT Length;
    USHORT MaximumLength;
    DWORD* Buffer;
}STRING32, * PSTRING32;

typedef struct _STRING64
{
    USHORT Length;
    USHORT MaximumLength;
    QWORD* Buffer;
}STRING64, * PSTRING64;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef struct _TIME_FIELDS
{
    SHORT Year;
    SHORT Month;
    SHORT Day;
    SHORT Hour;
    SHORT Minute;
    SHORT Second;
    SHORT Milliseconds;
    SHORT Weekday;
}TIME_FIELDS, * PTIME_FIELDS;

typedef struct _GENERIC_MAPPING
{
    DWORD GenericRead;
    DWORD GenericWrite;
    DWORD GenericExecute;
    DWORD GenericAll;
}GENERIC_MAPPING, * PGENERIC_MAPPING;

typedef struct _SID_IDENTIFIER_AUTHORITY
{
    UCHAR Value[0x6];
}SID_IDENTIFIER_AUTHORITY, * PSID_IDENTIFIER_AUTHORITY;

typedef struct _SID
{
    UCHAR Revision;
    UCHAR SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    DWORD SubAuthority[0x1];
}SID, * PSID;

typedef struct _SID_AND_ATTRIBUTES
{
    PSID Sid;
    DWORD Attributes;
}SID_AND_ATTRIBUTES, * PSID_AND_ATTRIBUTES;

//typedef PVOID PSID;

typedef USHORT SECURITY_DESCRIPTOR_CONTROL, * PSECURITY_DESCRIPTOR_CONTROL;

typedef struct _ACL {
    UCHAR AclRevision;
    UCHAR Sbz1;
    USHORT AclSize;
    USHORT AceCount;
    USHORT Sbz2;
} ACL, * PACL;

typedef struct _ACCEL
{
    UCHAR fVirt;
    WORD key;
    WORD cmd;
}ACCEL, * PACCEL;

typedef enum _ACL_INFORMATION_CLASS // int32_t
{
    AclRevisionInformation = 0x1,
    AclSizeInformation = 0x2
}ACL_INFORMATION_CLASS, * PACL_INFORMATION_CLASS;

typedef struct _ACL_REVISION_INFORMATION
{
    DWORD AclRevision;
}ACL_REVISION_INFORMATION, * PACL_REVISION_INFORMATION;

typedef struct _ACL_SIZE_INFORMATION
{
    DWORD AceCount;
    DWORD AclBytesInUse;
    DWORD AclBytesFree;
}ACL_SIZE_INFORMATION, * PACL_SIZE_INFORMATION;

/*struct _SECURITY_DESCRIPTOR
{
    uint8_t Revision;
    uint8_t Sbz1;
    uint16_t Control;
    void* Owner;
    void* Group;
    struct _ACL* Sacl;
    struct _ACL* Dacl;
};*/
typedef struct _SECURITY_DESCRIPTOR {
    BYTE                        Revision;
    BYTE                        Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    PSID                        Owner;
    PSID                        Group;
    PACL                        Sacl;
    PACL                        Dacl;
} SECURITY_DESCRIPTOR, * PSECURITY_DESCRIPTOR;

typedef struct _SECURITY_ATTRIBUTES
{
    DWORD nLength;
    PSECURITY_DESCRIPTOR lpSecurityDescriptor;
    BOOL bInheritHandle;
}SECURITY_ATTRIBUTES, * PSECURITY_ATTRIBUTES;

typedef struct _GROUP_AFFINITY
{
    QWORD* Mask;
    WORD Group;
    WORD Reserved[0x3];
}GROUP_AFFINITY, * PGROUP_AFFINITY;

typedef PVOID HCERTSTORE;

typedef struct _HMAC_INFORMATION
{
    DWORD HashAlgid;
    UCHAR* pbInnerString;
    DWORD cbInnerString;
    UCHAR* pbOuterString;
    DWORD cbOuterString;
}HMAC_INFORMATION, * PHMAC_INFORMATION;

typedef struct _CRYPTOAPI_BLOB
{
    DWORD cbData;
    UCHAR* pbData;
}CRYPTOAPI_BLOB, * PCRYPTOAPI_BLOB;

typedef struct _CRYPT_BIT_BLOB
{
    DWORD cbData;
    UCHAR* pbData;
    DWORD cUnusedBits;
}CRYPT_BIT_BLOB, * PCRYPT_BIT_BLOB;

typedef struct _CRYPT_ATTRIBUTE
{
    PSTR pszObjId;
    DWORD cValue;
    CRYPTOAPI_BLOB* rgValue;
}CRYPT_ATTRIBUTE, * PCRYPT_ATTRIBUTE;

typedef struct _CRYPT_ATTRIBUTES
{
    DWORD cAttr;
    CRYPT_ATTRIBUTE* rgAttr;
}CRYPT_ATTRIBUTES, * PCRYPT_ATTRIBUTES;

typedef struct _CRYPT_ALGORITHM_IDENTIFIER
{
    PSTR pszObjId;
    CRYPTOAPI_BLOB Parameters;
}CRYPT_ALGORITHM_IDENTIFIER, * PCRYPT_ALGORITHM_IDENTIFIER;

typedef struct _CERT_TRUST_STATUS
{
    DWORD dwErrorStatus;
    DWORD dwInfoStatus;
}CERT_TRUST_STATUS, * PCERT_TRUST_STATUS;

typedef struct _CTL_ENTRY
{
    CRYPTOAPI_BLOB SubjectIdentifier;
    DWORD cAttribute;
    CRYPT_ATTRIBUTE* rgAttribute;
}CTL_ENTRY, * PCTL_ENTRY;

typedef struct _CTL_USAGE
{
    DWORD cUsageIdentifier;
    PSTR* rgpszUsageIdentifier;
}CTL_USAGE, * PCTL_USAGE;

typedef struct _CERT_EXTENSION
{
    PSTR pszObjId;
    BOOL fCritical;
    CRYPTOAPI_BLOB Value;
}CERT_EXTENSION, * PCERT_EXTENSION;

typedef struct _CTL_INFO
{
    DWORD dwVersion;
    CTL_USAGE SubjectUsage;
    CRYPTOAPI_BLOB ListIdentifier;
    CRYPTOAPI_BLOB SequenceNumber;
    FILETIME ThisUpdate;
    FILETIME NextUpdate;
    CRYPT_ALGORITHM_IDENTIFIER SubjectAlgorithm;
    DWORD cCTLEntry;
    CTL_ENTRY* rgCTLEntry;
    DWORD cExtension;
    CERT_EXTENSION* rgExtension;
}CTL_INFO, * PCTL_INFO;

typedef struct _CTL_CONTEXT
{
    DWORD dwMsgAndCertEncodingType;
    UCHAR* pbCtlEncoded;
    DWORD cbCtlEncoded;
    CTL_INFO* pCtlInfo;
    PVOID hCertStore;
    PVOID hCryptMsg;
    UCHAR* pbCtlContent;
    DWORD cbCtlContent;
}CTL_CONTEXT, * PCTL_CONTEXT;

typedef struct _CERT_PUBLIC_KEY_INFO
{
    CRYPT_ALGORITHM_IDENTIFIER Algorithm;
    CRYPT_BIT_BLOB PublicKey;
}CERT_PUBLIC_KEY_INFO, * PCERT_PUBLIC_KEY_INFO;

typedef struct _CERT_INFO
{
    DWORD dwVersion;
    CRYPTOAPI_BLOB SerialNumber;
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    CRYPTOAPI_BLOB Issuer;
    FILETIME NotBefore;
    FILETIME NotAfter;
    CRYPTOAPI_BLOB Subject;
    CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
    CRYPT_BIT_BLOB IssuerUniqueId;
    CRYPT_BIT_BLOB SubjectUniqueId;
    DWORD cExtension;
    CERT_EXTENSION* rgExtension;
}CERT_INFO, * PCERT_INFO;

typedef struct _CERT_CONTEXT
{
    DWORD dwCertEncodingType;
    UCHAR* pbCertEncoded;
    DWORD cbCertEncoded;
    CERT_INFO* pCertInfo;
    HCERTSTORE hCertStore;
}CERT_CONTEXT, * PCERT_CONTEXT;

typedef struct _CRL_ENTRY
{
    CRYPTOAPI_BLOB SerialNumber;
    FILETIME RevocationDate;
    DWORD cExtension;
    CERT_EXTENSION* rgExtension;
}CRL_ENTRY, * PCRL_ENTRY;

typedef struct _CRL_INFO
{
    DWORD dwVersion;
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    CRYPTOAPI_BLOB Issuer;
    FILETIME ThisUpdate;
    FILETIME NextUpdate;
    DWORD cCRLEntry;
    CRL_ENTRY* rgCRLEntry;
    DWORD cExtension;
    CERT_EXTENSION* rgExtension;
}CRL_INFO, * PCRL_INFO;

typedef struct _CRL_CONTEXT
{
    DWORD dwCertEncodingType;
    UCHAR* pbCrlEncoded;
    DWORD cbCrlEncoded;
    CRL_INFO* pCrlInfo;
    HCERTSTORE hCertStore;
}CRL_CONTEXT, * PCRL_CONTEXT;

typedef struct _CERT_REVOCATION_CRL_INFO
{
    DWORD cbSize;
    CRL_CONTEXT* pBaseCrlContext;
    CRL_CONTEXT* pDeltaCrlContext;
    CRL_ENTRY* pCrlEntry;
    BOOL fDeltaCrlEntry;
}CERT_REVOCATION_CRL_INFO, * PCERT_REVOCATION_CRL_INFO;

typedef struct _CERT_REVOCATION_INFO
{
    DWORD cbSize;
    DWORD dwRevocationResult;
    PSTR pszRevocationOid;
    PVOID pvOidSpecificInfo;
    BOOL fHasFreshnessTime;
    DWORD dwFreshnessTime;
    CERT_REVOCATION_CRL_INFO* pCrlInfo;
}CERT_REVOCATION_INFO, * PCERT_REVOCATION_INFO;

typedef struct _CERT_CHAIN_ELEMENT
{
    DWORD cbSize;
    CERT_CONTEXT* pCertContext;
    CERT_TRUST_STATUS TrustStatus;
    CERT_REVOCATION_INFO* pRevocationInfo;
    CTL_USAGE* pIssuanceUsage;
    CTL_USAGE* pApplicationUsage;
    PWSTR pwszExtendedErrorInfo;
}CERT_CHAIN_ELEMENT, * PCERT_CHAIN_ELEMENT;

typedef struct _CERT_TRUST_LIST_INFO
{
    DWORD cbSize;
    CTL_ENTRY* pCtlEntry;
    CTL_CONTEXT const* pCtlContext;
}CERT_TRUST_LIST_INFO, * PCERT_TRUST_LIST_INFO;

typedef struct _CERT_SIMPLE_CHAIN
{
    DWORD cbSize;
    CERT_TRUST_STATUS TrustStatus;
    DWORD cElement;
    CERT_CHAIN_ELEMENT** rgpElement;
    CERT_TRUST_LIST_INFO* pTrustListInfo;
    BOOL fHasRevocationFreshnessTime;
    DWORD dwRevocationFreshnessTime;
}CERT_SIMPLE_CHAIN, * PCERT_SIMPLE_CHAIN;

typedef struct _CERT_CHAIN_CONTEXT
{
    DWORD cbSize;
    CERT_TRUST_STATUS TrustStatus;
    DWORD cChain;
    CERT_SIMPLE_CHAIN** rgpChain;
    DWORD cLowerQualityChainContext;
    struct CERT_CHAIN_CONTEXT** rgpLowerQualityChainContext;
    BOOL fHasRevocationFreshnessTime;
    DWORD dwRevocationFreshnessTime;
    DWORD dwCreateFlags;
    GUID ChainId;
}CERT_CHAIN_CONTEXT, * PCERT_CHAIN_CONTEXT;

typedef struct _BCRYPT_ALGORITHM_IDENTIFIER
{
    PWSTR pszName;  //AKA unicode string
    DWORD dwClass;
    DWORD dwFlags;
}BCRYPT_ALGORITHM_IDENTIFIER, * PBCRYPT_ALGORITHM_IDENTIFIER;

typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
{
    DWORD cbSize;
    DWORD dwInfoVersion;
    UCHAR* pbNonce;
    DWORD cbNonce;
    UCHAR* pbAuthData;
    DWORD cbAuthData;
    UCHAR* pbTag;
    DWORD cbTag;
    UCHAR* pbMacContext;
    DWORD cbMacContext;
    DWORD cbAAD;
    QWORD cbData;
    DWORD dwFlags;
}BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, * PBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;

typedef struct _BCRYPT_DH_KEY_BLOB
{
    DWORD dwMagic;
    DWORD cbKey;
}BCRYPT_DH_KEY_BLOB, * PBCRYPT_DH_KEY_BLOB;

typedef struct _BCRYPT_DH_PARAMETER_HEADER
{
    DWORD cbLength;
    DWORD dwMagic;
    DWORD cbKeyLength;
}BCRYPT_DH_PARAMETER_HEADER, * PBCRYPT_DH_PARAMETER_HEADER;

typedef struct _BCRYPT_DSA_KEY_BLOB
{
    DWORD dwMagic;
    DWORD cbKey;
    UCHAR Count[0x4];
    UCHAR Seed[0x14];
    UCHAR q[0x14];
}BCRYPT_DSA_KEY_BLOB, * PBCRYPT_DSA_KEY_BLOB;

typedef enum _HASHALGORITHM_ENUM // int32_t
{
    DSA_HASH_ALGORITHM_SHA1 = 0x0,
    DSA_HASH_ALGORITHM_SHA256 = 0x1,
    DSA_HASH_ALGORITHM_SHA512 = 0x2
}HASHALGORITHM_ENUM, * PHASHALGORITHM_ENUM;

typedef enum _DSAFIPSVERSION_ENUM // int32_t
{
    DSA_FIPS186_2 = 0x0,
    DSA_FIPS186_3 = 0x1
}DSAFIPSVERSION_ENUM, * PDSAFIPSVERSION_ENUM;

typedef struct _BCRYPT_DSA_KEY_BLOB_V2
{
    DWORD dwMagic;
    DWORD cbKey;
    HASHALGORITHM_ENUM hashAlgorithm;
    DSAFIPSVERSION_ENUM standardVersion;
    DWORD cbSeedLength;
    DWORD cbGroupSize;
    UCHAR Count[0x4];
}BCRYPT_DSA_KEY_BLOB_V2, * PBCRYPT_DSA_KEY_BLOB_V2;

typedef struct _BCRYPT_DSA_PARAMETER_HEADER
{
    DWORD cbLength;
    DWORD dwMagic;
    DWORD cbKeyLength;
    UCHAR Count[0x4];
    UCHAR Seed[0x14];
    UCHAR q[0x14];
}BCRYPT_DSA_PARAMETER_HEADER, * PBCRYPT_DSA_PARAMETER_HEADER;

typedef struct _BCRYPT_DSA_PARAMETER_HEADER_V2
{
    DWORD cbLength;
    DWORD dwMagic;
    DWORD cbKeyLength;
    HASHALGORITHM_ENUM hashAlgorithm;
    DSAFIPSVERSION_ENUM standardVersion;
    DWORD cbSeedLength;
    DWORD cbGroupSize;
    UCHAR Count[0x4];
}BCRYPT_DSA_PARAMETER_HEADER_V2, * PBCRYPT_DSA_PARAMETER_HEADER_V2;

typedef enum _ECC_CURVE_ALG_ID_ENUM// int32_t
{
    BCRYPT_NO_CURVE_GENERATION_ALG_ID = 0x0
}ECC_CURVE_ALG_ID_ENUM, * PECC_CURVE_ALG_ID_ENUM;

typedef enum _ECC_CURVE_TYPE_ENUM // int32_t
{
    BCRYPT_ECC_PRIME_SHORT_WEIERSTRASS_CURVE = 0x1,
    BCRYPT_ECC_PRIME_TWISTED_EDWARDS_CURVE = 0x2,
    BCRYPT_ECC_PRIME_MONTGOMERY_CURVE = 0x3
}ECC_CURVE_TYPE_ENUM, * PECC_CURVE_TYPE_ENUM;

typedef struct _BCRYPT_ECCFULLKEY_BLOB
{
    DWORD dwMagic;
    DWORD dwVersion;
    ECC_CURVE_TYPE_ENUM dwCurveType;
    ECC_CURVE_ALG_ID_ENUM dwCurveGenerationAlgId;
    DWORD cbFieldLength;
    DWORD cbSubgroupOrder;
    DWORD cbCofactor;
    DWORD cbSeed;
}BCRYPT_ECCFULLKEY_BLOB, * PBCRYPT_ECCFULLKEY_BLOB;

typedef struct _BCRYPT_ECCKEY_BLOB
{
    DWORD dwMagic;
    DWORD cbKey;
}BCRYPT_ECCKEY_BLOB, * PBCRYPT_ECCKEY_BLOB;

typedef struct _BCRYPT_ECC_CURVE_NAMES
{
    DWORD dwEccCurveNames;
    USHORT** pEccCurveNames;
}BCRYPT_ECC_CURVE_NAMES, * PBCRYPT_ECC_CURVE_NAMES;

typedef struct _BCRYPT_INTERFACE_VERSION
{
    USHORT MajorVersion;
    USHORT MinorVersion;
}BCRYPT_INTERFACE_VERSION, * PBCRYPT_INTERFACE_VERSION;

typedef struct _BCRYPT_KEY_BLOB
{
    DWORD Magic;
}BCRYPT_KEY_BLOB, * PBCRYPT_KEY_BLOB;

typedef struct _BCRYPT_KEY_DATA_BLOB_HEADER
{
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD cbKeyData;
}BCRYPT_KEY_DATA_BLOB_HEADER, * PBCRYPT_KEY_DATA_BLOB_HEADER;

typedef enum BCRYPT_HASH_OPERATION_TYPE// int32_t
{
    BCRYPT_HASH_OPERATION_HASH_DATA = 0x1,
    BCRYPT_HASH_OPERATION_FINISH_HASH = 0x2
}BCRYPT_HASH_OPERATION_TYPE, * PBCRYPT_HASH_OPERATION_TYPE;

typedef struct _BCRYPT_MULTI_HASH_OPERATION
{
    DWORD iHash;
    BCRYPT_HASH_OPERATION_TYPE hashOperation;
    UCHAR* pbBuffer;
    DWORD cbBuffer;

}BCRYPT_MULTI_HASH_OPERATION, * PBCRYPT_MULTI_HASH_OPERATION;

typedef struct _BCRYPT_MULTI_OBJECT_LENGTH_STRUCT
{
    DWORD cbPerObject;
    DWORD cbPerElement;
}BCRYPT_MULTI_OBJECT_LENGTH_STRUCT, * PBCRYPT_MULTI_OBJECT_LENGTH_STRUCT;

typedef struct _BCRYPT_OAEP_PADDING_INFO
{
    USHORT const* pszAlgId;
    UCHAR* pbLabel;
    DWORD cbLabel;

}BCRYPT_OAEP_PADDING_INFO, * PBCRYPT_OAEP_PADDING_INFO;

typedef struct _BCRYPT_OID
{
    DWORD cbOID;
    UCHAR* pbOID;
}BCRYPT_OID, * PBCRYPT_OID;

typedef struct _BCRYPT_OID_LIST
{
    DWORD dwOIDCount;
    BCRYPT_OID* pOIDs;
}BCRYPT_OID_LIST, * PBCRYPT_OID_LIST;

typedef struct _BCRYPT_PKCS1_PADDING_INFO
{
    USHORT const* pszAlgId;
}BCRYPT_PKCS1_PADDING_INFO, * PBCRYPT_PKCS1_PADDING_INFO;

typedef struct _BCRYPT_PROVIDER_NAME
{
    USHORT* pszProviderName;
}BCRYPT_PROVIDER_NAME, * PBCRYPT_PROVIDER_NAME;

typedef struct _BCRYPT_PSS_PADDING_INFO
{
    USHORT const* pszAlgId;
    DWORD cbSalt;

}BCRYPT_PSS_PADDING_INFO, * PBCRYPT_PSS_PADDING_INFO;

typedef struct _BCRYPT_RSAKEY_BLOB
{
    DWORD Magic;
    DWORD BitLength;
    DWORD cbPublicExp;
    DWORD cbModulus;
    DWORD cbPrime1;
    DWORD cbPrime2;
}BCRYPT_RSAKEY_BLOB, * PBCRYPT_RSAKEY_BLOB;

typedef struct _BCRYPTBUFFER
{
    DWORD cbBuffer;
    DWORD BufferType;
    PVOID pvBuffer;
}BCRYPTBUFFER, * PBCRYPTBUFFER;

typedef struct _BCRYPTBUFFERDESC
{
    DWORD ulVersion;
    DWORD cBuffers;
    BCRYPTBUFFER* pBuffers;
}BCRYPTBUFFERDESC, * PBCRYPTBUFFERDESC;

typedef enum _BCRYPT_MULTI_OPERATION_TYPE // int32_t
{
    BCRYPT_OPERATION_TYPE_HASH = 0x1
}BCRYPT_MULTI_OPERATION_TYPE, * PBCRYPT_MULTI_OPERATION_TYPE;

typedef struct _CRYPT_ATTRIBUTE_TYPE_VALUE
{
    char* pszObjId;
    CRYPTOAPI_BLOB Value;
}CRYPT_ATTRIBUTE_TYPE_VALUE, * PCRYPT_ATTRIBUTE_TYPE_VALUE;

typedef struct _CRYPTPROTECT_PROMPTSTRUCT
{
    DWORD cbSize;
    DWORD dwPromptFlags;
    struct HWND__* hwndApp;
    USHORT const* szPrompt;
}CRYPTPROTECT_PROMPTSTRUCT, * PCRYPTPROTECT_PROMPTSTRUCT;

typedef struct _CRYPT_3DES_KEY_STATE
{
    UCHAR Key[0x18];
    UCHAR IV[0x8];
    UCHAR Feedback[0x8];
}CRYPT_3DES_KEY_STATE, * PCRYPT_3DES_KEY_STATE;

typedef struct _CRYPT_AES_128_KEY_STATE
{
    UCHAR Key[0x10];
    UCHAR IV[0x10];
    UCHAR EncryptionState[0xb][0x10];
    UCHAR DecryptionState[0xb][0x10];
    UCHAR Feedback[0x10];
}CRYPT_AES_128_KEY_STATE, * PCRYPT_AES_128_KEY_STATE;

typedef struct _CRYPT_AES_256_KEY_STATE
{
    UCHAR Key[0x20];
    UCHAR IV[0x10];
    UCHAR EncryptionState[0xf][0x10];
    UCHAR DecryptionState[0xf][0x10];
    UCHAR Feedback[0x10];
}CRYPT_AES_256_KEY_STATE, * PCRYPT_AES_256_KEY_STATE;

typedef struct _CRYPT_BLOB_ARRAY
{
    DWORD cBlob;
    CRYPTOAPI_BLOB* rgBlob;
}CRYPT_BLOB_ARRAY, * PCRYPT_BLOB_ARRAY;

typedef struct _CRYPT_CONTENT_INFO
{
    char* pszObjId;
    CRYPTOAPI_BLOB Content;
}CRYPT_CONTENT_INFO, * PCRYPT_CONTENT_INFO;

typedef struct _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY
{
    char* pszObjId;
    DWORD cValue;
    CRYPTOAPI_BLOB* rgValue;
}CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY, * PCRYPT_CONTENT_INFO_SEQUENCE_OF_ANY;

typedef struct _CRYPT_CONTEXTS
{
    DWORD cContexts;
    USHORT** rgpszContexts;//wchar16** rgpszContexts;
}CRYPT_CONTEXTS, * PCRYPT_CONTEXTS;

typedef struct _CRYPT_CONTEXT_CONFIG
{
    DWORD dwFlags;
    DWORD dwReserved;
}CRYPT_CONTEXT_CONFIG, * PCRYPT_CONTEXT_CONFIG;

typedef struct _CRYPT_CONTEXT_FUNCTIONS
{
    DWORD cFunctions;
    USHORT** rgpszFunctions;//wchar16**
}CRYPT_CONTEXT_FUNCTIONS, * PCRYPT_CONTEXT_FUNCTIONS;

typedef struct _CRYPT_CONTEXT_FUNCTION_CONFIG
{
    DWORD dwFlags;
    DWORD dwReserved;
}CRYPT_CONTEXT_FUNCTION_CONFIG, * PCRYPT_CONTEXT_FUNCTION_CONFIG;

typedef struct _CRYPT_CONTEXT_FUNCTION_PROVIDERS
{
    DWORD cProviders;
    USHORT** rgpszProviders;//wchar16**
}CRYPT_CONTEXT_FUNCTION_PROVIDERS, * PCRYPT_CONTEXT_FUNCTION_PROVIDERS;

typedef struct _CRYPT_CREDENTIALS
{
    DWORD cbSize;
    char const* pszCredentialsOid;
    PVOID pvCredentials;
}CRYPT_CREDENTIALS, * PCRYPT_CREDENTIALS;

typedef struct _CRYPT_CSP_PROVIDER
{
    DWORD dwKeySpec;
    USHORT* pwszProviderName;
    CRYPT_BIT_BLOB Signature;
}CRYPT_CSP_PROVIDER, * PCRYPT_CSP_PROVIDER;

typedef struct _CRYPT_DECODE_PARA
{
    DWORD cbSize;
    PVOID(*pfnAlloc)(QWORD);
    void (*pfnFree)(PVOID);
}CRYPT_DECODE_PARA, * PCRYPT_DECODE_PARA;

typedef struct _CRYPT_DECRYPT_MESSAGE_PARA
{
    DWORD cbSize;
    DWORD dwMsgAndCertEncodingType;
    DWORD cCertStore;
    PVOID* rghCertStore;
}CRYPT_DECRYPT_MESSAGE_PARA, * PCRYPT_DECRYPT_MESSAGE_PARA;

typedef struct _CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA
{
    DWORD cOID;
    char** rgpszOID;
}CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA, * PCRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA;

typedef struct _CRYPT_DES_KEY_STATE
{
    UCHAR Key[0x8];
    UCHAR IV[0x8];
    UCHAR Feedback[0x8];
}CRYPT_DES_KEY_STATE, * PCRYPT_DES_KEY_STATE;

typedef struct _CRYPT_ECC_CMS_SHARED_INFO
{
    CRYPT_ALGORITHM_IDENTIFIER Algorithm;
    CRYPTOAPI_BLOB EntityUInfo;
    UCHAR rgbSuppPubInfo[0x4];
}CRYPT_ECC_CMS_SHARED_INFO, * PCRYPT_ECC_CMS_SHARED_INFO;

typedef struct _CRYPT_ECC_PRIVATE_KEY_INFO
{
    DWORD dwVersion;
    CRYPTOAPI_BLOB PrivateKey;
    char* szCurveOid;
    CRYPT_BIT_BLOB PublicKey;
}CRYPT_ECC_PRIVATE_KEY_INFO, * PCRYPT_ECC_PRIVATE_KEY_INFO;

typedef struct _CRYPT_ENCODE_PARA
{
    DWORD cbSize;
    PVOID(*pfnAlloc)(QWORD);
    void (*pfnFree)(PVOID);
}CRYPT_ENCODE_PARA, * PCRYPT_ENCODE_PARA;

typedef struct _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO
{
    struct _CRYPT_ALGORITHM_IDENTIFIER EncryptionAlgorithm;
    struct _CRYPTOAPI_BLOB EncryptedPrivateKey;
}CRYPT_ENCRYPTED_PRIVATE_KEY_INFO, * PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO;

typedef struct _CRYPT_ENCRYPT_MESSAGE_PARA
{
    DWORD cbSize;
    DWORD dwMsgEncodingType;
    QWORD hCryptProv;
    CRYPT_ALGORITHM_IDENTIFIER ContentEncryptionAlgorithm;
    PVOID pvEncryptionAuxInfo;
    DWORD dwFlags;
    DWORD dwInnerContentType;
}CRYPT_ENCRYPT_MESSAGE_PARA, * PCRYPT_ENCRYPT_MESSAGE_PARA;

typedef struct _CRYPT_ENROLLMENT_NAME_VALUE_PAIR
{
    USHORT* pwszName;//wchar16*
    USHORT* pwszValue;//wchar16*
}CRYPT_ENROLLMENT_NAME_VALUE_PAIR, * PCRYPT_ENROLLMENT_NAME_VALUE_PAIR;

typedef struct _CERT_REVOCATION_CHAIN_PARA
{
    DWORD cbSize;
    PVOID hChainEngine;
    PVOID hAdditionalStore;
    DWORD dwChainFlags;
    DWORD dwUrlRetrievalTimeout;
    FILETIME* pftCurrentTime;
    FILETIME* pftCacheResync;
    DWORD cbMaxUrlRetrievalByteCount;
}CERT_REVOCATION_CHAIN_PARA, * PCERT_REVOCATION_CHAIN_PARA;

typedef struct _CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO
{
    DWORD cbSize;
    LONG iDeltaCrlIndicator;
    FILETIME* pftCacheResync;
    FILETIME* pLastSyncTime;
    FILETIME* pMaxAgeTime;
    CERT_REVOCATION_CHAIN_PARA* pChainPara;
    CRYPTOAPI_BLOB* pDeltaCrlIndicator;
}CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO, * PCRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO;

typedef struct _CRYPT_HASH_INFO
{
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPTOAPI_BLOB Hash;
}CRYPT_HASH_INFO, * PCRYPT_HASH_INFO;

typedef struct _CRYPT_HASH_MESSAGE_PARA
{
    DWORD cbSize;
    DWORD dwMsgEncodingType;
    QWORD hCryptProv;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    PVOID pvHashAuxInfo;
}CRYPT_HASH_MESSAGE_PARA, * PCRYPT_HASH_MESSAGE_PARA;

typedef struct _CRYPT_IMAGE_REF
{
    USHORT* pszImage;
    DWORD dwFlags;
}CRYPT_IMAGE_REF, * PCRYPT_IMAGE_REF;

typedef struct _CRYPT_INTERFACE_REG
{
    DWORD dwInterface;
    DWORD dwFlags;
    DWORD cFunctions;
    USHORT** rgpszFunctions;
}CRYPT_INTERFACE_REG, * PCRYPT_INTERFACE_REG;

typedef struct _CRYPT_IMAGE_REG
{
    USHORT* pszImage;
    DWORD cInterfaces;
    CRYPT_INTERFACE_REG** rgpInterfaces;
}CRYPT_IMAGE_REG, * PCRYPT_IMAGE_REG;

typedef struct _CRYPT_KEY_PROV_PARAM
{
    DWORD dwParam;
    UCHAR* pbData;
    DWORD cbData;
    DWORD dwFlags;
}CRYPT_KEY_PROV_PARAM, * PCRYPT_KEY_PROV_PARAM;

typedef struct _CRYPT_KEY_PROV_INFO
{
    USHORT* pwszContainerName;
    USHORT* pwszProvName;
    DWORD dwProvType;
    DWORD dwFlags;
    DWORD cProvParam;
    CRYPT_KEY_PROV_PARAM* rgProvParam;
    DWORD dwKeySpec;
}CRYPT_KEY_PROV_INFO, * PCRYPT_KEY_PROV_INFO;

typedef struct _CRYPT_KEY_SIGN_MESSAGE_PARA
{
    DWORD cbSize;
    DWORD dwMsgAndCertEncodingType;
    union
    {
        QWORD hCryptProv;
        QWORD hNCryptKey;
    };
    DWORD dwKeySpec;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    PVOID pvHashAuxInfo;
    CRYPT_ALGORITHM_IDENTIFIER PubKeyAlgorithm;
}CRYPT_KEY_SIGN_MESSAGE_PARA, * PCRYPT_KEY_SIGN_MESSAGE_PARA;

typedef struct _CRYPT_KEY_VERIFY_MESSAGE_PARA
{
    DWORD cbSize;
    DWORD dwMsgEncodingType;
    QWORD hCryptProv;
}CRYPT_KEY_VERIFY_MESSAGE_PARA, * PCRYPT_KEY_VERIFY_MESSAGE_PARA;

typedef struct _CRYPT_MASK_GEN_ALGORITHM
{
    char* pszObjId;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
}CRYPT_MASK_GEN_ALGORITHM, * PCRYPT_MASK_GEN_ALGORITHM;

typedef struct _CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE
{
    DWORD cbSize;
    LONG(*pfnGet)(PVOID, CRYPTOAPI_BLOB*, DWORD, CRYPTOAPI_BLOB*, UCHAR**, DWORD*, USHORT const**, CRYPTOAPI_BLOB**);
    void (*pfnRelease)(DWORD, PVOID);
    void (*pfnFreePassword)(PVOID, USHORT const*);
    void (*pfnFree)(PVOID, UCHAR*);
    void (*pfnFreeIdentifier)(PVOID, CRYPTOAPI_BLOB*);
}CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE, * PCRYPT_OBJECT_LOCATOR_PROVIDER_TABLE;

typedef struct _CRYPT_OBJID_TABLE
{
    DWORD dwAlgId;
    char const* pszObjId;
}CRYPT_OBJID_TABLE, * PCRYPT_OBJID_TABLE;

typedef struct _CRYPT_OID_FUNC_ENTRY
{
    char const* pszOID;
    PVOID pvFuncAddr;
}CRYPT_OID_FUNC_ENTRY, * PCRYPT_OID_FUNC_ENTRY;

typedef struct _CRYPT_OID_INFO
{
    DWORD cbSize;
    char const* pszOID;
    USHORT const* pwszName;
    DWORD dwGroupId;
    union
    {
        DWORD dwValue;
        DWORD Algid;
        DWORD dwLength;
    } __inner4;
    CRYPTOAPI_BLOB ExtraInfo;
}CRYPT_OID_INFO, * PCRYPT_OID_INFO;

typedef struct _CRYPT_PASSWORD_CREDENTIALSA
{
    DWORD cbSize;
    char* pszUsername;
    char* pszPassword;
}CRYPT_PASSWORD_CREDENTIALSA, * PCRYPT_PASSWORD_CREDENTIALSA;

typedef struct _CRYPT_PASSWORD_CREDENTIALSW
{
    DWORD cbSize;
    USHORT* pszUsername;
    USHORT* pszPassword;
}CRYPT_PASSWORD_CREDENTIALSW, * PCRYPT_PASSWORD_CREDENTIALSW;

typedef struct _CRYPT_PKCS12_PBE_PARAMS
{
    LONG iIterations;
    DWORD cbSalt;
}CRYPT_PKCS12_PBE_PARAMS, * PCRYPT_PKCS12_PBE_PARAMS;

typedef struct _CRYPT_PKCS8_EXPORT_PARAMS
{
    QWORD hCryptProv;
    DWORD dwKeySpec;
    char* pszPrivateKeyObjId;
    LONG(*pEncryptPrivateKeyFunc)(CRYPT_ALGORITHM_IDENTIFIER*, CRYPTOAPI_BLOB*, UCHAR*, DWORD*, PVOID);
    PVOID pVoidEncryptFunc;
}CRYPT_PKCS8_EXPORT_PARAMS, * PCRYPT_PKCS8_EXPORT_PARAMS;

typedef struct _CRYPT_PRIVATE_KEY_INFO
{
    DWORD Version;
    CRYPT_ALGORITHM_IDENTIFIER Algorithm;
    CRYPTOAPI_BLOB PrivateKey;
    CRYPT_ATTRIBUTES* pAttributes;
}CRYPT_PRIVATE_KEY_INFO, * PCRYPT_PRIVATE_KEY_INFO;

typedef struct _CRYPT_PKCS8_IMPORT_PARAMS
{
    CRYPTOAPI_BLOB PrivateKey;
    LONG(*pResolvehCryptProvFunc)(CRYPT_PRIVATE_KEY_INFO*, QWORD*, PVOID);
    PVOID pVoidResolveFunc;
    LONG(*pDecryptPrivateKeyFunc)(CRYPT_ALGORITHM_IDENTIFIER*, CRYPTOAPI_BLOB*, UCHAR*, DWORD*, PVOID);
    PVOID pVoidDecryptFunc;
}CRYPT_PKCS8_IMPORT_PARAMS, * PCRYPT_PKCS8_IMPORT_PARAMS;

typedef struct _CRYPT_PROPERTY_REF
{
    USHORT* pszProperty;
    DWORD cbValue;
    UCHAR* pbValue;
}CRYPT_PROPERTY_REF, * PCRYPT_PROPERTY_REF;

typedef struct _CRYPT_PROVIDERS
{
    DWORD cProviders;
    USHORT** rgpszProviders;
}CRYPT_PROVIDERS, * PCRYPT_PROVIDERS;

typedef struct _CRYPT_PROVIDER_CERT
{
    DWORD cbStruct;
    CERT_CONTEXT const* pCert;
    LONG fCommercial;
    LONG fTrustedRoot;
    LONG fSelfSigned;
    LONG fTestCert;
    DWORD dwRevokedReason;
    DWORD dwConfidence;
    DWORD dwError;
    CTL_CONTEXT* pTrustListContext;
    LONG fTrustListSignerCert;
    CTL_CONTEXT const* pCtlContext;
    DWORD dwCtlError;
    LONG fIsCyclic;
    CERT_CHAIN_ELEMENT* pChainElement;
}CRYPT_PROVIDER_CERT, * PCRYPT_PROVIDER_CERT;

typedef struct _CRYPT_PROVIDER_PRIVDATA
{
    DWORD cbStruct;
    GUID gProviderID;
    DWORD cbProvData;
    PVOID pvProvData;
}CRYPT_PROVIDER_PRIVDATA, * PCRYPT_PROVIDER_PRIVDATA;

typedef struct _CMSG_SIGNER_INFO
{
    DWORD dwVersion;
    CRYPTOAPI_BLOB Issuer;
    CRYPTOAPI_BLOB SerialNumber;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
    CRYPTOAPI_BLOB EncryptedHash;
    CRYPT_ATTRIBUTES AuthAttrs;
    CRYPT_ATTRIBUTES UnauthAttrs;
}CMSG_SIGNER_INFO, * PCMSG_SIGNER_INFO;

typedef struct _CRYPT_PROVIDER_SGNR
{
    DWORD cbStruct;
    FILETIME sftVerifyAsOf;
    DWORD csCertChain;
    CRYPT_PROVIDER_CERT* pasCertChain;
    DWORD dwSignerType;
    CMSG_SIGNER_INFO* psSigner;
    DWORD dwError;
    DWORD csCounterSigners;
    struct CRYPT_PROVIDER_SGNR* pasCounterSigners;
    CERT_CHAIN_CONTEXT const* pChainContext;
}CRYPT_PROVIDER_SGNR, * PCRYPT_PROVIDER_SGNR;

typedef struct _SEALING_SIGNATURE_ATTRIBUTE
{
    DWORD version;
    DWORD signerIndex;
    CRYPT_ALGORITHM_IDENTIFIER signatureAlgorithm;
    CRYPTOAPI_BLOB encryptedDigest;
}SEALING_SIGNATURE_ATTRIBUTE, * PSEALING_SIGNATURE_ATTRIBUTE;

typedef struct _CRYPT_PROVIDER_SIGSTATE
{
    DWORD cbStruct;
    PVOID* rhSecondarySigs;
    PVOID hPrimarySig;
    LONG fFirstAttemptMade;
    LONG fNoMoreSigs;
    DWORD cSecondarySigs;
    DWORD dwCurrentIndex;
    LONG fSupportMultiSig;
    DWORD dwCryptoPolicySupport;
    DWORD iAttemptCount;
    LONG fCheckedSealing;
    SEALING_SIGNATURE_ATTRIBUTE* pSealingSignature;
}CRYPT_PROVIDER_SIGSTATE, * PCRYPT_PROVIDER_SIGSTATE;

typedef struct _CRYPT_PROVUI_DATA
{
    DWORD cbStruct;
    DWORD dwFinalError;
    USHORT* pYesButtonText;
    USHORT* pNoButtonText;
    USHORT* pMoreInfoButtonText;
    USHORT* pAdvancedLinkText;
    USHORT* pCopyActionText;
    USHORT* pCopyActionTextNoTS;
    USHORT* pCopyActionTextNotSigned;
}CRYPT_PROVUI_DATA, * PCRYPT_PROVUI_DATA;

typedef enum _WINTRUST_SIGNATURE_SETTINGS_FLAGS//uint32_t
{
    WSS_VERIFY_SPECIFIC = 0x1,
    WSS_GET_SECONDARY_SIG_COUNT = 0x2
}WINTRUST_SIGNATURE_SETTINGS_FLAGS, * PWINTRUST_SIGNATURE_SETTINGS_FLAGS;

typedef enum _CERT_STRONG_SIGN_FLAGS // uint32_t
{
    CERT_STRONG_SIGN_ENABLE_CRL_CHECK = 0x1,
    CERT_STRONG_SIGN_ENABLE_OCSP_CHECK = 0x2
}CERT_STRONG_SIGN_FLAGS, * PCERT_STRONG_SIGN_FLAGS;

typedef struct _CERT_STRONG_SIGN_SERIALIZED_INFO
{
    CERT_STRONG_SIGN_FLAGS dwFlags;
    PWSTR pwszCNGSignHashAlgids;
    PWSTR pwszCNGPubKeyMinBitLengths;
}CERT_STRONG_SIGN_SERIALIZED_INFO, * PCERT_STRONG_SIGN_SERIALIZED_INFO;

typedef struct _CERT_STRONG_SIGN_PARA
{
    DWORD cbSize;
    DWORD dwInfoChoice;
    union
    {
        PVOID pvInfo;
        CERT_STRONG_SIGN_SERIALIZED_INFO* pSerializedInfo;
        PSTR pszOID;
    };
}CERT_STRONG_SIGN_PARA, * PCERT_STRONG_SIGN_PARA;

typedef struct _WINTRUST_SIGNATURE_SETTINGS
{
    DWORD cbStruct;
    DWORD dwIndex;
    WINTRUST_SIGNATURE_SETTINGS_FLAGS dwFlags;
    DWORD cSecondarySigs;
    DWORD dwVerifiedSigIndex;
    CERT_STRONG_SIGN_PARA* pCryptoPolicy;
} WINTRUST_SIGNATURE_SETTINGS, * PWINTRUST_SIGNATURE_SETTINGS;

typedef struct _WINTRUST_BLOB_INFO
{
    DWORD cbStruct;
    GUID gSubject;
    USHORT const* pcwszDisplayName;//wchar16 const*
    DWORD cbMemObject;
    UCHAR* pbMemObject;
    DWORD cbMemSignedMsg;
    UCHAR* pbMemSignedMsg;
}WINTRUST_BLOB_INFO, * PWINTRUST_BLOB_INFO;

typedef struct _WINTRUST_CATALOG_INFO
{
    DWORD cbStruct;
    DWORD dwCatalogVersion;
    USHORT const* pcwszCatalogFilePath;
    USHORT const* pcwszMemberTag;
    USHORT const* pcwszMemberFilePath;
    PVOID hMemberFile;
    UCHAR* pbCalculatedFileHash;
    DWORD cbCalculatedFileHash;
    CTL_CONTEXT const* pcCatalogContext;
    PVOID hCatAdmin;
}WINTRUST_CATALOG_INFO, * PWINTRUST_CATALOG_INFO;

typedef struct _WINTRUST_CERT_INFO
{
    DWORD cbStruct;
    USHORT const* pcwszDisplayName;
    CERT_CONTEXT* psCertContext;
    DWORD chStores;
    PVOID* pahStores;
    DWORD dwFlags;
    FILETIME* psftVerifyAsOf;
}WINTRUST_CERT_INFO, * PWINTRUST_CERT_INFO;

typedef struct _WINTRUST_FILE_INFO
{
    DWORD cbStruct;
    USHORT const* pcwszFilePath;
    PVOID hFile;
    GUID* pgKnownSubject;
}WINTRUST_FILE_INFO, * PWINTRUST_FILE_INFO;

typedef struct _WINTRUST_SGNR_INFO
{
    DWORD cbStruct;
    USHORT const* pcwszDisplayName;
    CMSG_SIGNER_INFO* psSignerInfo;
    DWORD chStores;
    PVOID* pahStores;
}WINTRUST_SGNR_INFO, * PWINTRUST_SGNR_INFO;

typedef enum _CERT_CHAIN_POLICY_FLAGS // uint32_t
{
    CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG = 0x1,
    CERT_CHAIN_POLICY_IGNORE_CTL_NOT_TIME_VALID_FLAG = 0x2,
    CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG = 0x4,
    CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS = 0x7,
    CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG = 0x8,
    CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG = 0x10,
    CERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG = 0x20,
    CERT_CHAIN_POLICY_IGNORE_INVALID_NAME_FLAG = 0x40,
    CERT_CHAIN_POLICY_IGNORE_INVALID_POLICY_FLAG = 0x80,
    CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG = 0x100,
    CERT_CHAIN_POLICY_IGNORE_CTL_SIGNER_REV_UNKNOWN_FLAG = 0x200,
    CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN_FLAG = 0x400,
    CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN_FLAG = 0x800,
    CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS = 0xf00,
    CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG = 0x8000,
    CERT_CHAIN_POLICY_TRUST_TESTROOT_FLAG = 0x4000,
    CERT_CHAIN_POLICY_IGNORE_NOT_SUPPORTED_CRITICAL_EXT_FLAG = 0x2000,
    CERT_CHAIN_POLICY_IGNORE_PEER_TRUST_FLAG = 0x1000
}CERT_CHAIN_POLICY_FLAGS, * PCERT_CHAIN_POLICY_FLAGS;

typedef struct _CERT_CHAIN_POLICY_PARA
{
    DWORD cbSize;
    CERT_CHAIN_POLICY_FLAGS dwFlags;
    PVOID pvExtraPolicyPara;
}CERT_CHAIN_POLICY_PARA, * PCERT_CHAIN_POLICY_PARA;

typedef struct _CERT_CHAIN_POLICY_STATUS
{
    DWORD cbSize;
    DWORD dwError;
    LONG lChainIndex;
    LONG lElementIndex;
    PVOID pvExtraPolicyStatus;
}CERT_CHAIN_POLICY_STATUS, * PCERT_CHAIN_POLICY_STATUS;

typedef struct _WINTRUST_DATA
{
    DWORD cbStruct;
    void* pPolicyCallbackData;
    void* pSIPClientData;
    DWORD dwUIChoice;
    DWORD fdwRevocationChecks;
    DWORD dwUnionChoice;

    union
    {
        WINTRUST_FILE_INFO* pFile;
        WINTRUST_CATALOG_INFO* pCatalog;
        WINTRUST_BLOB_INFO* pBlob;
        WINTRUST_SGNR_INFO* pSgnr;
        WINTRUST_CERT_INFO* pCert;
    };
    DWORD dwStateAction;
    PVOID hWVTStateData;
    USHORT* pwszURLReference;
    DWORD dwProvFlags;
    DWORD dwUIContext;
    WINTRUST_SIGNATURE_SETTINGS* pSignatureSettings;
}WINTRUST_DATA, * PWINTRUST_DATA;

typedef struct _SIP_INDIRECT_DATA
{
    CRYPT_ATTRIBUTE_TYPE_VALUE Data;
    CRYPT_ALGORITHM_IDENTIFIER DigestAlgorithm;
    CRYPTOAPI_BLOB Digest;
}SIP_INDIRECT_DATA, * PSIP_INDIRECT_DATA;

typedef struct MS_ADDINFO_FLAT
{
    DWORD cbStruct;
    SIP_INDIRECT_DATA* pIndirectData;
}MS_ADDINFO_FLAT, * PMS_ADDINFO_FLAT;

typedef struct _MS_ADDINFO_BLOB
{
    DWORD cbStruct;
    DWORD cbMemObject;
    UCHAR* pbMemObject;
    DWORD cbMemSignedMsg;
    UCHAR* pbMemSignedMsg;
}MS_ADDINFO_BLOB, * PMS_ADDINFO_BLOB;

typedef enum _CRYPTCAT_OPEN_FLAGS // uint32_t
{
    CRYPTCAT_OPEN_ALWAYS = 0x2,
    CRYPTCAT_OPEN_CREATENEW = 0x1,
    CRYPTCAT_OPEN_EXISTING = 0x4,
    CRYPTCAT_OPEN_EXCLUDE_PAGE_HASHES = 0x10000,
    CRYPTCAT_OPEN_INCLUDE_PAGE_HASHES = 0x20000,
    CRYPTCAT_OPEN_VERIFYSIGHASH = 0x10000000,
    CRYPTCAT_OPEN_NO_CONTENT_HCRYPTMSG = 0x20000000,
    CRYPTCAT_OPEN_SORTED = 0x40000000,
    CRYPTCAT_OPEN_FLAGS_MASK = 0xffff0000
}CRYPTCAT_OPEN_FLAGS, * PCRYPTCAT_OPEN_FLAGS;

typedef struct CRYPTCATSTORE
{
    DWORD cbStruct;
    DWORD dwPublicVersion;
    PWSTR pwszP7File;
    QWORD* hProv;
    DWORD dwEncodingType;
    CRYPTCAT_OPEN_FLAGS fdwStoreFlags;
    HANDLE hReserved;
    HANDLE hAttrs;
    PVOID hCryptMsg;
    HANDLE hSorted;
}CRYPTCATSTORE, * PCRYPTCATSTORE;

typedef struct _CRYPTCATMEMBER
{
    DWORD cbStruct;
    PWSTR pwszReferenceTag;
    PWSTR pwszFileName;
    GUID gSubjectType;
    DWORD fdwMemberFlags;
    SIP_INDIRECT_DATA* pIndirectData;
    DWORD dwCertVersion;
    DWORD dwReserved;
    HANDLE hReserved;
    CRYPTOAPI_BLOB sEncodedIndirectData;
    CRYPTOAPI_BLOB sEncodedMemberInfo;
}CRYPTCATMEMBER, * PCRYPTCATMEMBER;

typedef struct _MS_ADDINFO_CATALOGMEMBER
{
    DWORD cbStruct;
    CRYPTCATSTORE* pStore;
    CRYPTCATMEMBER* pMember;
}MS_ADDINFO_CATALOGMEMBER, * PMS_ADDINFO_CATALOGMEMBER;

typedef struct SIP_SUBJECTINFO
{
    DWORD cbSize;
    GUID* pgSubjectType;
    HANDLE hFile;
    PWSTR pwsFileName;
    PWSTR pwsDisplayName;
    DWORD dwReserved1;
    DWORD dwIntVersion;
    QWORD* hProv;
    CRYPT_ALGORITHM_IDENTIFIER DigestAlgorithm;
    DWORD dwFlags;
    DWORD dwEncodingType;
    DWORD dwReserved2;
    DWORD fdwCAPISettings;
    DWORD fdwSecuritySettings;
    DWORD dwIndex;
    DWORD dwUnionChoice;
    union
    {
        MS_ADDINFO_FLAT* psFlat;
        MS_ADDINFO_CATALOGMEMBER* psCatMember;
        MS_ADDINFO_BLOB* psBlob;
    };
    PVOID pClientData;
}SIP_SUBJECTINFO, * PSIP_SUBJECTINFO;

typedef BOOL(*pCryptSIPCreateIndirectData)(SIP_SUBJECTINFO* pSubjectInfo, DWORD* pcbIndirectData, SIP_INDIRECT_DATA* pIndirectData);

typedef BOOL(*pCryptSIPGetSignedDataMsg)(SIP_SUBJECTINFO* pSubjectInfo, DWORD* pdwEncodingType, DWORD dwIndex, DWORD* pcbSignedDataMsg, UCHAR* pbSignedDataMsg);

typedef BOOL(*pCryptSIPPutSignedDataMsg)(SIP_SUBJECTINFO* pSubjectInfo, DWORD dwEncodingType, DWORD* pdwIndex, DWORD cbSignedDataMsg, UCHAR* pbSignedDataMsg);

typedef BOOL(*pCryptSIPRemoveSignedDataMsg)(SIP_SUBJECTINFO* pSubjectInfo, DWORD dwIndex);

typedef BOOL(*pCryptSIPVerifyIndirectData)(SIP_SUBJECTINFO* pSubjectInfo, SIP_INDIRECT_DATA* pIndirectData);

typedef struct _SIP_DISPATCH_INFO
{
    DWORD cbSize;
    HANDLE hSIP;
    pCryptSIPGetSignedDataMsg pfGet;
    pCryptSIPPutSignedDataMsg pfPut;
    pCryptSIPCreateIndirectData pfCreate;
    pCryptSIPVerifyIndirectData pfVerify;
    pCryptSIPRemoveSignedDataMsg pfRemove;
}SIP_DISPATCH_INFO, * PSIP_DISPATCH_INFO;

typedef struct _PROVDATA_SIP
{
    DWORD cbStruct;
    GUID gSubject;
    SIP_DISPATCH_INFO* pSip;
    SIP_DISPATCH_INFO* pCATSip;
    SIP_SUBJECTINFO* psSipSubjectInfo;
    SIP_SUBJECTINFO* psSipCATSubjectInfo;
    SIP_INDIRECT_DATA* psIndirectData;
}PROVDATA_SIP, * PPROVDATA_SIP;

typedef struct _CERT_USAGE_MATCH
{
    DWORD dwType;
    CTL_USAGE Usage;
}CERT_USAGE_MATCH, * PCERT_USAGE_MATCH;

typedef struct _CRYPT_PROVIDER_DATA
{
    DWORD cbStruct;
    WINTRUST_DATA* pWintrustData;
    LONG fOpenedFile;
    struct HWND__* hWndParent;
    GUID* pgActionID;
    QWORD hProv;
    DWORD dwError;
    DWORD dwRegSecuritySettings;
    DWORD dwRegPolicySettings;
    struct CRYPT_PROVIDER_FUNCTIONS* psPfns;
    DWORD cdwTrustStepErrors;
    DWORD* padwTrustStepErrors;
    DWORD chStores;
    PVOID* pahStores;
    DWORD dwEncoding;
    PVOID hMsg;
    DWORD csSigners;
    CRYPT_PROVIDER_SGNR* pasSigners;
    DWORD csProvPrivData;
    CRYPT_PROVIDER_PRIVDATA* pasProvPrivData;
    DWORD dwSubjectChoice;
    PROVDATA_SIP* pPDSip;
    char* pszUsageOID;
    LONG fRecallWithState;
    FILETIME sftSystemTime;
    char* pszCTLSignerUsageOID;
    DWORD dwProvFlags;
    DWORD dwFinalError;
    CERT_USAGE_MATCH* pRequestUsage;
    DWORD dwTrustPubSettings;
    DWORD dwUIStateFlags;
    CRYPT_PROVIDER_SIGSTATE* pSigState;
    WINTRUST_SIGNATURE_SETTINGS* pSigSettings;
}CRYPT_PROVIDER_DATA, * PCRYPT_PROVIDER_DATA;

typedef struct _CRYPT_PROVUI_FUNCS
{
    DWORD cbStruct;
    CRYPT_PROVUI_DATA* psUIData;
    LONG(*pfnOnMoreInfoClick)(struct HWND__*, CRYPT_PROVIDER_DATA*);
    LONG(*pfnOnMoreInfoClickDefault)(struct HWND__*, CRYPT_PROVIDER_DATA*);
    LONG(*pfnOnAdvancedClick)(struct HWND__*, CRYPT_PROVIDER_DATA*);
    LONG(*pfnOnAdvancedClickDefault)(struct HWND__*, CRYPT_PROVIDER_DATA*);
}CRYPT_PROVUI_FUNCS, * PCRYPT_PROVUI_FUNCS;

typedef struct _CRYPT_PROVIDER_FUNCTIONS
{
    DWORD cbStruct;
    PVOID(*pfnAlloc)(DWORD);
    void (*pfnFree)(PVOID);
    LONG(*pfnAddStore2Chain)(CRYPT_PROVIDER_DATA*, void*);
    LONG(*pfnAddSgnr2Chain)(CRYPT_PROVIDER_DATA*, LONG, DWORD, CRYPT_PROVIDER_SGNR*);
    LONG(*pfnAddCert2Chain)(CRYPT_PROVIDER_DATA*, DWORD, LONG, DWORD, CERT_CONTEXT const*);
    LONG(*pfnAddPrivData2Chain)(CRYPT_PROVIDER_DATA*, CRYPT_PROVIDER_PRIVDATA*);
    HRESULT(*pfnInitialize)(CRYPT_PROVIDER_DATA*);
    HRESULT(*pfnObjectTrust)(CRYPT_PROVIDER_DATA*);
    HRESULT(*pfnSignatureTrust)(CRYPT_PROVIDER_DATA*);
    HRESULT(*pfnCertificateTrust)(CRYPT_PROVIDER_DATA*);
    HRESULT(*pfnFinalPolicy)(CRYPT_PROVIDER_DATA*);
    LONG(*pfnCertCheckPolicy)(CRYPT_PROVIDER_DATA*, DWORD, LONG, DWORD);
    HRESULT(*pfnTestFinalPolicy)(CRYPT_PROVIDER_DATA*);
    CRYPT_PROVUI_FUNCS* psUIpfns;
    HRESULT(*pfnCleanupPolicy)(CRYPT_PROVIDER_DATA*);
}CRYPT_PROVIDER_FUNCTIONS, * PCRYPT_PROVIDER_FUNCTIONS;

typedef struct _CRYPT_PROVIDER_DEFUSAGE
{
    DWORD cbStruct;
    GUID gActionID;
    PVOID pDefPolicyCallbackData;
    PVOID pDefSIPClientData;
}CRYPT_PROVIDER_DEFUSAGE, * PCRYPT_PROVIDER_DEFUSAGE;

typedef struct _CRYPT_PROVIDER_REF
{
    DWORD dwInterface;
    USHORT* pszFunction;
    USHORT* pszProvider;
    DWORD cProperties;
    CRYPT_PROPERTY_REF** rgpProperties;
    CRYPT_IMAGE_REF* pUM;
    CRYPT_IMAGE_REF* pKM;
}CRYPT_PROVIDER_REF, * PCRYPT_PROVIDER_REF;

typedef struct _CRYPT_PROVIDER_REFS
{
    DWORD cProviders;
    CRYPT_PROVIDER_REF** rgpProviders;
}CRYPT_PROVIDER_REFS, * PCRYPT_PROVIDER_REFS;

typedef struct _CRYPT_PROVIDER_REG
{
    DWORD cAliases;
    USHORT** rgpszAliases;
    CRYPT_IMAGE_REG* pUM;
    CRYPT_IMAGE_REG* pKM;
}CRYPT_PROVIDER_REG, * PCRYPT_PROVIDER_REG;

typedef struct _CRYPT_PROVIDER_REGDEFUSAGE
{
    DWORD cbStruct;
    GUID* pgActionID;
    USHORT* pwszDllName;
    char* pwszLoadCallbackDataFunctionName;
    char* pwszFreeCallbackDataFunctionName;
}CRYPT_PROVIDER_REGDEFUSAGE, * PCRYPT_PROVIDER_REGDEFUSAGE;

typedef struct _CRYPT_PSOURCE_ALGORITHM
{
    char* pszObjId;
    CRYPTOAPI_BLOB EncodingParameters;
}CRYPT_PSOURCE_ALGORITHM, * PCRYPT_PSOURCE_ALGORITHM;

typedef struct _CRYPT_RC2_CBC_PARAMETERS
{
    DWORD dwVersion;
    LONG fIV;
    UCHAR rgbIV[0x8];
}CRYPT_RC2_CBC_PARAMETERS, * PCRYPT_RC2_CBC_PARAMETERS;

typedef struct _CRYPT_RC4_KEY_STATE
{
    UCHAR Key[0x10];
    UCHAR SBox[0x100];
    UCHAR i;
    UCHAR j;
}CRYPT_RC4_KEY_STATE, * PCRYPT_RC4_KEY_STATE;

typedef struct _CRYPT_TRUST_REG_ENTRY
{
    DWORD cbStruct;
    USHORT* pwszDLLName;
    USHORT* pwszFunctionName;
}CRYPT_TRUST_REG_ENTRY, * PCRYPT_TRUST_REG_ENTRY;

typedef struct _CRYPT_REGISTER_ACTIONID
{
    DWORD cbStruct;
    CRYPT_TRUST_REG_ENTRY sInitProvider;
    CRYPT_TRUST_REG_ENTRY sObjectProvider;
    CRYPT_TRUST_REG_ENTRY sSignatureProvider;
    CRYPT_TRUST_REG_ENTRY sCertificateProvider;
    CRYPT_TRUST_REG_ENTRY sCertificatePolicyProvider;
    CRYPT_TRUST_REG_ENTRY sFinalPolicyProvider;
    CRYPT_TRUST_REG_ENTRY sTestPolicyProvider;
    CRYPT_TRUST_REG_ENTRY sCleanupProvider;
}CRYPT_REGISTER_ACTIONID, * PCRYPT_REGISTER_ACTIONID;

typedef struct _CRYPT_RSAES_OAEP_PARAMETERS
{
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_MASK_GEN_ALGORITHM MaskGenAlgorithm;
    CRYPT_PSOURCE_ALGORITHM PSourceAlgorithm;
}CRYPT_RSAES_OAEP_PARAMETERS, * PCRYPT_RSAES_OAEP_PARAMETERS;

typedef struct _CRYPT_RSA_SSA_PSS_PARAMETERS
{
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_MASK_GEN_ALGORITHM MaskGenAlgorithm;
    DWORD dwSaltLength;
    DWORD dwTrailerField;
}CRYPT_RSA_SSA_PSS_PARAMETERS, * PCRYPT_RSA_SSA_PSS_PARAMETERS;

typedef struct _CRYPT_SEQUENCE_OF_ANY
{
    DWORD cValue;
    CRYPTOAPI_BLOB* rgValue;
}CRYPT_SEQUENCE_OF_ANY, * PCRYPT_SEQUENCE_OF_ANY;

typedef struct _CRYPT_SIGN_MESSAGE_PARA
{
    DWORD cbSize;
    DWORD dwMsgEncodingType;
    CERT_CONTEXT const* pSigningCert;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    PVOID pvHashAuxInfo;
    DWORD cMsgCert;
    CERT_CONTEXT const** rgpMsgCert;
    DWORD cMsgCrl;
    CRL_CONTEXT const** rgpMsgCrl;
    DWORD cAuthAttr;
    CRYPT_ATTRIBUTE* rgAuthAttr;
    DWORD cUnauthAttr;
    CRYPT_ATTRIBUTE* rgUnauthAttr;
    DWORD dwFlags;
    DWORD dwInnerContentType;
}CRYPT_SIGN_MESSAGE_PARA, * PCRYPT_SIGN_MESSAGE_PARA;

typedef struct _CRYPT_SMART_CARD_ROOT_INFO
{
    UCHAR rgbCardID[0x10];
    ROOT_INFO_LUID luid;
}CRYPT_SMART_CARD_ROOT_INFO, * PCRYPT_SMART_CARD_ROOT_INFO;

typedef struct _CRYPT_SMIME_CAPABILITY
{
    char* pszObjId;
    CRYPTOAPI_BLOB Parameters;
}CRYPT_SMIME_CAPABILITY, * PCRYPT_SMIME_CAPABILITY;

typedef struct _CRYPT_SMIME_CAPABILITIES
{
    DWORD cCapability;
    CRYPT_SMIME_CAPABILITY* rgCapability;
}CRYPT_SMIME_CAPABILITIES, * PCRYPT_SMIME_CAPABILITIES;


typedef struct _CRYPT_TIMESTAMP_ACCURACY
{
    DWORD dwSeconds;
    DWORD dwMillis;
    DWORD dwMicros;
}CRYPT_TIMESTAMP_ACCURACY, * PCRYPT_TIMESTAMP_ACCURACY;

typedef struct _CRYPT_TIMESTAMP_INFO
{
    DWORD dwVersion;
    char* pszTSAPolicyId;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPTOAPI_BLOB HashedMessage;
    CRYPTOAPI_BLOB SerialNumber;
    FILETIME ftTime;
    CRYPT_TIMESTAMP_ACCURACY* pvAccuracy;
    LONG fOrdering;
    CRYPTOAPI_BLOB Nonce;
    CRYPTOAPI_BLOB Tsa;
    DWORD cExtension;
    CERT_EXTENSION* rgExtension;
}CRYPT_TIMESTAMP_INFO, * PCRYPT_TIMESTAMP_INFO;

typedef struct _CRYPT_TIMESTAMP_CONTEXT
{
    DWORD cbEncoded;
    UCHAR* pbEncoded;
    CRYPT_TIMESTAMP_INFO* pTimeStamp;
}CRYPT_TIMESTAMP_CONTEXT, * PCRYPT_TIMESTAMP_CONTEXT;

typedef struct _CRYPT_TIMESTAMP_PARA
{
    char const* pszTSAPolicyId;
    LONG fRequestCerts;
    CRYPTOAPI_BLOB Nonce;
    DWORD cExtension;
    CERT_EXTENSION* rgExtension;
}CRYPT_TIMESTAMP_PARA, * PCRYPT_TIMESTAMP_PARA;

typedef struct _CRYPT_TIMESTAMP_REQUEST
{
    DWORD dwVersion;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPTOAPI_BLOB HashedMessage;
    char* pszTSAPolicyId;
    CRYPTOAPI_BLOB Nonce;
    LONG fCertReq;
    DWORD cExtension;
    CERT_EXTENSION* rgExtension;
}CRYPT_TIMESTAMP_REQUEST, * PCRYPT_TIMESTAMP_REQUEST;

typedef struct _CRYPT_TIMESTAMP_RESPONSE
{
    DWORD dwStatus;
    DWORD cFreeText;
    USHORT** rgFreeText;
    struct _CRYPT_BIT_BLOB FailureInfo;
    struct _CRYPTOAPI_BLOB ContentInfo;
}CRYPT_TIMESTAMP_RESPONSE, * PCRYPT_TIMESTAMP_RESPONSE;

typedef struct _CRYPT_TIME_STAMP_REQUEST_INFO
{
    char* pszTimeStampAlgorithm;
    char* pszContentType;
    CRYPTOAPI_BLOB Content;
    DWORD cAttribute;
    CRYPT_ATTRIBUTE* rgAttribute;
}CRYPT_TIME_STAMP_REQUEST_INFO, * PCRYPT_TIME_STAMP_REQUEST_INFO;

typedef struct _CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO
{
    CRYPTOAPI_BLOB CertSignHashCNGAlgPropData;
    CRYPTOAPI_BLOB CertIssuerPubKeyBitLengthPropData;
}CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO, * PCRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO;

typedef struct _CRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO
{
    DWORD cCNGHashAlgid;
    USHORT const** rgpwszCNGHashAlgid;
    DWORD dwWeakIndex;

}CRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO, * PCRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO;

typedef struct _CRYPT_VERIFY_MESSAGE_PARA
{
    DWORD cbSize;
    DWORD dwMsgAndCertEncodingType;
    QWORD hCryptProv;
    CERT_CONTEXT const* (*pfnGetSignerCertificate)(PVOID, DWORD, CERT_INFO*, PVOID);
    PVOID pvGetArg;
}CRYPT_VERIFY_MESSAGE_PARA, * PCRYPT_VERIFY_MESSAGE_PARA;

typedef struct _CRYPT_X942_OTHER_INFO
{
    char* pszContentEncryptionObjId;
    UCHAR rgbCounter[0x4];
    UCHAR rgbKeyLength[0x4];
    CRYPTOAPI_BLOB PubInfo;
}CRYPT_X942_OTHER_INFO, * PCRYPT_X942_OTHER_INFO;

typedef struct _NCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER
{
    DWORD magic;
    DWORD cbHeader;
    DWORD cbPublic;
    DWORD cbPrivate;
    DWORD cbName;
}NCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER, * PNCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER;

typedef struct _NCRYPTKEYNAME
{
    USHORT* pszName;
    USHORT* pszAlgid;
    DWORD dwLegacyKeySpec;
    DWORD dwFlags;
}NCRYPTKEYNAME, * PNCRYPTKEYNAME;

typedef struct _NCRYPTPROVIDERNAME
{
    USHORT* pszName;
    USHORT* pszComment;
}NCRYPTPROVIDERNAME, * PNCRYPTPROVIDERNAME;

typedef struct _NCRYPT_CIPHER_PADDING_INFO
{
    DWORD cbSize;
    DWORD dwFlags;
    UCHAR* pbIV;
    DWORD cbIV;
    UCHAR* pbOtherInfo;
    DWORD cbOtherInfo;
}NCRYPT_CIPHER_PADDING_INFO, * PNCRYPT_CIPHER_PADDING_INFO;

typedef struct _NCRYPT_EXPORTED_ISOLATED_KEY_HEADER
{
    DWORD Version;
    DWORD KeyUsage;
    union
    {
        DWORD PerBootKey;
        DWORD Reserved;
    } __bitfield8;
    DWORD cbAlgName;
    DWORD cbNonce;
    DWORD cbAuthTag;
    DWORD cbWrappingKey;
    DWORD cbIsolatedKey;
}NCRYPT_EXPORTED_ISOLATED_KEY_HEADER, * PNCRYPT_EXPORTED_ISOLATED_KEY_HEADER;

typedef struct _NCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE
{
    NCRYPT_EXPORTED_ISOLATED_KEY_HEADER Header;
}NCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE, * PNCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE;

typedef struct _NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES
{
    DWORD Version;
    DWORD Flags;
    DWORD cbPublicKeyBlob;
}NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES, * PNCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES;

typedef struct _NCRYPT_KEY_ATTEST_PADDING_INFO
{
    DWORD magic;
    UCHAR* pbKeyBlob;
    DWORD cbKeyBlob;
    UCHAR* pbKeyAuth;
    DWORD cbKeyAuth;
}NCRYPT_KEY_ATTEST_PADDING_INFO, * PNCRYPT_KEY_ATTEST_PADDING_INFO;

typedef struct _NCRYPT_KEY_BLOB_HEADER
{
    DWORD cbSize;
    DWORD dwMagic;
    DWORD cbAlgName;
    DWORD cbKeyData;
}NCRYPT_KEY_BLOB_HEADER, * PNCRYPT_KEY_BLOB_HEADER;

typedef struct _NCRYPT_PLATFORM_ATTEST_PADDING_INFO
{
    DWORD magic;
    DWORD pcrMask;
}NCRYPT_PLATFORM_ATTEST_PADDING_INFO, * PNCRYPT_PLATFORM_ATTEST_PADDING_INFO;

typedef struct _NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT
{
    DWORD Magic;
    DWORD Version;
    DWORD pcrAlg;
    DWORD cbSignature;
    DWORD cbQuote;
    DWORD cbPcrs;
}NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT, * PNCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT;

typedef struct _NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS
{
    DWORD Version;
    QWORD TrustletId;
    DWORD MinSvn;
    DWORD FlagsMask;
    DWORD FlagsExpected;
    union
    {
        DWORD AllowDebugging;
        DWORD Reserved;
    } __bitfield28;
}NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS, * PNCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS;

typedef struct _NCRYPT_VSM_KEY_ATTESTATION_STATEMENT
{
    DWORD Magic;
    DWORD Version;
    DWORD cbSignature;
    DWORD cbReport;
    DWORD cbAttributes;
}NCRYPT_VSM_KEY_ATTESTATION_STATEMENT, * PNCRYPT_VSM_KEY_ATTESTATION_STATEMENT;

typedef struct _NCRYPT_ALGORITHM_NAME
{
    PWSTR pszName;
    DWORD dwClass;
    DWORD dwAlgOperations;
    DWORD dwFlags;
}NCRYPT_ALGORITHM_NAME, * PNCRYPT_ALGORITHM_NAME;

typedef struct _NCRYPT_KEY_ACCESS_POLICY_BLOB
{
    DWORD dwVersion;
    DWORD dwPolicyFlags;
    DWORD cbUserSid;
    DWORD cbApplicationSid;
}NCRYPT_KEY_ACCESS_POLICY_BLOB, * PNCRYPT_KEY_ACCESS_POLICY_BLOB;

typedef struct _NCRYPT_PCP_HMAC_AUTH_SIGNATURE_INFO
{
    DWORD dwVersion;
    LONG iExpiration;
    UCHAR pabNonce[0x20];
    UCHAR pabPolicyRef[0x20];
    UCHAR pabHMAC[0x20];
}NCRYPT_PCP_HMAC_AUTH_SIGNATURE_INFO, * PNCRYPT_PCP_HMAC_AUTH_SIGNATURE_INFO;

typedef struct _NCRYPT_PCP_RAW_POLICYDIGEST
{
    DWORD dwVersion;
    DWORD cbDigest;
}NCRYPT_PCP_RAW_POLICYDIGEST, * PNCRYPT_PCP_RAW_POLICYDIGEST;

typedef struct _NCRYPT_PCP_TPM_FW_VERSION_INFO
{
    USHORT major1;
    USHORT major2;
    USHORT minor1;
    USHORT minor2;
}NCRYPT_PCP_TPM_FW_VERSION_INFO, * PNCRYPT_PCP_TPM_FW_VERSION_INFO;

typedef struct _NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT
{
    DWORD Magic;
    DWORD Version;
    DWORD HeaderSize;
    DWORD cbCertifyInfo;
    DWORD cbSignature;
    DWORD cbTpmPublic;
}NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT, * PNCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT;

typedef struct _NCRYPT_SUPPORTED_LENGTHS
{
    DWORD dwMinLength;
    DWORD dwMaxLength;
    DWORD dwIncrement;
    DWORD dwDefaultLength;
}NCRYPT_SUPPORTED_LENGTHS, * PNCRYPT_SUPPORTED_LENGTHS;

typedef struct _NCRYPT_UI_POLICY
{
    DWORD dwVersion;
    DWORD dwFlags;
    PWSTR const* pszCreationTitle;
    PWSTR const* pszFriendlyName;
    PWSTR const* pszDescription;
}NCRYPT_UI_POLICY, * PNCRYPT_UI_POLICY;

typedef struct _BOOT_AREA_INFO
{
    DWORD BootSectorCount;
    struct { LARGE_INTEGER Offset; } BootSectors[0x2];
}BOOT_AREA_INFO, * PBOOT_AREA_INFO;

typedef enum _BOOT_ENTROPY_SOURCE_ID // int32_t
{
    BootEntropySourceNone = 0x0,
    BootEntropySourceSeedfile = 0x1,
    BootEntropySourceExternal = 0x2,
    BootEntropySourceTpm = 0x3,
    BootEntropySourceRdrand = 0x4,
    BootEntropySourceTime = 0x5,
    BootEntropySourceAcpiOem0 = 0x6,
    BootEntropySourceUefi = 0x7,
    BootEntropySourceCng = 0x8,
    BootEntropySourceTcbTpm = 0x9,
    BootEntropySourceTcbRdrand = 0xa,
    BootMaxEntropySources = 0xa
}BOOT_ENTROPY_SOURCE_ID, * PBOOT_ENTROPY_SOURCE_ID;

typedef enum _BOOT_ENTROPY_SOURCE_RESULT_CODE // int32_t
{
    BootEntropySourceStructureUninitialized = 0x0,
    BootEntropySourceDisabledByPolicy = 0x1,
    BootEntropySourceNotPresent = 0x2,
    BootEntropySourceError = 0x3,
    BootEntropySourceSuccess = 0x4
}BOOT_ENTROPY_SOURCE_RESULT_CODE, * PBOOT_ENTROPY_SOURCE_RESULT_CODE;

typedef struct _BOOT_ENTROPY_SOURCE_NT_RESULT
{
    BOOT_ENTROPY_SOURCE_ID SourceId;
    QWORD Policy;
    BOOT_ENTROPY_SOURCE_RESULT_CODE ResultCode;
    DWORD ResultStatus;
    QWORD Time;
    DWORD EntropyLength;
    UCHAR EntropyData[0x40];

}BOOT_ENTROPY_SOURCE_NT_RESULT, * PBOOT_ENTROPY_SOURCE_NT_RESULT;

typedef struct _BOOT_ENTROPY_NT_RESULT
{
    DWORD maxEntropySources;
    BOOT_ENTROPY_SOURCE_NT_RESULT EntropySourceResult[0xa];
    UCHAR SeedBytesForCng[0x30];
}BOOT_ENTROPY_NT_RESULT, * PBOOT_ENTROPY_NT_RESULT;

typedef struct _BOOT_ENTRY
{
    DWORD Version;
    DWORD Length;
    DWORD Id;
    DWORD Attributes;
    DWORD FriendlyNameOffset;
    DWORD BootFilePathOffset;
    DWORD OsOptionsLength;
    UCHAR OsOptions[0x1];

}BOOT_ENTRY, * PBOOT_ENTRY;

typedef struct _BOOT_ENTRY_LIST
{
    DWORD NextEntryOffset;
    BOOT_ENTRY BootEntry;
}BOOT_ENTRY_LIST, * PBOOT_ENTRY_LIST;

typedef struct _BOOT_OPTIONS
{
    DWORD Version;
    DWORD Length;
    DWORD Timeout;
    DWORD CurrentBootEntryId;
    DWORD NextBootEntryId;
    USHORT HeadlessRedirection[0x1];//wchar16
}BOOT_OPTIONS, * PBOOT_OPTIONS;

//----------------------REACTOS PEB STRUCTURES----------------------//

typedef struct _LIST_ENTRY
{
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, * PLIST_ENTRY;

typedef struct LIST_ENTRY32
{
    DWORD Flink;
    DWORD Blink;
}LIST_ENTRY32, * PLIST_ENTRY32;

typedef struct _LIST_ENTRY64
{
    QWORD Flink;
    QWORD Blink;
}LIST_ENTRY64, * PLIST_ENTRY64;

typedef struct _PEB_LDR_DATA
{
    ULONG                  Length;
    BOOLEAN                Initialized;
    PVOID                  SsHandle;
    LIST_ENTRY             InLoadOrderModuleList;
    LIST_ENTRY             InMemoryOrderModuleList;
    LIST_ENTRY             InInitializationOrderModuleList;
    PVOID                  EntryInProgress;
    UCHAR                  ShutdownInProgress;
    PVOID                  ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_ENTRY
{
    LIST_ENTRY             InLoadOrderModuleList;
    LIST_ENTRY             InMemoryOrderModuleList;
    LIST_ENTRY             InInitializationOrderModuleList;
    PVOID                  BaseAddress;
    PVOID                  EntryPoint;
    ULONG                  SizeOfImage;
    UNICODE_STRING         FullDllName;
    UNICODE_STRING         BaseDllName;
    ULONG                  Flags;
    WORD                   LoadCount;
    WORD                   TlsIndex;
    LIST_ENTRY             HashLinks;
    ULONG                  TimeDateStamp;
    HANDLE                 ActivationContext;
    PVOID                  PatchInformation;
    LIST_ENTRY             ForwarderLinks;
    LIST_ENTRY             ServiceTagLinks;
    LIST_ENTRY             StaticLinks;
    PVOID                  ContextInformation;
    ULONG_PTR              OriginalBase;
    LARGE_INTEGER          LoadTime;
} LDR_DATA_ENTRY, * PLDR_DATA_ENTRY;//_LDR_MODULE

typedef struct _RTL_BITMAP
{
    ULONG  SizeOfBitMap;
    PULONG Buffer;
} RTL_BITMAP, * PRTL_BITMAP;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT              Flags;
    USHORT              Length;
    ULONG               TimeStamp;
    STRING DosPath;//UNICODE_STRING      DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR
{
    UNICODE_STRING     DosPath;
    PVOID              Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS_PEB
{
    ULONG                      AllocationSize;
    ULONG                      Size;
    ULONG                      Flags;
    ULONG                      DebugFlags;
    HANDLE                     ConsoleHandle;
    ULONG                      ConsoleFlags;
    HANDLE                     hStdInput;
    HANDLE                     hStdOutput;
    HANDLE                     hStdError;
    CURDIR                     CurrentDirectory;
    UNICODE_STRING             DllPath;
    UNICODE_STRING             ImagePathName;
    UNICODE_STRING             CommandLine;
    PWSTR                      Environment;
    ULONG                      dwX;
    ULONG                      dwY;
    ULONG                      dwXSize;
    ULONG                      dwYSize;
    ULONG                      dwXCountChars;
    ULONG                      dwYCountChars;
    ULONG                      dwFillAttribute;
    ULONG                      dwFlags;
    ULONG                      wShowWindow;
    UNICODE_STRING             WindowTitle;
    UNICODE_STRING             Desktop;
    UNICODE_STRING             ShellInfo;
    UNICODE_STRING             RuntimeInfo;
    RTL_DRIVE_LETTER_CURDIR    DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS_PEB, * PRTL_USER_PROCESS_PARAMETERS_PEB;

typedef struct _RTL_MODULE_BASIC_INFO
{
    PVOID ImageBase;
}RTL_MODULE_BASIC_INFO, * PRTL_MODULE_BASIC_INFO;

typedef struct _RTL_MODULE_EXTENDED_INFO
{
    RTL_MODULE_BASIC_INFO BasicInfo;
    DWORD ImageSize;
    USHORT FileNameOffset;
    UCHAR FullPathName[0x100];
}RTL_MODULE_EXTENDED_INFO, * PRTL_MODULE_EXTENDED_INFO;

typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
    WORD                               Type;
    WORD                               CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION* CriticalSection;
    LIST_ENTRY                         ProcessLocksList;
    DWORD                              EntryCount;
    DWORD                              ContentionCount;
    DWORD                              Flags;
    WORD                               CreatorBackTraceIndexHigh;
    WORD                               Identifier;
} RTL_CRITICAL_SECTION_DEBUG, * PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, * PRTL_RESOURCE_DEBUG;

typedef struct _RTL_CRITICAL_SECTION
{
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
    /*    struct RTL_CRITICAL_SECTION_DEBUG* DebugInfo;
    int32_t LockCount;
    int32_t RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    uint64_t* SpinCount;*/
} RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION32
{
    DWORD DebugInfo;  //PRTL_CRITICAL_SECTION_DEBUG32
    LONG LockCount;
    LONG RecursionCount;
    DWORD OwningThread;
    DWORD LockSemaphore;
    DWORD SpinCount;
}RTL_CRITICAL_SECTION32, * PRTL_CRITICAL_SECTION32;

typedef struct _RTL_CRITICAL_SECTION64
{
    QWORD DebugInfo; //PRTL_CRITICAL_SECTION_DEBUG64
    LONG LockCount;
    LONG RecursionCount;
    QWORD OwningThread;
    QWORD LockSemaphore;
    QWORD SpinCount;
}RTL_CRITICAL_SECTION64, * PRTL_CRITICAL_SECTION64;

typedef struct _RTL_CRITICAL_SECTION_DEBUG32
{
    WORD Type;
    WORD CreatorBackTraceIndex;
    DWORD CriticalSection;
    LIST_ENTRY32 ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Spare[0x2];
}RTL_CRITICAL_SECTION_DEBUG32, * PRTL_CRITICAL_SECTION_DEBUG32;

typedef struct _RTL_CRITICAL_SECTION_DEBUG64
{
    WORD Type;
    WORD CreatorBackTraceIndex;
    QWORD CriticalSection;
    LIST_ENTRY64 ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Spare[0x2];
}RTL_CRITICAL_SECTION_DEBUG64, * PRTL_CRITICAL_SECTION_DEBUG64;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    DWORD ImageSize;
    DWORD Flags;
    WORD LoadOrderIndex;
    WORD InitOrderIndex;
    WORD LoadCount;
    WORD OffsetToFileName;
    UCHAR FullPathName[0x100];
}RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    DWORD NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[0x1];
}RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
    WORD NextOffset;
    RTL_PROCESS_MODULE_INFORMATION BaseInfo;
    DWORD ImageChecksum;
    DWORD TimeDateStamp;
    PVOID DefaultBase;
}RTL_PROCESS_MODULE_INFORMATION_EX, * PRTL_PROCESS_MODULE_INFORMATION_EX;

typedef struct _RTL_PROCESS_BACKTRACE_INFORMATION
{
    char* SymbolicBackTrace;
    DWORD TraceCount;
    WORD Index;
    WORD Depth;
    PVOID BackTrace[0x20];
}RTL_PROCESS_BACKTRACE_INFORMATION, * PRTL_PROCESS_BACKTRACE_INFORMATION;

typedef struct _RTL_PROCESS_BACKTRACES
{
    QWORD CommittedMemory;
    QWORD ReservedMemory;
    DWORD NumberOfBackTraceLookups;
    DWORD NumberOfBackTraces;
    RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[0x1];
}RTL_PROCESS_BACKTRACES, * PRTL_PROCESS_BACKTRACES;

typedef struct _RTL_HEAP_TAG
{
    DWORD NumberOfAllocations;
    DWORD NumberOfFrees;
    QWORD BytesAllocated;
    WORD TagIndex;
    WORD CreatorBackTraceIndex;
    USHORT TagName[0x18];
}RTL_HEAP_TAG, * PRTL_HEAP_TAG;

typedef struct _RTL_HEAP_ENTRY
{
    QWORD Size;
    WORD Flags;
    WORD AllocatorBackTraceIndex;
    union
    {
        struct
        {
            QWORD Settable;
            DWORD Tag;

        } s1;
        struct
        {
            QWORD CommittedSize;
            void* FirstBlock;
        } s2;
    } u;
}RTL_HEAP_ENTRY, * PRTL_HEAP_ENTRY;

typedef struct _RTL_HEAP_INFORMATION
{
    PVOID BaseAddress;
    DWORD Flags;
    WORD EntryOverhead;
    WORD CreatorBackTraceIndex;
    QWORD BytesAllocated;
    QWORD BytesCommitted;
    DWORD NumberOfTags;
    DWORD NumberOfEntries;
    DWORD NumberOfPseudoTags;
    DWORD PseudoTagGranularity;
    DWORD Reserved[0x5];
    RTL_HEAP_TAG* Tags;
    RTL_HEAP_ENTRY* Entries;
}RTL_HEAP_INFORMATION, * PRTL_HEAP_INFORMATION;

typedef struct _RTL_PROCESS_HEAPS
{
    DWORD NumberOfHeaps;
    RTL_HEAP_INFORMATION Heaps[0x1];
}RTL_PROCESS_HEAPS, * PRTL_PROCESS_HEAPS;

typedef struct _RTL_PROCESS_LOCK_INFORMATION
{
    PVOID Address;
    WORD Type;
    WORD CreatorBackTraceIndex;
    PVOID OwningThread;
    LONG LockCount;
    DWORD ContentionCount;
    DWORD EntryCount;
    LONG RecursionCount;
    DWORD NumberOfWaitingShared;
    DWORD NumberOfWaitingExclusive;
}RTL_PROCESS_LOCK_INFORMATION, * PRTL_PROCESS_LOCK_INFORMATION;

typedef struct _RTL_PROCESS_LOCKS
{
    DWORD NumberOfLocks;
    RTL_PROCESS_LOCK_INFORMATION Locks[0x1];
}RTL_PROCESS_LOCKS, * PRTL_PROCESS_LOCKS;

typedef struct _RTL_PROCESS_VERIFIER_OPTIONS
{
    DWORD SizeStruct;
    DWORD Option;
    UCHAR OptionData[0x1];
}RTL_PROCESS_VERIFIER_OPTIONS, * PRTL_PROCESS_VERIFIER_OPTIONS;

typedef struct _RTL_DEBUG_INFORMATION
{
    PVOID SectionHandleClient;
    PVOID ViewBaseClient;
    PVOID ViewBaseTarget;
    QWORD ViewBaseDelta;
    PVOID EventPairClient;
    PVOID EventPairTarget;
    PVOID TargetProcessId;
    PVOID TargetThreadHandle;
    DWORD Flags;
    QWORD OffsetFree;
    QWORD CommitSize;
    QWORD ViewSize;
    union
    {
        RTL_PROCESS_MODULES* Modules;
        RTL_PROCESS_MODULE_INFORMATION_EX* ModulesEx;
    } __inner12;
    RTL_PROCESS_BACKTRACES* BackTraces;
    RTL_PROCESS_HEAPS* Heaps;
    RTL_PROCESS_LOCKS* Locks;
    PVOID SpecificHeap;
    PVOID TargetProcessHandle;
    RTL_PROCESS_VERIFIER_OPTIONS* VerifierOptions;
    PVOID ProcessHeap;
    PVOID CriticalSectionHandle;
    PVOID CriticalSectionOwnerThread;
    PVOID Reserved[0x4];
}RTL_DEBUG_INFORMATION, * PRTL_DEBUG_INFORMATION;

typedef struct _RTL_DEBUG_INFORMATION32
{
    DWORD SectionHandleClient;
    DWORD ViewBaseClient;
    DWORD ViewBaseTarget;
    DWORD ViewBaseDelta;
    DWORD EventPairClient;
    DWORD EventPairTarget;
    DWORD TargetProcessId;
    DWORD TargetThreadHandle;
    DWORD Flags;
    DWORD OffsetFree;
    DWORD CommitSize;
    DWORD ViewSize;
    union
    {
        DWORD Modules;
        DWORD ModulesEx;
    } __inner12;
    DWORD BackTraces;
    DWORD Heaps;
    DWORD Locks;
    DWORD SpecificHeap;
    DWORD TargetProcessHandle;
    DWORD VerifierOptions;
    DWORD ProcessHeap;
    DWORD CriticalSectionHandle;
    DWORD CriticalSectionOwnerThread;
    DWORD Reserved[0x4];
}RTL_DEBUG_INFORMATION32, * PRTL_DEBUG_INFORMATION32;

typedef struct _RTL_QUERY_DEBUG_INFORMATION_INFO
{
    DWORD UniqueProcessId;
    DWORD Flags;
    QWORD Buffer;
}RTL_QUERY_DEBUG_INFORMATION_INFO, * PRTL_QUERY_DEBUG_INFORMATION_INFO;

typedef struct _RTL_PROTECTED_ACCESS
{
    DWORD DominateMask;
    DWORD DeniedProcessAccess;
    DWORD DeniedThreadAccess;
}RTL_PROTECTED_ACCESS, * PRTL_PROTECTED_ACCESS;

typedef union _RTL_ELEVATION_FLAGS
{
    DWORD Flags;
    DWORD ElevationEnabled;
    DWORD VirtualizationEnabled;
    DWORD InstallerDetectEnabled;
    DWORD ReservedBits;
}RTL_ELEVATION_FLAGS, * PRTL_ELEVATION_FLAGS;

typedef enum _RUNLEVEL // int32_t
{
    RUNLEVEL_LUA = 0x0,
    RUNLEVEL_HIGHEST = 0x1,
    RUNLEVEL_ADMIN = 0x2,
    RUNLEVEL_MAX_NON_UIA = 0x3,
    RUNLEVEL_LUA_UIA = 0x10,
    RUNLEVEL_HIGHEST_UIA = 0x11,
    RUNLEVEL_ADMIN_UIA = 0x12,
    RUNLEVEL_MAX = 0x13
}RUNLEVEL, * PRUNLEVEL;

typedef struct _PEB
{                                                                 /* win32/win64 */
    BOOLEAN                        InheritedAddressSpace;             /* 000/000 */
    BOOLEAN                        ReadImageFileExecOptions;          /* 001/001 */
    BOOLEAN                        BeingDebugged;                     /* 002/002 */
    BOOLEAN                        SpareBool;                         /* 003/003 */
    HANDLE                         Mutant;                            /* 004/008 */
    PVOID                          ImageBaseAddress;                  /* 008/010 */
    PPEB_LDR_DATA                  LdrData;
    RTL_USER_PROCESS_PARAMETERS_PEB* ProcessParameters;               /* 010/020 */
    PVOID                          SubSystemData;                     /* 014/028 */
    HANDLE                         ProcessHeap;                       /* 018/030 */
    PRTL_CRITICAL_SECTION          FastPebLock;                       /* 01c/038 */
    PVOID /*PPEBLOCKROUTINE*/      FastPebLockRoutine;                /* 020/040 */
    PVOID /*PPEBLOCKROUTINE*/      FastPebUnlockRoutine;              /* 024/048 */
    ULONG                          EnvironmentUpdateCount;            /* 028/050 */
    PVOID                          KernelCallbackTable;               /* 02c/058 */
    ULONG                          Reserved[2];                       /* 030/060 */
    PVOID /*PPEB_FREE_BLOCK*/      FreeList;                          /* 038/068 */
    ULONG                          TlsExpansionCounter;               /* 03c/070 */
    PRTL_BITMAP                    TlsBitmap;                         /* 040/078 */
    ULONG                          TlsBitmapBits[2];                  /* 044/080 */
    PVOID                          ReadOnlySharedMemoryBase;          /* 04c/088 */
    PVOID                          ReadOnlySharedMemoryHeap;          /* 050/090 */
    PVOID* ReadOnlyStaticServerData;          /* 054/098 */
    PVOID                          AnsiCodePageData;                  /* 058/0a0 */
    PVOID                          OemCodePageData;                   /* 05c/0a8 */
    PVOID                          UnicodeCaseTableData;              /* 060/0b0 */
    ULONG                          NumberOfProcessors;                /* 064/0b8 */
    ULONG                          NtGlobalFlag;                      /* 068/0bc */
    LARGE_INTEGER                  CriticalSectionTimeout;            /* 070/0c0 */
    ULONG_PTR                      HeapSegmentReserve;                /* 078/0c8 */
    ULONG_PTR                      HeapSegmentCommit;                 /* 07c/0d0 */
    ULONG_PTR                      HeapDeCommitTotalFreeThreshold;    /* 080/0d8 */
    ULONG_PTR                      HeapDeCommitFreeBlockThreshold;    /* 084/0e0 */
    ULONG                          NumberOfHeaps;                     /* 088/0e8 */
    ULONG                          MaximumNumberOfHeaps;              /* 08c/0ec */
    PVOID* ProcessHeaps;                      /* 090/0f0 */
    PVOID                          GdiSharedHandleTable;              /* 094/0f8 */
    PVOID                          ProcessStarterHelper;              /* 098/100 */
    PVOID                          GdiDCAttributeList;                /* 09c/108 */
    PVOID                          LoaderLock;                        /* 0a0/110 */
    ULONG                          OSMajorVersion;                    /* 0a4/118 */
    ULONG                          OSMinorVersion;                    /* 0a8/11c */
    ULONG                          OSBuildNumber;                     /* 0ac/120 */
    ULONG                          OSPlatformId;                      /* 0b0/124 */
    ULONG                          ImageSubSystem;                    /* 0b4/128 */
    ULONG                          ImageSubSystemMajorVersion;        /* 0b8/12c */
    ULONG                          ImageSubSystemMinorVersion;        /* 0bc/130 */
    ULONG                          ImageProcessAffinityMask;          /* 0c0/134 */
    HANDLE                         GdiHandleBuffer[28];               /* 0c4/138 */
    ULONG                          unknown[6];                        /* 134/218 */
    PVOID                          PostProcessInitRoutine;            /* 14c/230 */
    PRTL_BITMAP                    TlsExpansionBitmap;                /* 150/238 */
    ULONG                          TlsExpansionBitmapBits[32];        /* 154/240 */
    ULONG                          SessionId;                         /* 1d4/2c0 */
    ULARGE_INTEGER                 AppCompatFlags;                    /* 1d8/2c8 */
    ULARGE_INTEGER                 AppCompatFlagsUser;                /* 1e0/2d0 */
    PVOID                          ShimData;                          /* 1e8/2d8 */
    PVOID                          AppCompatInfo;                     /* 1ec/2e0 */
    UNICODE_STRING                 CSDVersion;                        /* 1f0/2e8 */
    PVOID                          ActivationContextData;             /* 1f8/2f8 */
    PVOID                          ProcessAssemblyStorageMap;         /* 1fc/300 */
    PVOID                          SystemDefaultActivationData;       /* 200/308 */
    PVOID                          SystemAssemblyStorageMap;          /* 204/310 */
    ULONG_PTR                      MinimumStackCommit;                /* 208/318 */
    PVOID* FlsCallback;                       /* 20c/320 */
    LIST_ENTRY                     FlsListHead;                       /* 210/328 */
    PRTL_BITMAP                    FlsBitmap;                         /* 218/338 */
    ULONG                          FlsBitmapBits[4];                  /* 21c/340 */
} PEB, * PPEB;

typedef union _SLIST_HEADER
{
    struct
    {
        QWORD Alignment;
        QWORD Region;
    } __inner0;
    struct
    {
        union
        {
            QWORD Depth;
            QWORD Sequence;
        } __bitfield0;
        union
        {
            QWORD Reserved;
            QWORD NextEntry;
        } __bitfield8;
    } HeaderX64;
}SLIST_HEADER, * PSLIST_HEADER;

typedef struct _LEAP_SECOND_DATA
{
    UCHAR Enabled;
    DWORD Count;
    LARGE_INTEGER Data[0x1];
}LEAP_SECOND_DATA, * PLEAP_SECOND_DATA;

typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    union
    {
        UCHAR BitField;
        union
        {
            UCHAR ImageUsesLargePages;
            UCHAR IsProtectedProcess;
            UCHAR IsImageDynamicallyRelocated;
            UCHAR SkipPatchingUser32Forwarders;
            UCHAR IsPackagedProcess;
            UCHAR IsAppContainer;
            UCHAR IsProtectedProcessLight;
            UCHAR IsLongPathAwareProcess;
        } __bitfield3;
    } __inner3;
    UCHAR Padding0[0x4];
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PEB_LDR_DATA* Ldr;
    RTL_USER_PROCESS_PARAMETERS_PEB* ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    RTL_CRITICAL_SECTION* FastPebLock;
    SLIST_HEADER* AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        DWORD CrossProcessFlags;
        union
        {
            DWORD ProcessInJob;
            DWORD ProcessInitializing;
            DWORD ProcessUsingVEH;
            DWORD ProcessUsingVCH;
            DWORD ProcessUsingFTH;
            DWORD ProcessPreviouslyThrottled;
            DWORD ProcessCurrentlyThrottled;
            DWORD ProcessImagesHotPatched;
            DWORD ReservedBits0;
        } __bitfield80;
    } __inner14;
    UCHAR Padding1[0x4];
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    } __inner16;
    DWORD SystemReserved;
    DWORD AtlThunkSListPtr32;
    PVOID ApiSetMap;
    DWORD TlsExpansionCounter;
    UCHAR Padding2[0x4];
    PVOID TlsBitmap;
    DWORD TlsBitmapBits[0x2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    DWORD NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    QWORD HeapSegmentReserve;
    QWORD HeapSegmentCommit;
    QWORD HeapDeCommitTotalFreeThreshold;
    QWORD HeapDeCommitFreeBlockThreshold;
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    DWORD GdiDCAttributeList;
    UCHAR Padding3[0x4];
    RTL_CRITICAL_SECTION* LoaderLock;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;
    DWORD ImageSubsystemMinorVersion;
    UCHAR Padding4[0x4];
    QWORD ActiveProcessAffinityMask;
    DWORD GdiHandleBuffer[0x3c];
    void (*PostProcessInitRoutine)();
    PVOID TlsExpansionBitmap;
    DWORD TlsExpansionBitmapBits[0x20];
    DWORD SessionId;
    UCHAR Padding5[0x4];
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;
    PVOID ActivationContextData; //ACTIVATION_CONTEXT_DATA*
    PVOID ProcessAssemblyStorageMap; //ASSEMBLY_STORAGE_MAP*
    PVOID SystemDefaultActivationContextData;//ACTIVATION_CONTEXT_DATA
    PVOID SystemAssemblyStorageMap;//ASSEMBLY_STORAGE_MAP*
    QWORD MinimumStackCommit;
    PVOID SparePointers[0x4];
    DWORD SpareUlongs[0x5];
    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pUnused;
    PVOID pImageHeaderHash;
    union
    {
        DWORD TracingFlags;
        union
        {
            DWORD HeapTracingEnabled;
            DWORD CritSecTracingEnabled;
            DWORD LibLoaderTracingEnabled;
            DWORD SpareTracingBits;
        } __bitfield888;
    } __inner77;
    UCHAR Padding6[0x4];
    QWORD CsrServerReadOnlySharedMemoryBase;
    QWORD TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[0x80];
    PVOID TelemetryCoverageHeader;
    DWORD CloudFileFlags;
    DWORD CloudFileDiagFlags;
    char PlaceholderCompatibilityMode;
    char PlaceholderCompatibilityModeReserved[0x7];
    LEAP_SECOND_DATA* LeapSecondData;
    union
    {
        DWORD LeapSecondFlags;
        union
        {
            DWORD SixtySecondEnabled;
            DWORD Reserved;
        } __bitfield1984;
    } __inner89;
    DWORD NtGlobalFlag2;
}PEB64, * PPEB64;

typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    union
    {
        UCHAR BitField;
        union
        {
            UCHAR ImageUsesLargePages;
            UCHAR IsProtectedProcess;
            UCHAR IsImageDynamicallyRelocated;
            UCHAR SkipPatchingUser32Forwarders;
            UCHAR IsPackagedProcess;
            UCHAR IsAppContainer;
            UCHAR IsProtectedProcessLight;
            UCHAR IsLongPathAwareProcess;
        } __bitfield3;
    } __inner3;
    DWORD Mutant;
    DWORD ImageBaseAddress;
    DWORD Ldr;
    DWORD ProcessParameters;
    DWORD SubSystemData;
    DWORD ProcessHeap;
    DWORD FastPebLock;
    DWORD AtlThunkSListPtr;
    DWORD IFEOKey;
    union
    {
        DWORD CrossProcessFlags;
        union
        {
            DWORD ProcessInJob;
            DWORD ProcessInitializing;
            DWORD ProcessUsingVEH;
            DWORD ProcessUsingVCH;
            DWORD ProcessUsingFTH;
            DWORD ProcessPreviouslyThrottled;
            DWORD ProcessCurrentlyThrottled;
            DWORD ProcessImagesHotPatched;
            DWORD ReservedBits0;
        } __bitfield40;
    } __inner13;
    union
    {
        DWORD KernelCallbackTable;
        DWORD UserSharedInfoPtr;
    } __inner14;
    DWORD SystemReserved;
    DWORD AtlThunkSListPtr32;
    DWORD ApiSetMap;
    DWORD TlsExpansionCounter;
    DWORD TlsBitmap;
    DWORD TlsBitmapBits[0x2];
    DWORD ReadOnlySharedMemoryBase;
    DWORD SharedData;
    DWORD ReadOnlyStaticServerData;
    DWORD AnsiCodePageData;
    DWORD OemCodePageData;
    DWORD UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    DWORD NtGlobalFlag;

    LARGE_INTEGER CriticalSectionTimeout;
    DWORD HeapSegmentReserve;
    DWORD HeapSegmentCommit;
    DWORD HeapDeCommitTotalFreeThreshold;
    DWORD HeapDeCommitFreeBlockThreshold;
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    DWORD ProcessHeaps;
    DWORD GdiSharedHandleTable;
    DWORD ProcessStarterHelper;
    DWORD GdiDCAttributeList;
    DWORD LoaderLock;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;
    DWORD ImageSubsystemMinorVersion;
    DWORD ActiveProcessAffinityMask;
    DWORD GdiHandleBuffer[0x22];
    DWORD PostProcessInitRoutine;
    DWORD TlsExpansionBitmap;
    DWORD TlsExpansionBitmapBits[0x20];
    DWORD SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    DWORD pShimData;
    DWORD AppCompatInfo;
    STRING32 CSDVersion;
    DWORD ActivationContextData;
    DWORD ProcessAssemblyStorageMap;
    DWORD SystemDefaultActivationContextData;
    DWORD SystemAssemblyStorageMap;
    DWORD MinimumStackCommit;
    DWORD SparePointers[0x4];
    DWORD SpareUlongs[0x5];
    DWORD WerRegistrationData;
    DWORD WerShipAssertPtr;
    DWORD pUnused;
    DWORD pImageHeaderHash;
    union
    {
        DWORD TracingFlags;
        union
        {
            DWORD HeapTracingEnabled;
            DWORD CritSecTracingEnabled;
            DWORD LibLoaderTracingEnabled;
            DWORD SpareTracingBits;
        } __bitfield576;
    } __inner71;
    QWORD CsrServerReadOnlySharedMemoryBase;
    DWORD TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    DWORD WaitOnAddressHashTable[0x80];
    DWORD TelemetryCoverageHeader;
    DWORD CloudFileFlags;
    DWORD CloudFileDiagFlags;
    char PlaceholderCompatibilityMode;
    char PlaceholderCompatibilityModeReserved[0x7];
    DWORD LeapSecondData;
    union
    {
        DWORD LeapSecondFlags;
        union
        {
            DWORD SixtySecondEnabled;
            DWORD Reserved;
        } __bitfield1140;
    } __inner82;
    DWORD NtGlobalFlag2;
}PEB32, * PPEB32;

typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            struct _RTL_BALANCED_NODE* Left;                                //0x0
            struct _RTL_BALANCED_NODE* Right;                               //0x4
        };
    };
    union
    {
        struct
        {
            UCHAR Red : 1;                                                    //0x8
            UCHAR Balance : 2;                                                //0x8
        };
        ULONG ParentValue;                                                  //0x8
    };
}RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonEnclavePrimary, // since REDSTONE3
    LoadReasonEnclaveDependency,
    LoadReasonPatchImage, // since WIN11
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef enum _LDR_HOT_PATCH_STATE
{
    LdrHotPatchBaseImage,
    LdrHotPatchNotApplied,
    LdrHotPatchAppliedReverse,
    LdrHotPatchAppliedForward,
    LdrHotPatchFailedToPatch,
    LdrHotPatchStateMax,
} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;

typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;
// LDR_DATA_TABLE_ENTRY->Flags
#define LDRP_PACKAGED_BINARY 0x00000001
#define LDRP_MARKED_FOR_REMOVAL 0x00000002
#define LDRP_IMAGE_DLL 0x00000004
#define LDRP_LOAD_NOTIFICATIONS_SENT 0x00000008
#define LDRP_TELEMETRY_ENTRY_PROCESSED 0x00000010
#define LDRP_PROCESS_STATIC_IMPORT 0x00000020
#define LDRP_IN_LEGACY_LISTS 0x00000040
#define LDRP_IN_INDEXES 0x00000080
#define LDRP_SHIM_DLL 0x00000100
#define LDRP_IN_EXCEPTION_TABLE 0x00000200
#define LDRP_LOAD_IN_PROGRESS 0x00001000
#define LDRP_LOAD_CONFIG_PROCESSED 0x00002000
#define LDRP_ENTRY_PROCESSED 0x00004000
#define LDRP_PROTECT_DELAY_LOAD 0x00008000
#define LDRP_DONT_CALL_FOR_THREADS 0x00040000
#define LDRP_PROCESS_ATTACH_CALLED 0x00080000
#define LDRP_PROCESS_ATTACH_FAILED 0x00100000
#define LDRP_COR_DEFERRED_VALIDATE 0x00200000
#define LDRP_COR_IMAGE 0x00400000
#define LDRP_DONT_RELOCATE 0x00800000
#define LDRP_COR_IL_ONLY 0x01000000
#define LDRP_CHPE_IMAGE 0x02000000
#define LDRP_CHPE_EMULATOR_IMAGE 0x04000000
#define LDRP_REDIRECTED 0x10000000
#define LDRP_COMPAT_DATABASE_PROCESSED 0x80000000

typedef struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY* Next;
} SINGLE_LIST_ENTRY, * PSINGLE_LIST_ENTRY;

typedef BOOLEAN(NTAPI* PLDR_INIT_ROUTINE)(
    PVOID DllHandle,                    //_In_
    ULONG Reason,                       //_In_
    PVOID Context                       //_In_opt_
    );

typedef struct _LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef struct _LDR_SERVICE_TAG_RECORD
{
    struct _LDR_SERVICE_TAG_RECORD* Next;//struct _LDR_SERVICE_TAG_RECORD*
    DWORD ServiceTag;
}LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount;
    ULONG LowestLink;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PLDR_INIT_ROUTINE EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ChpeEmulatorImage : 1;
            ULONG ReservedFlags5 : 1;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID Lock; // RtlAcquireSRWLockExclusive
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT* LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason; // since WIN8
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount; // since WIN10
    ULONG DependentLoadFlags;
    UCHAR SigningLevel; // since REDSTONE2
    ULONG CheckSum; // since 22H1
    PVOID ActivePatchImageBase;
    LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    DWORD DllBase;
    DWORD EntryPoint;
    DWORD SizeOfImage;
    STRING32 FullDllName;
    STRING32 BaseDllName;
    DWORD Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY32 HashLinks;
        struct
        {
            DWORD SectionPointer;
            DWORD CheckSum;
        } __inner1;
    } __inner11;
    union
    {
        DWORD TimeDateStamp;
        DWORD LoadedImports;
    } __inner12;
}LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderLinks;
    LIST_ENTRY64 InInitializationOrderLinks;
    QWORD DllBase;
    QWORD EntryPoint;
    DWORD SizeOfImage;

    STRING64 FullDllName;
    STRING64 BaseDllName;
    DWORD Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY64 HashLinks;
        struct
        {
            QWORD SectionPointer;
            DWORD CheckSum;
        } __inner1;
    } __inner11;
    union
    {
        DWORD TimeDateStamp;
        QWORD LoadedImports;
    } __inner12;
}LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA
{
    DWORD Flags;
    UNICODE_STRING const* FullDllName;
    UNICODE_STRING const* BaseDllName;
    PVOID DllBase;
    DWORD SizeOfImage;
}LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA
{
    DWORD Flags;
    UNICODE_STRING const* FullDllName;
    UNICODE_STRING const* BaseDllName;
    PVOID DllBase;
    DWORD SizeOfImage;
}LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA
{
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
}LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

typedef struct _LDR_ENUM_RESOURCE_ENTRY
{
    union { QWORD NameOrId; struct IMAGE_RESOURCE_DIRECTORY_STRING* Name; } Path[0x3];
    PVOID Data;
    DWORD Size;
    DWORD Reserved;
}LDR_ENUM_RESOURCE_ENTRY, * PLDR_ENUM_RESOURCE_ENTRY;

typedef struct _LDR_FAILURE_DATA
{
    LONG Status;  //NTSTATUS ?
    USHORT ImageName[0x20];
    USHORT AdditionalInfo[0x20];
}LDR_FAILURE_DATA, * PLDR_FAILURE_DATA;

typedef struct _LDR_IMPORT_CALLBACK_INFO
{
    void (*ImportCallbackRoutine)(PVOID, char*);
    PVOID ImportCallbackParameter;
}LDR_IMPORT_CALLBACK_INFO, * PLDR_IMPORT_CALLBACK_INFO;

typedef struct _LDR_RESLOADER_RET
{
    PVOID Module;
    PVOID DataEntry;
    PVOID TargetModule;
}LDR_RESLOADER_RET, * PLDR_RESLOADER_RET;

typedef struct _LDR_SECTION_INFO
{
    PVOID SectionHandle;
    DWORD DesiredAccess;
    OBJECT_ATTRIBUTES* ObjA;
    DWORD SectionPageProtection;
    DWORD AllocationAttributes;
}LDR_SECTION_INFO, * PLDR_SECTION_INFO;

typedef struct _LDR_VERIFY_IMAGE_INFO
{
    DWORD Size;
    DWORD Flags;
    struct _LDR_IMPORT_CALLBACK_INFO CallbackInfo;
    struct _LDR_SECTION_INFO SectionInfo;
    WORD ImageCharacteristics;
}LDR_VERIFY_IMAGE_INFO, * PLDR_VERIFY_IMAGE_INFO;

typedef struct _LDT_ENTRY
{
    WORD LimitLow;
    WORD BaseLow;
    union
    {
        struct
        {
            UCHAR BaseMid;
            UCHAR Flags1;
            UCHAR Flags2;
            UCHAR BaseHi;
        } Bytes;
        struct
        {
            union
            {
                DWORD BaseMid;
                DWORD Type;
                DWORD Dpl;
                DWORD Pres;
                DWORD LimitHi;
                DWORD Sys;
                DWORD Reserved_0;
                DWORD Default_Big;
                DWORD Granularity;
                DWORD BaseHi;
            } __bitfield0;
        } Bits;
    } HighWord;
}LDT_ENTRY, * PLDT_ENTRY;

typedef ULONG_PTR KAFFINITY;
typedef KAFFINITY* PKAFFINITY;

typedef struct _KAFFINITY_EX
{
    WORD Count;
    WORD Size;
    DWORD Reserved;
    QWORD Bitmap[0x14];
}KAFFINITY_EX, * PKAFFINITY_EX;

typedef struct _KAFFINITY_ENUMERATION_CONTEXT
{
    KAFFINITY_EX* Affinity;
    QWORD CurrentMask;
    WORD CurrentIndex;
}KAFFINITY_ENUMERATION_CONTEXT, * PKAFFINITY_ENUMERATION_CONTEXT;

typedef enum _KWAIT_BLOCK_STATE // int32_t
{
    WaitBlockBypassStart = 0x0,
    WaitBlockBypassComplete = 0x1,
    WaitBlockSuspendBypassStart = 0x2,
    WaitBlockSuspendBypassComplete = 0x3,
    WaitBlockActive = 0x4,
    WaitBlockInactive = 0x5,
    WaitBlockSuspended = 0x6,
    WaitBlockAllStates = 0x7
}KWAIT_BLOCK_STATE, * PKWAIT_BLOCK_STATE;

typedef enum _KWAIT_STATE // int32_t
{
    WaitInProgress = 0x0,
    WaitCommitted = 0x1,
    WaitAborted = 0x2,
    WaitSuspendInProgress = 0x3,
    WaitSuspended = 0x4,
    WaitResumeInProgress = 0x5,
    WaitResumeAborted = 0x6,
    WaitFirstSuspendState = 0x3,
    WaitLastSuspendState = 0x6,
    MaximumWaitState = 0x7
}KWAIT_STATE, * PKWAIT_STATE;

typedef enum _KCONTINUE_TYPE // int32_t
{
    KCONTINUE_UNWIND = 0x0,
    KCONTINUE_RESUME = 0x1,
    KCONTINUE_LONGJUMP = 0x2,
    KCONTINUE_SET = 0x3,
    KCONTINUE_LAST = 0x4
}KCONTINUE_TYPE, * PKCONTINUE_TYPE;

typedef struct _KCONTINUE_ARGUMENT
{
    KCONTINUE_TYPE ContinueType;
    DWORD ContinueFlags;
    QWORD Reserved[0x2];
}KCONTINUE_ARGUMENT, * PKCONTINUE_ARGUMENT;

typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, * PKTHREAD_STATE;

typedef enum _KTHREAD_TAG //int32_t
{
    KThreadTagNone = 0x0,
    KThreadTagMediaBuffering = 0x1,
    KThreadTagDeadline = 0x2,
    KThreadTagMax = 0x3
}KTHREAD_TAG, * PKTHREAD_TAG;

typedef enum _KWAIT_REASON
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    WrPhysicalFault,
    WrIoRing,
    WrMdlCache,
    MaximumWaitReason
} KWAIT_REASON, * PKWAIT_REASON;

typedef enum _WORKING_SET_TYPE // int32_t
{
    WorkingSetTypeUser = 0x0,
    WorkingSetTypeSession = 0x1,
    WorkingSetTypeSystemTypes = 0x2,
    WorkingSetTypeSystemCache = 0x2,
    WorkingSetTypePagedPool = 0x3,
    WorkingSetTypeSystemViews = 0x4,
    WorkingSetTypePagableMaximum = 0x4,
    WorkingSetTypeSystemPtes = 0x5,
    WorkingSetTypeKernelStacks = 0x6,
    WorkingSetTypeNonPagedPool = 0x7,
    WorkingSetTypeMaximum = 0x8
}WORKING_SET_TYPE, * PWORKING_SET_TYPE;

typedef union _KWAIT_STATUS_REGISTER
{
    UCHAR Flags;
    UCHAR State;
    UCHAR Affinity;
    UCHAR Priority;
    UCHAR Apc;
    UCHAR UserApc;
    UCHAR Alert;
}KWAIT_STATUS_REGISTER, * PKWAIT_STATUS_REGISTER;

typedef LONG KPRIORITY;

//----------------------WinNT PE HEADER & Reversed Structures----------------------//

typedef enum _SE_WS_APPX_SIGNATURE_ORIGIN // int32_t
{
    SE_WS_APPX_SIGNATURE_ORIGIN_NOT_VALIDATED = 0x0,
    SE_WS_APPX_SIGNATURE_ORIGIN_UNKNOWN = 0x1,
    SE_WS_APPX_SIGNATURE_ORIGIN_APPSTORE = 0x2,
    SE_WS_APPX_SIGNATURE_ORIGIN_WINDOWS = 0x3,
    SE_WS_APPX_SIGNATURE_ORIGIN_ENTERPRISE = 0x4
}SE_WS_APPX_SIGNATURE_ORIGIN, * PSE_WS_APPX_SIGNATURE_ORIGIN;

typedef enum _AVRF_MODE_FLAGS // int32_t
{
    APP_VERIFIER_DISABLED = 0x0,
    APP_VERIFIER_ENABLED = 0x1,
    APP_VERIFIER_MITIGATIONS = 0x2
}AVRF_MODE_FLAG, * PAVRF_MODE_FLAG;

#define IMAGE_DOS_SIGNATURE                                    0x5A4D      //MZ
#define IMAGE_NT_SIGNATURE                                     0x50450000  //PE00

#define IMAGE_SIZEOF_FILE_HEADER                               20
#define IMAGE_SIZEOF_SECTION_HEADER                            40
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES                       16
#define IMAGE_SIZEOF_SHORT_NAME                                8

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC                          0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC                          0x20b

typedef enum _PE_MAGIC // uint16_t
{
    PE_ROM_IMAGE = 0x107,
    PE_32BIT = 0x10b,
    PE_64BIT = 0x20b
}PE_MAGIC, * PPE_MAGIC;

#define IMAGE_ORDINAL_FLAG64                                   0x8000000000000000
#define IMAGE_ORDINAL_FLAG32                                   0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

#define IMAGE_DIRECTORY_ENTRY_EXPORT                           0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT                           1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE                         2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION                        3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY                         4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC                        5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG                            6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE                     7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR                        8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS                              9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG                      10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT                     11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT                              12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT                     13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR                   14   // COM Runtime descriptor

#define DLL_PROCESS_ATTACH   1    
#define DLL_THREAD_ATTACH    2    
#define DLL_THREAD_DETACH    3    
#define DLL_PROCESS_DETACH   0    

#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_TARGET_HOST       0x0001
#define IMAGE_FILE_MACHINE_I386              0x014c// Intel 386.
#define IMAGE_FILE_MACHINE_R3000             0x0162
#define IMAGE_FILE_MACHINE_R4000             0x0166  
#define IMAGE_FILE_MACHINE_R10000            0x0168 
#define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  
#define IMAGE_FILE_MACHINE_ALPHA             0x0184  
#define IMAGE_FILE_MACHINE_SH3               0x01a2 
#define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
#define IMAGE_FILE_MACHINE_SH3E              0x01a4
#define IMAGE_FILE_MACHINE_SH4               0x01a6
#define IMAGE_FILE_MACHINE_SH5               0x01a8
#define IMAGE_FILE_MACHINE_ARM               0x01c0
#define IMAGE_FILE_MACHINE_THUMB             0x01c2
#define IMAGE_FILE_MACHINE_ARMNT             0x01c4
#define IMAGE_FILE_MACHINE_AM33              0x01d3
#define IMAGE_FILE_MACHINE_POWERPC           0x01F0
#define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
#define IMAGE_FILE_MACHINE_IA64              0x0200// Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            0x0266
#define IMAGE_FILE_MACHINE_ALPHA64           0x0284
#define IMAGE_FILE_MACHINE_MIPSFPU           0x0366
#define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466
#define IMAGE_FILE_MACHINE_AXP64             _IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE           0x0520
#define IMAGE_FILE_MACHINE_CEF               0x0CEF
#define IMAGE_FILE_MACHINE_EBC               0x0EBC
#define IMAGE_FILE_MACHINE_AMD64             0x8664// AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              0x9041
#define IMAGE_FILE_MACHINE_ARM64             0xAA64
#define IMAGE_FILE_MACHINE_CEE               0xC0EE

typedef enum _COFF_MACHINE // uint16_t
{
    /*IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
    IMAGE_FILE_MACHINE_AM33 = 0x1d3,
    IMAGE_FILE_MACHINE_AMD64 = 0x8664,
    IMAGE_FILE_MACHINE_ARM = 0x1c0,
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
    IMAGE_FILE_MACHINE_ARMNT = 0x1c4,
    IMAGE_FILE_MACHINE_EBC = 0xebc,
    IMAGE_FILE_MACHINE_I386 = 0x14c,
    IMAGE_FILE_MACHINE_IA64 = 0x200,
    IMAGE_FILE_MACHINE_M32R = 0x9041,
    IMAGE_FILE_MACHINE_MIPS16 = 0x266,
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366,
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,
    IMAGE_FILE_MACHINE_POWERPC = 0x1f0,
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,
    IMAGE_FILE_MACHINE_R4000 = 0x166,*/
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032,
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064,
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128,
    /*IMAGE_FILE_MACHINE_SH3 = 0x1a2,
    IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
    IMAGE_FILE_MACHINE_SH4 = 0x1a6,
    IMAGE_FILE_MACHINE_SH5 = 0x1a8,
    IMAGE_FILE_MACHINE_THUMB = 0x1c2,
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169*/
}COFF_MACHINE, * PCOFF_MACHINE;

#define IMAGE_SUBSYSTEM_UNKNOWN              0   // Unknown subsystem.
#define IMAGE_SUBSYSTEM_NATIVE               1   // Image doesn't require a subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_GUI          2   // Image runs in the Windows GUI subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI          3   // Image runs in the Windows character subsystem.
#define IMAGE_SUBSYSTEM_OS2_CUI              5   // image runs in the OS/2 character subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI            7   // image runs in the Posix character subsystem.
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS       8   // image is a native Win9x driver.
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI       9   // Image runs in the Windows CE subsystem.
#define IMAGE_SUBSYSTEM_EFI_APPLICATION      10  //
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11   //
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER   12  //
#define IMAGE_SUBSYSTEM_EFI_ROM              13
#define IMAGE_SUBSYSTEM_XBOX                 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16
#define IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG    17

typedef enum _PE_SUBSYSTEM // uint16_t
{
    /*IMAGE_SUBSYSTEM_UNKNOWN = 0x0,
    IMAGE_SUBSYSTEM_NATIVE = 0x1,
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 0x2,
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 0x3,
    IMAGE_SUBSYSTEM_OS2_CUI = 0x5,
    IMAGE_SUBSYSTEM_POSIX_CUI = 0x7,
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 0x8,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 0x9,
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 0xa,
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 0xb,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 0xc,
    IMAGE_SUBSYSTEM_EFI_ROM = 0xd,
    IMAGE_SUBSYSTEM_XBOX = 0xe,
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 0x10*/
}PE_SUBSYSTEM, * PPE_SUBSYSTEM;

#define IMAGE_LIBRARY_PROCESS_INIT                          0x0001     // Reserved.
#define IMAGE_LIBRARY_PROCESS_TERM                          0x0002     // Reserved.
#define IMAGE_LIBRARY_THREAD_INIT                           0x0004     // Reserved.
#define IMAGE_LIBRARY_THREAD_TERM                           0x0008     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA            0x0020//64-bit  
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE               0x0040    
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY            0x0080     
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT                  0x0100// DEP
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION               0x0200     
#define IMAGE_DLLCHARACTERISTICS_NO_SEH                     0x0400     
#define IMAGE_DLLCHARACTERISTICS_NO_BIND                    0x0800    
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER               0x1000 
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER                 0x2000   
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF                   0x4000
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE      0x8000

#define IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT                                  0x01
#define IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE                      0x02
#define IMAGE_DLLCHARACTERISTICS_EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE  0x04
#define IMAGE_DLLCHARACTERISTICS_EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC              0x08
#define IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_1                              0x10  // Reserved for CET policy *downgrade* only!
#define IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_2                              0x20  // Reserved for CET policy *downgrade* only!


typedef enum _PE_DLL_CHARACTERISTICS // uint16_t
{
    IMAGE_DLLCHARACTERISTICS_0001 = 0x1,
    IMAGE_DLLCHARACTERISTICS_0002 = 0x2,
    IMAGE_DLLCHARACTERISTICS_0004 = 0x4,
    IMAGE_DLLCHARACTERISTICS_0008 = 0x8,
    /*IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x20,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40,
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x80,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x100,
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x200,
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x400,
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x800,
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000*/
}PE_DLL_CHARACTERISTICS, * PPE_DLL_CHARACTERISTICS;

#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved external references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Aggressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed.
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file.
#define IMAGE_FILE_SYSTEM                    0x1000  // System File.
#define IMAGE_FILE_DLL                       0x2000  // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed.

typedef enum _COFF_CHARACTERISTICS // uint16_t
{
    /*IMAGE_FILE_RELOCS_STRIPPED = 0x1,
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x2,
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x4,
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x8,
    IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x10,
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x20,
    IMAGE_FILE_BYTES_REVERSED_LO = 0x80,
    IMAGE_FILE_32BIT_MACHINE = 0x100,
    IMAGE_FILE_DEBUG_STRIPPED = 0x200,
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x400,
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x800,
    IMAGE_FILE_SYSTEM = 0x1000,
    IMAGE_FILE_DLL = 0x2000,
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000*/
}COFF_CHARACTERISTICS, * PCOFF_CHARACTERISTICS;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_OS2_HEADER
{
    WORD ne_magic;
    char ne_ver;
    char ne_rev;
    WORD ne_enttab;
    WORD ne_cbenttab;
    LONG ne_crc;
    WORD ne_flags;
    WORD ne_autodata;
    WORD ne_heap;
    WORD ne_stack;
    LONG ne_csip;
    LONG ne_sssp;
    WORD ne_cseg;
    WORD ne_cmod;
    WORD ne_cbnrestab;
    WORD ne_segtab;
    WORD ne_rsrctab;
    WORD ne_restab;
    WORD ne_modtab;
    WORD ne_imptab;
    LONG ne_nrestab;
    WORD ne_cmovent;
    WORD ne_align;
    WORD ne_cres;
    UCHAR ne_exetyp;
    UCHAR ne_flagsothers;
    WORD ne_pretthunks;
    WORD ne_psegrefbytes;
    WORD ne_swaparea;
    WORD ne_expver;
}IMAGE_OS2_HEADER, * PIMAGE_OS2_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_COR20_HEADER
{
    DWORD cb;
    WORD MajorRuntimeVersion;
    WORD MinorRuntimeVersion;
    IMAGE_DATA_DIRECTORY MetaData;
    DWORD Flags;
    union
    {
        DWORD EntryPointToken;
        DWORD EntryPointRVA;
    } __inner5;
    IMAGE_DATA_DIRECTORY Resources;
    IMAGE_DATA_DIRECTORY StrongNameSignature;
    IMAGE_DATA_DIRECTORY CodeManagerTable;
    IMAGE_DATA_DIRECTORY VTableFixups;
    IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
    IMAGE_DATA_DIRECTORY ManagedNativeHeader;
}IMAGE_COR20_HEADER, * PIMAGE_COR20_HEADER;

typedef struct _IMAGE_COR_ILMETHOD_FAT
{
    union
    {
        DWORD Flags;
        DWORD Size;
        DWORD MaxStack;
    } __bitfield0;
    DWORD CodeSize;
    DWORD LocalVarSigTok;
}IMAGE_COR_ILMETHOD_FAT, * PIMAGE_COR_ILMETHOD_FAT;

typedef struct _IMAGE_COR_ILMETHOD_TINY
{
    UCHAR Flags_CodeSize;
}IMAGE_COR_ILMETHOD_TINY, * PIMAGE_COR_ILMETHOD_TINY;

typedef union _IMAGE_COR_ILMETHOD
{
    IMAGE_COR_ILMETHOD_TINY Tiny;
    IMAGE_COR_ILMETHOD_FAT Fat;
}IMAGE_COR_ILMETHOD, * PIMAGE_COR_ILMETHOD;

typedef enum _CorExceptionFlag// int32_t
{
    COR_ILEXCEPTION_CLAUSE_NONE = 0x0,
    COR_ILEXCEPTION_CLAUSE_OFFSETLEN = 0x0,
    COR_ILEXCEPTION_CLAUSE_DEPRECATED = 0x0,
    COR_ILEXCEPTION_CLAUSE_FILTER = 0x1,
    COR_ILEXCEPTION_CLAUSE_FINALLY = 0x2,
    COR_ILEXCEPTION_CLAUSE_FAULT = 0x4,
    COR_ILEXCEPTION_CLAUSE_DUPLICATED = 0x8
}CorExceptionFlag, * PCorExceptionFlag;

typedef struct _IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT
{
    CorExceptionFlag Flags;
    DWORD TryOffset;
    DWORD TryLength;
    DWORD HandlerOffset;
    DWORD HandlerLength;
    union
    {
        DWORD ClassToken;
        DWORD FilterOffset;
    } __inner5;
}IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT, * PIMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT;

typedef struct _IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL
{
    union
    {
        DWORD Flags;
        DWORD TryOffset;
    } __bitfield0;
    union
    {
        DWORD TryLength;
        DWORD HandlerOffset;
        DWORD HandlerLength;
    } __bitfield4;
    union
    {
        DWORD ClassToken;
        DWORD FilterOffset;
    } __inner2;
}IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL, * PIMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL;

typedef struct _IMAGE_COR_FIXUPENTRY
{
    DWORD ulRVA;
    DWORD Count;
}IMAGE_COR_FIXUPENTRY, * PIMAGE_COR_FIXUPENTRY;

typedef struct _IMAGE_COR_MIH_ENTRY
{
    DWORD EHRVA;
    DWORD MethodRVA;
    DWORD Token;
    UCHAR Flags;
    UCHAR CodeManager;
    UCHAR MIHData[0x0];
}IMAGE_COR_MIH_ENTRY, * PIMAGE_COR_MIH_ENTRY;

typedef struct _IMAGE_COR_NATIVE_DESCRIPTOR
{
    DWORD GCInfo;
    DWORD EHInfo;
}IMAGE_COR_NATIVE_DESCRIPTOR, * PIMAGE_COR_NATIVE_DESCRIPTOR;

typedef struct _IMAGE_COR_X86_RUNTIME_FUNCTION_ENTRY
{
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD MIH;
}IMAGE_COR_X86_RUNTIME_FUNCTION_ENTRY, * PIMAGE_COR_X86_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_COR_ILMETHOD_SECT_FAT
{
    union
    {
        DWORD Kind;
        DWORD DataSize;
    } __bitfield0;
}IMAGE_COR_ILMETHOD_SECT_FAT, * PIMAGE_COR_ILMETHOD_SECT_FAT;

typedef struct _IMAGE_COR_ILMETHOD_SECT_EH_FAT
{
    IMAGE_COR_ILMETHOD_SECT_FAT SectFat;
    IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT Clauses[0x1];
}IMAGE_COR_ILMETHOD_SECT_EH_FAT, * PIMAGE_COR_ILMETHOD_SECT_EH_FAT;

typedef struct _IMAGE_COR_ILMETHOD_SECT_SMALL
{
    UCHAR Kind;
    UCHAR DataSize;
}IMAGE_COR_ILMETHOD_SECT_SMALL, * PIMAGE_COR_ILMETHOD_SECT_SMALL;

typedef struct _IMAGE_COR_ILMETHOD_SECT_EH_SMALL
{
    IMAGE_COR_ILMETHOD_SECT_SMALL SectSmall;
    USHORT Reserved;
    IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL Clauses[0x1];
}IMAGE_COR_ILMETHOD_SECT_EH_SMALL, * PIMAGE_COR_ILMETHOD_SECT_EH_SMALL;

typedef union _IMAGE_COR_ILMETHOD_SECT_EH
{
    IMAGE_COR_ILMETHOD_SECT_EH_SMALL Small;
    IMAGE_COR_ILMETHOD_SECT_EH_FAT Fat;
}IMAGE_COR_ILMETHOD_SECT_EH, * PIMAGE_COR_ILMETHOD_SECT_EH;

typedef struct _IMAGE_COR_VTABLEFIXUP
{
    DWORD RVA;
    USHORT Count;
    USHORT Type;
}IMAGE_COR_VTABLEFIXUP, * PIMAGE_COR_VTABLEFIXUP;

typedef struct _COR_FIELD_OFFSET
{
    DWORD ridOfField;
    DWORD ulOffset;
}COR_FIELD_OFFSET, * PCOR_FIELD_OFFSET;

typedef struct _COR_NATIVE_LINK
{
    UCHAR m_linkType;
    UCHAR m_flags;
    //__offset(0x2);
    DWORD m_entryPoint;
}COR_NATIVE_LINK, * PCOR_NATIVE_LINK;

typedef struct _COR_SECATTR
{
    DWORD tkCtor;
    void const* pCustomAttribute;
    DWORD cbCustomAttribute;
}COR_SECATTR, * PCOR_SECATTR;

typedef enum _COR_ARG_TYPE//CorArgType // int32_t
{
    IMAGE_CEE_CS_END = 0x0,
    IMAGE_CEE_CS_VOID = 0x1,
    IMAGE_CEE_CS_I4 = 0x2,
    IMAGE_CEE_CS_I8 = 0x3,
    IMAGE_CEE_CS_R4 = 0x4,
    IMAGE_CEE_CS_R8 = 0x5,
    IMAGE_CEE_CS_PTR = 0x6,
    IMAGE_CEE_CS_OBJECT = 0x7,
    IMAGE_CEE_CS_STRUCT4 = 0x8,
    IMAGE_CEE_CS_STRUCT32 = 0x9,
    IMAGE_CEE_CS_BYVALUE = 0xa
}COR_ARG_TYPE, * PCOR_ARG_TYPE;

typedef enum _COR_ASSEMBLY_FLAGS//CorAssemblyFlags // int32_t
{
    afPublicKey = 0x1,
    afPA_None = 0x0,
    afPA_MSIL = 0x10,
    afPA_x86 = 0x20,
    afPA_IA64 = 0x30,
    afPA_AMD64 = 0x40,
    afPA_ARM = 0x50,
    afPA_NoPlatform = 0x70,
    afPA_Specified = 0x80,
    afPA_Mask = 0x70,
    afPA_FullMask = 0xf0,
    afPA_Shift = 0x4,
    afEnableJITcompileTracking = 0x8000,
    afDisableJITcompileOptimizer = 0x4000,
    afRetargetable = 0x100,
    afContentType_Default = 0x0,
    afContentType_WindowsRuntime = 0x200,
    afContentType_Mask = 0xe00
}COR_ASSEMBLY_FLAGS, * PCOR_ASSEMBLY_FLAGS;

typedef enum _COR_ATTRIBUTE_TARGETS//CorAttributeTargets// int32_t
{
    catAssembly = 0x1,
    catModule = 0x2,
    catClass = 0x4,
    catStruct = 0x8,
    catEnum = 0x10,
    catConstructor = 0x20,
    catMethod = 0x40,
    catProperty = 0x80,
    catField = 0x100,
    catEvent = 0x200,
    catInterface = 0x400,
    catParameter = 0x800,
    catDelegate = 0x1000,
    catGenericParameter = 0x4000,
    catAll = 0x5fff,
    catClassMembers = 0x17fc
}COR_ATTRIBUTE_TARGETS, * PCOR_ATTRIBUTE_TARGETS;

typedef enum _COR_CALLING_CONVENTION//CorCallingConvention // int32_t
{
    IMAGE_CEE_CS_CALLCONV_DEFAULT = 0x0,
    IMAGE_CEE_CS_CALLCONV_VARARG = 0x5,
    IMAGE_CEE_CS_CALLCONV_FIELD = 0x6,
    IMAGE_CEE_CS_CALLCONV_LOCAL_SIG = 0x7,
    IMAGE_CEE_CS_CALLCONV_PROPERTY = 0x8,
    IMAGE_CEE_CS_CALLCONV_UNMGD = 0x9,
    IMAGE_CEE_CS_CALLCONV_GENERICINST = 0xa,
    IMAGE_CEE_CS_CALLCONV_NATIVEVARARG = 0xb,
    IMAGE_CEE_CS_CALLCONV_MAX = 0xc,
    IMAGE_CEE_CS_CALLCONV_MASK = 0xf,
    IMAGE_CEE_CS_CALLCONV_HASTHIS = 0x20,
    IMAGE_CEE_CS_CALLCONV_EXPLICITTHIS = 0x40,
    IMAGE_CEE_CS_CALLCONV_GENERIC = 0x10
}COR_CALLING_CONVENTION, * PCOR_CALLING_CONVENTION;

typedef enum _COR_CHECK_DUPLICATES_FOR//CorCheckDuplicatesFor// int32_t
{
    MDDupAll = 0xff,
    MDDupENC = 0xff,
    MDNoDupChecks = 0x0,
    MDDupTypeDef = 0x1,
    MDDupInterfaceImpl = 0x2,
    MDDupMethodDef = 0x4,
    MDDupTypeRef = 0x8,
    MDDupMemberRef = 0x10,
    MDDupCustomAttribute = 0x20,
    MDDupParamDef = 0x40,
    MDDupPermission = 0x80,
    MDDupProperty = 0x100,
    MDDupEvent = 0x200,
    MDDupFieldDef = 0x400,
    MDDupSignature = 0x800,
    MDDupModuleRef = 0x1000,
    MDDupTypeSpec = 0x2000,
    MDDupImplMap = 0x4000,
    MDDupAssemblyRef = 0x8000,
    MDDupFile = 0x10000,
    MDDupExportedType = 0x20000,
    MDDupManifestResource = 0x40000,
    MDDupGenericParam = 0x80000,
    MDDupMethodSpec = 0x100000,
    MDDupGenericParamConstraint = 0x200000,
    MDDupAssembly = 0x10000000,
    MDDupDefault = 0x102818
}COR_CHECK_DUPLICATES_FOR, * PCOR_CHECK_DUPLICATES_FOR;

typedef enum _COR_DECL_SECURITY//CorDeclSecurity // int32_t
{
    dclActionMask = 0x1f,
    dclActionNil = 0x0,
    dclRequest = 0x1,
    dclDemand = 0x2,
    dclAssert = 0x3,
    dclDeny = 0x4,
    dclPermitOnly = 0x5,
    dclLinktimeCheck = 0x6,
    dclInheritanceCheck = 0x7,
    dclRequestMinimum = 0x8,
    dclRequestOptional = 0x9,
    dclRequestRefuse = 0xa,
    dclPrejitGrant = 0xb,
    dclPrejitDenied = 0xc,
    dclNonCasDemand = 0xd,
    dclNonCasLinkDemand = 0xe,
    dclNonCasInheritance = 0xf,
    dclMaximumValue = 0xf
}COR_DECL_SECURITY, * PCOR_DECL_SECURITY;

typedef enum _COR_ELEMENT_TYPE//CorElementType // int32_t
{
    ELEMENT_TYPE_END = 0x0,
    ELEMENT_TYPE_VOID = 0x1,
    ELEMENT_TYPE_BOOLEAN = 0x2,
    ELEMENT_TYPE_CHAR = 0x3,
    ELEMENT_TYPE_I1 = 0x4,
    ELEMENT_TYPE_U1 = 0x5,
    ELEMENT_TYPE_I2 = 0x6,
    ELEMENT_TYPE_U2 = 0x7,
    ELEMENT_TYPE_I4 = 0x8,
    ELEMENT_TYPE_U4 = 0x9,
    ELEMENT_TYPE_I8 = 0xa,
    ELEMENT_TYPE_U8 = 0xb,
    ELEMENT_TYPE_R4 = 0xc,
    ELEMENT_TYPE_R8 = 0xd,
    ELEMENT_TYPE_STRING = 0xe,
    ELEMENT_TYPE_PTR = 0xf,
    ELEMENT_TYPE_BYREF = 0x10,
    ELEMENT_TYPE_VALUETYPE = 0x11,
    ELEMENT_TYPE_CLASS = 0x12,
    ELEMENT_TYPE_VAR = 0x13,
    ELEMENT_TYPE_ARRAY = 0x14,
    ELEMENT_TYPE_GENERICINST = 0x15,
    ELEMENT_TYPE_TYPEDBYREF = 0x16,
    ELEMENT_TYPE_I = 0x18,
    ELEMENT_TYPE_U = 0x19,
    ELEMENT_TYPE_FNPTR = 0x1b,
    ELEMENT_TYPE_OBJECT = 0x1c,
    ELEMENT_TYPE_SZARRAY = 0x1d,
    ELEMENT_TYPE_MVAR = 0x1e,
    ELEMENT_TYPE_CMOD_REQD = 0x1f,
    ELEMENT_TYPE_CMOD_OPT = 0x20,
    ELEMENT_TYPE_INTERNAL = 0x21,
    ELEMENT_TYPE_MAX = 0x22,
    ELEMENT_TYPE_MODIFIER = 0x40,
    ELEMENT_TYPE_SENTINEL = 0x41,
    ELEMENT_TYPE_PINNED = 0x45
}COR_ELEMENT_TYPE, * PCOR_ELEMENT_TYPE;

typedef enum _COR_ERROR_IF_EMIT_OUT_OF_ORDER//CorErrorIfEmitOutOfOrder // int32_t
{
    MDErrorOutOfOrderDefault = 0x0,
    MDErrorOutOfOrderNone = 0x0,
    MDErrorOutOfOrderAll = 0xff,
    MDMethodOutOfOrder = 0x1,
    MDFieldOutOfOrder = 0x2,
    MDParamOutOfOrder = 0x4,
    MDPropertyOutOfOrder = 0x8,
    MDEventOutOfOrder = 0x10
}COR_ERROR_IF_EMIT_OUT_OF_ORDER, * PCOR_ERROR_IF_EMIT_OUT_OF_ORDER;

typedef enum _COR_EVENT_ATTR//CorEventAttr // int32_t
{
    evSpecialName = 0x200,
    evReservedMask = 0x400,
    evRTSpecialName = 0x400
}COR_EVENT_ATTR, * PCOR_EVENT_ATTR;

typedef enum _COR_FIELD_ATTR//CorFieldAttr // int32_t
{
    fdFieldAccessMask = 0x7,
    fdPrivateScope = 0x0,
    fdPrivate = 0x1,
    fdFamANDAssem = 0x2,
    fdAssembly = 0x3,
    fdFamily = 0x4,
    fdFamORAssem = 0x5,
    fdPublic = 0x6,
    fdStatic = 0x10,
    fdInitOnly = 0x20,
    fdLiteral = 0x40,
    fdNotSerialized = 0x80,
    fdSpecialName = 0x200,
    fdPinvokeImpl = 0x2000,
    fdReservedMask = 0x9500,
    fdRTSpecialName = 0x400,
    fdHasFieldMarshal = 0x1000,
    fdHasDefault = 0x8000,
    fdHasFieldRVA = 0x100
}COR_FIELD_ATTR, * PCOR_FIELD_ATTR;

typedef enum _COR_FILE_FLAGS//CorFileFlags // int32_t
{
    ffContainsMetaData = 0x0,
    ffContainsNoMetaData = 0x1
}COR_FILE_FLAGS, * PCOR_FILE_FLAGS;

typedef enum _COR_FILE_MAPPING//CorFileMapping // int32_t
{
    fmFlat = 0x0,
    fmExecutableImage = 0x1
}COR_FILE_MAPPING, * PCOR_FILE_MAPPING;

typedef enum _COR_GENERIC_PARAM_ATTR//CorGenericParamAttr // int32_t
{
    gpVarianceMask = 0x3,
    gpNonVariant = 0x0,
    gpCovariant = 0x1,
    gpContravariant = 0x2,
    gpSpecialConstraintMask = 0x1c,
    gpNoSpecialConstraint = 0x0,
    gpReferenceTypeConstraint = 0x4,
    gpNotNullableValueTypeConstraint = 0x8,
    gpDefaultConstructorConstraint = 0x10
}COR_GENERIC_PARAM_ATTR, * PCOR_GENERIC_PARAM_ATTR;

typedef enum _COR_IL_METHOD_FLAGS//CorILMethodFlags // int32_t
{
    CorILMethod_InitLocals = 0x10,
    CorILMethod_MoreSects = 0x8,
    CorILMethod_CompressedIL = 0x40,
    CorILMethod_FormatShift = 0x3,
    CorILMethod_FormatMask = 0x7,
    CorILMethod_TinyFormat = 0x2,
    CorILMethod_SmallFormat = 0x0,
    CorILMethod_FatFormat = 0x3,
    CorILMethod_TinyFormat1 = 0x6
}COR_IL_METHOD_FLAGS, * PCOR_IL_METHOD_FLAGS;

typedef enum _COR_IL_METHOD_SECT//CorILMethodSect // int32_t
{
    CorILMethod_Sect_Reserved = 0x0,
    CorILMethod_Sect_EHTable = 0x1,
    CorILMethod_Sect_OptILTable = 0x2,
    CorILMethod_Sect_KindMask = 0x3f,
    CorILMethod_Sect_FatFormat = 0x40,
    CorILMethod_Sect_MoreSects = 0x80
}COR_IL_METHOD_SECT, * PCOR_IL_METHOD_SECT;

typedef enum _COR_IMPORT_OPTIONS//CorImportOptions // int32_t
{
    MDImportOptionDefault = 0x0,
    MDImportOptionAll = 0xff,
    MDImportOptionAllTypeDefs = 0x1,
    MDImportOptionAllMethodDefs = 0x2,
    MDImportOptionAllFieldDefs = 0x4,
    MDImportOptionAllProperties = 0x8,
    MDImportOptionAllEvents = 0x10,
    MDImportOptionAllCustomAttributes = 0x20,
    MDImportOptionAllExportedTypes = 0x40
}COR_IMPORT_OPTIONS, * PCOR_IMPORT_OPTIONS;

typedef enum _COR_LINKER_OPTIONS//CorLinkerOptions // int32_t
{
    MDAssembly = 0x0,
    MDNetModule = 0x1
}COR_LINKER_OPTIONS, * PCOR_LINKER_OPTIONS;

typedef enum _COR_LOCAL_REF_PRESERVATION//CorLocalRefPreservation //int32_t
{
    MDPreserveLocalRefsNone = 0x0,
    MDPreserveLocalTypeRef = 0x1,
    MDPreserveLocalMemberRef = 0x2
}COR_LOCAL_REF_PRESERVATION, * PCOR_LOCAL_REF_PRESERVATION;

typedef enum _COR_MANIFEST_RESOURCE_FLAGS//CorManifestResourceFlags// int32_t
{
    mrVisibilityMask = 0x7,
    mrPublic = 0x1,
    mrPrivate = 0x2
}COR_MANIFEST_RESOURCE_FLAGS, * PCOR_MANIFEST_RESOURCE_FLAGS;

typedef enum _COR_METHOD_ATTR//CorMethodAttr // int32_t
{
    mdMemberAccessMask = 0x7,
    mdPrivateScope = 0x0,
    mdPrivate = 0x1,
    mdFamANDAssem = 0x2,
    mdAssem = 0x3,
    mdFamily = 0x4,
    mdFamORAssem = 0x5,
    mdPublic = 0x6,
    mdStatic = 0x10,
    mdFinal = 0x20,
    mdVirtual = 0x40,
    mdHideBySig = 0x80,
    mdVtableLayoutMask = 0x100,
    mdReuseSlot = 0x0,
    mdNewSlot = 0x100,
    mdCheckAccessOnOverride = 0x200,
    mdAbstract = 0x400,
    mdSpecialName = 0x800,
    mdPinvokeImpl = 0x2000,
    mdUnmanagedExport = 0x8,
    mdReservedMask = 0xd000,
    mdRTSpecialName = 0x1000,
    mdHasSecurity = 0x4000,
    mdRequireSecObject = 0x8000
}COR_METHOD_ATTR, * PCOR_METHOD_ATTR;

typedef enum _COR_METHOD_IMPL//CorMethodImpl // int32_t
{
    miCodeTypeMask = 0x3,
    miIL = 0x0,
    miNative = 0x1,
    miOPTIL = 0x2,
    miRuntime = 0x3,
    miManagedMask = 0x4,
    miUnmanaged = 0x4,
    miManaged = 0x0,
    miForwardRef = 0x10,
    miPreserveSig = 0x80,
    miInternalCall = 0x1000,
    miSynchronized = 0x20,
    miNoInlining = 0x8,
    miAggressiveInlining = 0x100,
    miNoOptimization = 0x40,
    miSecurityMitigations = 0x400,
    miUserMask = 0x15fc,
    miMaxMethodImplVal = 0xffff
}COR_METHOD_IMPL, * PCOR_METHOD_IMPL;

typedef enum _COR_METHOD_SEMANTICS_ATTR//CorMethodSemanticsAttr // int32_t
{
    msSetter = 0x1,
    msGetter = 0x2,
    msOther = 0x4,
    msAddOn = 0x8,
    msRemoveOn = 0x10,
    msFire = 0x20
}COR_METHOD_SEMANTICS_ATTR, * PCOR_METHOD_SEMANTICS_ATTR;

typedef enum _COR_NATIVE_LINK_FLAGS//CorNativeLinkFlags // int32_t
{
    nlfNone = 0x0,
    nlfLastError = 0x1,
    nlfNoMangle = 0x2,
    nlfMaxValue = 0x3
}COR_NATIVE_LINK_FLAGS, * PCOR_NATIVE_LINK_FLAGS;

typedef enum _COR_NATIVE_LINK_TYPE//CorNativeLinkType // int32_t
{
    nltNone = 0x1,
    nltAnsi = 0x2,
    nltUnicode = 0x3,
    nltAuto = 0x4,
    nltOle = 0x5,
    nltMaxValue = 0x7
}COR_NATIVE_LINK_TYPE, * PCOR_NATIVE_LINK_TYPE;

typedef enum _COR_NATIVE_TYPE//CorNativeType // int32_t
{
    NATIVE_TYPE_END = 0x0,
    NATIVE_TYPE_VOID = 0x1,
    NATIVE_TYPE_BOOLEAN = 0x2,
    NATIVE_TYPE_I1 = 0x3,
    NATIVE_TYPE_U1 = 0x4,
    NATIVE_TYPE_I2 = 0x5,
    NATIVE_TYPE_U2 = 0x6,
    NATIVE_TYPE_I4 = 0x7,
    NATIVE_TYPE_U4 = 0x8,
    NATIVE_TYPE_I8 = 0x9,
    NATIVE_TYPE_U8 = 0xa,
    NATIVE_TYPE_R4 = 0xb,
    NATIVE_TYPE_R8 = 0xc,
    NATIVE_TYPE_SYSCHAR = 0xd,
    NATIVE_TYPE_VARIANT = 0xe,
    NATIVE_TYPE_CURRENCY = 0xf,
    NATIVE_TYPE_PTR = 0x10,
    NATIVE_TYPE_DECIMAL = 0x11,
    NATIVE_TYPE_DATE = 0x12,
    NATIVE_TYPE_BSTR = 0x13,
    NATIVE_TYPE_LPSTR = 0x14,
    NATIVE_TYPE_LPWSTR = 0x15,
    NATIVE_TYPE_LPTSTR = 0x16,
    NATIVE_TYPE_FIXEDSYSSTRING = 0x17,
    NATIVE_TYPE_OBJECTREF = 0x18,
    NATIVE_TYPE_IUNKNOWN = 0x19,
    NATIVE_TYPE_IDISPATCH = 0x1a,
    NATIVE_TYPE_STRUCT = 0x1b,
    NATIVE_TYPE_INTF = 0x1c,
    NATIVE_TYPE_SAFEARRAY = 0x1d,
    NATIVE_TYPE_FIXEDARRAY = 0x1e,
    NATIVE_TYPE_INT = 0x1f,
    NATIVE_TYPE_UINT = 0x20,
    NATIVE_TYPE_NESTEDSTRUCT = 0x21,
    NATIVE_TYPE_BYVALSTR = 0x22,
    NATIVE_TYPE_ANSIBSTR = 0x23,
    NATIVE_TYPE_TBSTR = 0x24,
    NATIVE_TYPE_VARIANTBOOL = 0x25,
    NATIVE_TYPE_FUNC = 0x26,
    NATIVE_TYPE_ASANY = 0x28,
    NATIVE_TYPE_ARRAY = 0x2a,
    NATIVE_TYPE_LPSTRUCT = 0x2b,
    NATIVE_TYPE_CUSTOMMARSHALER = 0x2c,
    NATIVE_TYPE_ERROR = 0x2d,
    NATIVE_TYPE_IINSPECTABLE = 0x2e,
    NATIVE_TYPE_HSTRING = 0x2f,
    NATIVE_TYPE_LPUTF8STR = 0x30,
    NATIVE_TYPE_MAX = 0x50
}COR_NATIVE_TYPE, * PCOR_NATIVE_TYPE;

typedef enum _COR_NOTIFICATION_FOR_TOKEN_MOVEMENT//CorNotificationForTokenMovement// int32_t
{
    MDNotifyDefault = 0xf,
    MDNotifyAll = 0xff,
    MDNotifyNone = 0x0,
    MDNotifyMethodDef = 0x1,
    MDNotifyMemberRef = 0x2,
    MDNotifyFieldDef = 0x4,
    MDNotifyTypeRef = 0x8,
    MDNotifyTypeDef = 0x10,
    MDNotifyParamDef = 0x20,
    MDNotifyInterfaceImpl = 0x40,
    MDNotifyProperty = 0x80,
    MDNotifyEvent = 0x100,
    MDNotifySignature = 0x200,
    MDNotifyTypeSpec = 0x400,
    MDNotifyCustomAttribute = 0x800,
    MDNotifySecurityValue = 0x1000,
    MDNotifyPermission = 0x2000,
    MDNotifyModuleRef = 0x4000,
    MDNotifyNameSpace = 0x8000,
    MDNotifyAssemblyRef = 0x1000000,
    MDNotifyFile = 0x2000000,
    MDNotifyExportedType = 0x4000000,
    MDNotifyResource = 0x8000000
}COR_NOTIFICATION_FOR_TOKEN_MOVEMENT, * PCOR_NOTIFICATION_FOR_TOKEN_MOVEMENT;

typedef enum _COR_OPEN_FLAGS//CorOpenFlags // int32_t
{
    ofRead = 0x0,
    ofWrite = 0x1,
    ofReadWriteMask = 0x1,
    ofCopyMemory = 0x2,
    ofReadOnly = 0x10,
    ofTakeOwnership = 0x20,
    ofNoTypeLib = 0x80,
    ofNoTransform = 0x1000,
    ofCheckIntegrity = 0x800,
    ofReserved1 = 0x100,
    ofReserved2 = 0x200,
    ofReserved3 = 0x400,
    ofReserved = -0x18c0
}COR_OPEN_FLAGS, * PCOR_OPEN_FLAGS;

typedef enum _COR_PE_KIND//CorPEKind // int32_t
{
    peNot = 0x0,
    peILonly = 0x1,
    pe32BitRequired = 0x2,
    pe32Plus = 0x4,
    pe32Unmanaged = 0x8,
    pe32BitPreferred = 0x10
}COR_PE_KIND, * PCOR_PE_KIND;

typedef enum _COR_PARAM_ATTR//CorParamAttr// int32_t
{
    pdIn = 0x1,
    pdOut = 0x2,
    pdOptional = 0x10,
    pdReservedMask = 0xf000,
    pdHasDefault = 0x1000,
    pdHasFieldMarshal = 0x2000,
    pdUnused = 0xcfe0
}COR_PARAM_ATTR, * PCOR_PARAM_ATTR;

typedef enum _COR_PINVOKE_MAP//CorPinvokeMap // int32_t
{
    pmNoMangle = 0x1,
    pmCharSetMask = 0x6,
    pmCharSetNotSpec = 0x0,
    pmCharSetAnsi = 0x2,
    pmCharSetUnicode = 0x4,
    pmCharSetAuto = 0x6,
    pmBestFitUseAssem = 0x0,
    pmBestFitEnabled = 0x10,
    pmBestFitDisabled = 0x20,
    pmBestFitMask = 0x30,
    pmThrowOnUnmappableCharUseAssem = 0x0,
    pmThrowOnUnmappableCharEnabled = 0x1000,
    pmThrowOnUnmappableCharDisabled = 0x2000,
    pmThrowOnUnmappableCharMask = 0x3000,
    pmSupportsLastError = 0x40,
    pmCallConvMask = 0x700,
    pmCallConvWinapi = 0x100,
    pmCallConvCdecl = 0x200,
    pmCallConvStdcall = 0x300,
    pmCallConvThiscall = 0x400,
    pmCallConvFastcall = 0x500,
    pmMaxValue = 0xffff
}COR_PINVOKE_MAP, * PCOR_PINVOKE_MAP;

typedef enum _COR_PROPERTY_ATTR//CorPropertyAttr //int32_t
{
    prSpecialName = 0x200,
    prReservedMask = 0xf400,
    prRTSpecialName = 0x400,
    prHasDefault = 0x1000,
    prUnused = 0xe9ff
}COR_PROPERTY_ATTR, * PCOR_PROPERTY_ATTR;

typedef enum _COR_REF_TO_DEF_CHECK//CorRefToDefCheck // int32_t
{
    MDRefToDefDefault = 0x3,
    MDRefToDefAll = 0xff,
    MDRefToDefNone = 0x0,
    MDTypeRefToDef = 0x1,
    MDMemberRefToDef = 0x2
}COR_REF_TO_DEF_CHECK, * PCOR_REF_TO_DEF_CHECK;

typedef enum _COR_REG_FLAGS//CorRegFlags // int32_t
{
    regNoCopy = 0x1,
    regConfig = 0x2,
    regHasRefs = 0x4
}COR_REG_FLAGS, * PCOR_REG_FLAGS;

typedef enum _COR_SAVE_SIZE//CorSaveSize // int32_t
{
    cssAccurate = 0x0,
    cssQuick = 0x1,
    cssDiscardTransientCAs = 0x2
}COR_SAVE_SIZE, * PCOR_SAVE_SIZE;

typedef enum _COR_SERIALIZATION_TYPE//CorSerializationType // int32_t
{
    SERIALIZATION_TYPE_UNDEFINED = 0x0,
    SERIALIZATION_TYPE_BOOLEAN = 0x2,
    SERIALIZATION_TYPE_CHAR = 0x3,
    SERIALIZATION_TYPE_I1 = 0x4,
    SERIALIZATION_TYPE_U1 = 0x5,
    SERIALIZATION_TYPE_I2 = 0x6,
    SERIALIZATION_TYPE_U2 = 0x7,
    SERIALIZATION_TYPE_I4 = 0x8,
    SERIALIZATION_TYPE_U4 = 0x9,
    SERIALIZATION_TYPE_I8 = 0xa,
    SERIALIZATION_TYPE_U8 = 0xb,
    SERIALIZATION_TYPE_R4 = 0xc,
    SERIALIZATION_TYPE_R8 = 0xd,
    SERIALIZATION_TYPE_STRING = 0xe,
    SERIALIZATION_TYPE_SZARRAY = 0x1d,
    SERIALIZATION_TYPE_TYPE = 0x50,
    SERIALIZATION_TYPE_TAGGED_OBJECT = 0x51,
    SERIALIZATION_TYPE_FIELD = 0x53,
    SERIALIZATION_TYPE_PROPERTY = 0x54,
    SERIALIZATION_TYPE_ENUM = 0x55
}COR_SERIALIZATION_TYPE, * PCOR_SERIALIZATION_TYPE;

typedef enum _COR_SET_ENC//CorSetENC // int32_t
{
    MDSetENCOn = 0x1,
    MDSetENCOff = 0x2,
    MDUpdateENC = 0x1,
    MDUpdateFull = 0x2,
    MDUpdateExtension = 0x3,
    MDUpdateIncremental = 0x4,
    MDUpdateDelta = 0x5,
    MDUpdateMask = 0x7
}COR_SET_ENC, * PCOR_SET_ENC;

typedef enum _COR_THREAD_SAFETY_OPTIONS//CorThreadSafetyOptions // int32_t
{
    MDThreadSafetyDefault = 0x0,
    MDThreadSafetyOff = 0x0,
    MDThreadSafetyOn = 0x1
}COR_THREAD_SAFETY_OPTIONS, * PCOR_THREAD_SAFETY_OPTIONS;

typedef enum _COR_TOKEN_TYPE//CorTokenType // int32_t
{
    mdtModule = 0x0,
    mdtTypeRef = 0x1000000,
    mdtTypeDef = 0x2000000,
    mdtFieldDef = 0x4000000,
    mdtMethodDef = 0x6000000,
    mdtParamDef = 0x8000000,
    mdtInterfaceImpl = 0x9000000,
    mdtMemberRef = 0xa000000,
    mdtCustomAttribute = 0xc000000,
    mdtPermission = 0xe000000,
    mdtSignature = 0x11000000,
    mdtEvent = 0x14000000,
    mdtProperty = 0x17000000,
    mdtMethodImpl = 0x19000000,
    mdtModuleRef = 0x1a000000,
    mdtTypeSpec = 0x1b000000,
    mdtAssembly = 0x20000000,
    mdtAssemblyRef = 0x23000000,
    mdtFile = 0x26000000,
    mdtExportedType = 0x27000000,
    mdtManifestResource = 0x28000000,
    mdtGenericParam = 0x2a000000,
    mdtMethodSpec = 0x2b000000,
    mdtGenericParamConstraint = 0x2c000000,
    mdtString = 0x70000000,
    mdtName = 0x71000000,
    mdtBaseType = 0x72000000
}COR_TOKEN_TYPE, * PCOR_TOKEN_TYPE;

typedef enum _COR_TYPE_ATTR//CorTypeAttr // int32_t
{
    tdVisibilityMask = 0x7,
    tdNotPublic = 0x0,
    tdPublic = 0x1,
    tdNestedPublic = 0x2,
    tdNestedPrivate = 0x3,
    tdNestedFamily = 0x4,
    tdNestedAssembly = 0x5,
    tdNestedFamANDAssem = 0x6,
    tdNestedFamORAssem = 0x7,
    tdLayoutMask = 0x18,
    tdAutoLayout = 0x0,
    tdSequentialLayout = 0x8,
    tdExplicitLayout = 0x10,
    tdClassSemanticsMask = 0x20,
    tdClass = 0x0,
    tdInterface = 0x20,
    tdAbstract = 0x80,
    tdSealed = 0x100,
    tdSpecialName = 0x400,
    tdImport = 0x1000,
    tdSerializable = 0x2000,
    tdWindowsRuntime = 0x4000,
    tdStringFormatMask = 0x30000,
    tdAnsiClass = 0x0,
    tdUnicodeClass = 0x10000,
    tdAutoClass = 0x20000,
    tdCustomFormatClass = 0x30000,
    tdCustomFormatMask = 0xc00000,
    tdBeforeFieldInit = 0x100000,
    tdForwarder = 0x200000,
    tdReservedMask = 0x40800,
    tdRTSpecialName = 0x800,
    tdHasSecurity = 0x40000
}COR_TYPE_ATTR, * PCOR_TYPE_ATTR;

typedef enum _COR_UNMANAGED_CALLING_CONVENTION//CorUnmanagedCallingConvention// int32_t
{
    IMAGE_CEE_UNMANAGED_CALLCONV_C = 0x1,
    IMAGE_CEE_UNMANAGED_CALLCONV_STDCALL = 0x2,
    IMAGE_CEE_UNMANAGED_CALLCONV_THISCALL = 0x3,
    IMAGE_CEE_UNMANAGED_CALLCONV_FASTCALL = 0x4,
    IMAGE_CEE_CS_CALLCONV_C = 0x1,
    IMAGE_CEE_CS_CALLCONV_STDCALL = 0x2,
    IMAGE_CEE_CS_CALLCONV_THISCALL = 0x3,
    IMAGE_CEE_CS_CALLCONV_FASTCALL = 0x4
}COR_UNMANAGED_CALLING_CONVENTION, * PCOR_UNMANAGED_CALLING_CONVENTION;

typedef enum _COR_VALIDATOR_MODULE_TYPE//CorValidatorModuleType // int32_t
{
    ValidatorModuleTypeInvalid = 0x0,
    ValidatorModuleTypeMin = 0x1,
    ValidatorModuleTypePE = 0x1,
    ValidatorModuleTypeObj = 0x2,
    ValidatorModuleTypeEnc = 0x3,
    ValidatorModuleTypeIncr = 0x4,
    ValidatorModuleTypeMax = 0x4
}COR_VALIDATOR_MODULE_TYPE, * PCOR_VALIDATOR_MODULE_TYPE;

typedef struct _IMAGE_COFF_SYMBOLS_HEADER
{
    DWORD NumberOfSymbols;
    DWORD LvaToFirstSymbol;
    DWORD NumberOfLinenumbers;
    DWORD LvaToFirstLinenumber;
    DWORD RvaToFirstByteOfCode;
    DWORD RvaToLastByteOfCode;
    DWORD RvaToFirstByteOfData;
    DWORD RvaToLastByteOfData;
}IMAGE_COFF_SYMBOLS_HEADER, * PIMAGE_COFF_SYMBOLS_HEADER;

#define FRAME_FPO       0
#define FRAME_TRAP      1
#define FRAME_TSS       2
#define FRAME_NONFPO    3

typedef struct _FPO_DATA {
    DWORD       ulOffStart;             // offset 1st byte of function code
    DWORD       cbProcSize;             // # bytes in function
    DWORD       cdwLocals;              // # bytes in locals/4
    WORD        cdwParams;              // # bytes in params/4
    WORD        cbProlog : 8;           // # bytes in prolog
    WORD        cbRegs : 3;           // # regs saved
    WORD        fHasSEH : 1;           // TRUE if SEH in func
    WORD        fUseBP : 1;           // TRUE if EBP has been allocated
    WORD        reserved : 1;           // reserved for future use
    WORD        cbFrame : 2;           // frame type
} FPO_DATA, * PFPO_DATA;

#define SIZEOF_RFPO_DATA 16

typedef struct _COFF_HEADER
{
    char magic[0x4];
    COFF_MACHINE machine;
    WORD numberOfSections;
    DWORD timeDateStamp;
    DWORD pointerToSymbolTable;
    DWORD numberOfSymbols;
    WORD sizeOfOptionalHeader;
    COFF_CHARACTERISTICS characteristics;
}COFF_HEADER, * PCOFF_HEADER;

typedef struct _IMAGE_ROM_OPTIONAL_HEADER
{
    WORD Magic;
    UCHAR MajorLinkerVersion;
    UCHAR MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD BaseOfBss;
    DWORD GprMask;
    DWORD CprMask[0x4];
    DWORD GpValue;
}IMAGE_ROM_OPTIONAL_HEADER, * PIMAGE_ROM_OPTIONAL_HEADER;

typedef struct _IMAGE_VXD_HEADER
{
    WORD e32_magic;
    UCHAR e32_border;
    UCHAR e32_worder;
    DWORD e32_level;
    WORD e32_cpu;
    WORD e32_os;
    DWORD e32_ver;
    DWORD e32_mflags;
    DWORD e32_mpages;
    DWORD e32_startobj;
    DWORD e32_eip;
    DWORD e32_stackobj;
    DWORD e32_esp;
    DWORD e32_pagesize;
    DWORD e32_lastpagesize;
    DWORD e32_fixupsize;
    DWORD e32_fixupsum;
    DWORD e32_ldrsize;
    DWORD e32_ldrsum;
    DWORD e32_objtab;
    DWORD e32_objcnt;
    DWORD e32_objmap;
    DWORD e32_itermap;
    DWORD e32_rsrctab;
    DWORD e32_rsrccnt;
    DWORD e32_restab;
    DWORD e32_enttab;
    DWORD e32_dirtab;
    DWORD e32_dircnt;
    DWORD e32_fpagetab;
    DWORD e32_frectab;
    DWORD e32_impmod;
    DWORD e32_impmodcnt;
    DWORD e32_impproc;
    DWORD e32_pagesum;
    DWORD e32_datapage;
    DWORD e32_preload;
    DWORD e32_nrestab;
    DWORD e32_cbnrestab;
    DWORD e32_nressum;
    DWORD e32_autodata;
    DWORD e32_debuginfo;
    DWORD e32_debuglen;
    DWORD e32_instpreload;
    DWORD e32_instdemand;
    DWORD e32_heapsize;
    UCHAR e32_res3[0xc];
    DWORD e32_winresoff;
    DWORD e32_winreslen;
    WORD e32_devid;
    WORD e32_ddkver;
}IMAGE_VXD_HEADER, * PIMAGE_VXD_HEADER;

typedef enum _REPLACES_COR_HDR_NUMERIC_DEFINES//ReplacesCorHdrNumericDefines // int32_t
{
    COMIMAGE_FLAGS_ILONLY = 0x1,
    COMIMAGE_FLAGS_32BITREQUIRED = 0x2,
    COMIMAGE_FLAGS_IL_LIBRARY = 0x4,
    COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x8,
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x10,
    COMIMAGE_FLAGS_TRACKDEBUGDATA = 0x10000,
    COMIMAGE_FLAGS_32BITPREFERRED = 0x20000,
    COR_VERSION_MAJOR_V2 = 0x2,
    COR_VERSION_MAJOR = 0x2,
    COR_VERSION_MINOR = 0x5,
    COR_DELETED_NAME_LENGTH = 0x8,
    COR_VTABLEGAP_NAME_LENGTH = 0x8,
    NATIVE_TYPE_MAX_CB = 0x1,
    COR_ILMETHOD_SECT_SMALL_MAX_DATASIZE = 0xff,
    IMAGE_COR_MIH_METHODRVA = 0x1,
    IMAGE_COR_MIH_EHRVA = 0x2,
    IMAGE_COR_MIH_BASICBLOCK = 0x8,
    COR_VTABLE_32BIT = 0x1,
    COR_VTABLE_64BIT = 0x2,
    COR_VTABLE_FROM_UNMANAGED = 0x4,
    COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN = 0x8,
    COR_VTABLE_CALL_MOST_DERIVED = 0x10,
    IMAGE_COR_EATJ_THUNK_SIZE = 0x20,
    MAX_CLASS_NAME = 0x400,
    MAX_PACKAGE_NAME = 0x400
}REPLACES_COR_HDR_NUMERIC_DEFINES, * PREPLACES_COR_HDR_NUMERIC_DEFINES;

typedef struct _ANON_OBJECT_HEADER
{
    WORD Sig1;
    WORD Sig2;
    WORD Version;
    WORD Machine;
    DWORD TimeDateStamp;
    GUID ClassID;
    DWORD SizeOfData;
}ANON_OBJECT_HEADER, * PANON_OBJECT_HEADER;

typedef struct _ANON_OBJECT_HEADER_BIGOBJ
{
    WORD Sig1;
    WORD Sig2;
    WORD Version;
    WORD Machine;
    DWORD TimeDateStamp;
    GUID ClassID;
    DWORD SizeOfData;
    DWORD Flags;
    DWORD MetaDataSize;
    DWORD MetaDataOffset;
    DWORD NumberOfSections;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
}ANON_OBJECT_HEADER_BIGOBJ, * PANON_OBJECT_HEADER_BIGOBJ;

typedef struct _ANON_OBJECT_HEADER_V2
{
    WORD Sig1;
    WORD Sig2;
    WORD Version;
    WORD Machine;
    DWORD TimeDateStamp;
    GUID ClassID;
    DWORD SizeOfData;
    DWORD Flags;
    DWORD MetaDataSize;
    DWORD MetaDataOffset;
}ANON_OBJECT_HEADER_V2, * PANON_OBJECT_HEADER_V2;

typedef struct _RICH_HEADER
{
    /*struct Rich_Header
{
    uint32_t e_magic__DanS;
    uint32_t e_align[0x3];
    uint32_t e_entry_id0__00937809;
    uint32_t e_entry_count0__51;
    uint32_t e_entry_id1__00010000;
    uint32_t e_entry_count1__135;
    uint32_t e_entry_id2__00fd6b14;
    uint32_t e_entry_count2__1;
    uint32_t e_entry_id3__01006b14;
    uint32_t e_entry_count3__1;
    uint32_t e_entry_id4__01036b14;
    uint32_t e_entry_count4__50;
    uint32_t e_entry_id5__01056b14;
    uint32_t e_entry_count5__94;
    uint32_t e_entry_id6__010e6b14;
    uint32_t e_entry_count6__568;
    uint32_t e_entry_id7__01046b14;
    uint32_t e_entry_count7__75;
    uint32_t e_entry_id8__00ff6b14;
    uint32_t e_entry_count8__1;
    uint32_t e_entry_id9__01026b14;
    uint32_t e_entry_count9__1;
    char e_magic[0x4];
    uint32_t e_checksum;
};*/
    DWORD e_magic__DanS;
    DWORD e_align[0x3];
    DWORD e_entry_id0__00937809;
    DWORD e_entry_count0__51;
    DWORD e_entry_id1__00010000;
    DWORD e_entry_count1__135;
    DWORD e_entry_id2__00fd6b14;
    DWORD e_entry_count2__1;
    DWORD e_entry_id3__01006b14;
    DWORD e_entry_count3__1;
    DWORD e_entry_id4__01036b14;
    DWORD e_entry_count4__50;
    DWORD e_entry_id5__01056b14;
    DWORD e_entry_count5__94;
    DWORD e_entry_id6__010e6b14;
    DWORD e_entry_count6__568;
    DWORD e_entry_id7__01046b14;
    DWORD e_entry_count7__75;
    DWORD e_entry_id8__00ff6b14;
    DWORD e_entry_count8__1;
    DWORD e_entry_id9__01026b14;
    DWORD e_entry_count9__1;
    char e_magic[0x4];
    DWORD e_checksum;
}RICH_HEADER, * PRICH_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;


#if defined(_M_MRX000) || defined(_M_ALPHA) || defined(_M_PPC) || defined(_M_IA64) || defined(_M_AMD64) || defined(_M_ARM) || defined(_M_ARM64)
#define ALIGNMENT_MACHINE
#define UNALIGNED __unaligned
#if defined(_WIN64)
#define UNALIGNED64 __unaligned
#else
#define UNALIGNED64
#endif
#else
#undef ALIGNMENT_MACHINE
#define UNALIGNED
#define UNALIGNED64
#endif

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_ROM_HEADERS
{
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
}IMAGE_ROM_HEADERS, * PIMAGE_ROM_HEADERS;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS32 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

/*//
// Section characteristics.
//
//      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
//      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
//      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
//      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // Reserved.
//      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.

#define IMAGE_SCN_LNK_OTHER                  0x00000100  // Reserved.
#define IMAGE_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
//      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
#define IMAGE_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
//                                           0x00002000  // Reserved.
//      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_GPREL                      0x00008000  // Section content can be accessed relative to GP
#define IMAGE_SCN_MEM_FARDATA                0x00008000
//      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000

#define IMAGE_SCN_ALIGN_1BYTES               0x00100000  //
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000  //
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000  //
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000  //
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000  //
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000  //
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000  //
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000  //
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000  //
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000  //
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000  //
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000  //
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000  //
// Unused                                    0x00F00000
#define IMAGE_SCN_ALIGN_MASK                 0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.

//
// TLS Characteristic Flags
//
#define IMAGE_SCN_SCALE_INDEX                0x00000001  // Tls index is scaled*/
typedef enum PE_SECTIONS_FLAGS
{
    IMAGE_SCN_RESERVED_0001 = 0x1,
    IMAGE_SCN_RESERVED_0002 = 0x2,
    IMAGE_SCN_RESERVED_0004 = 0x4,
    IMAGE_SCN_TYPE_NO_PAD = 0x8,
    IMAGE_SCN_RESERVED_0010 = 0x10,
    IMAGE_SCN_CNT_CODE = 0x20,
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80,
    IMAGE_SCN_LNK_OTHER = 0x100,
    IMAGE_SCN_LNK_INFO = 0x200,
    IMAGE_SCN_RESERVED_0400 = 0x400,
    IMAGE_SCN_LNK_REMOVE = 0x800,
    IMAGE_SCN_LNK_COMDAT = 0x1000,
    IMAGE_SCN_GPREL = 0x8000,
    IMAGE_SCN_MEM_PURGEABLE = 0x10000,
    IMAGE_SCN_MEM_16BIT = 0x20000,
    IMAGE_SCN_MEM_LOCKED = 0x40000,
    IMAGE_SCN_MEM_PRELOAD = 0x80000,
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x1000000,
    IMAGE_SCN_MEM_DISCARDABLE = 0x2000000,
    IMAGE_SCN_MEM_NOT_CACHED = 0x4000000,
    IMAGE_SCN_MEM_NOT_PAGED = 0x8000000,
    IMAGE_SCN_MEM_SHARED = 0x10000000,
    IMAGE_SCN_MEM_EXECUTE = 0x20000000,
    IMAGE_SCN_MEM_READ = 0x40000000,
    IMAGE_SCN_MEM_WRITE = 0x80000000
}PE_SECTIONS_FLAGS, * PPE_SECTIONS_FLAGS;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD   PhysicalAddress; //always virtualSize
        DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    PE_SECTIONS_FLAGS   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
    // -1 if bound, and real date\time stamp
    //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
    // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED* PIMAGE_IMPORT_DESCRIPTOR;

#define MAKEINTRESOURCEA(i) ((LPSTR)((ULONG_PTR)((WORD)(i))))

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;

typedef enum _IMPORT_OBJECT_NAME_TYPE // int32_t
{
    IMPORT_OBJECT_ORDINAL = 0x0,
    IMPORT_OBJECT_NAME = 0x1,
    IMPORT_OBJECT_NAME_NO_PREFIX = 0x2,
    IMPORT_OBJECT_NAME_UNDECORATE = 0x3,
    IMPORT_OBJECT_NAME_EXPORTAS = 0x4
}IMPORT_OBJECT_NAME_TYPE, * PIMPORT_OBJECT_NAME_TYPE;

typedef enum _IMPORT_OBJECT_TYPE // int32_t
{
    IMPORT_OBJECT_CODE = 0x0,
    IMPORT_OBJECT_DATA = 0x1,
    IMPORT_OBJECT_CONST = 0x2
}IMPORT_OBJECT_TYPE, * PIMPORT_OBJECT_TYPE;

#define IMPORT_OBJECT_HDR_SIG2  0xffff

typedef struct _IMPORT_OBJECT_HEADER
{
    USHORT Sig1;
    USHORT Sig2;
    USHORT Version;
    USHORT Machine;
    DWORD TimeDateStamp;
    DWORD SizeOfData;
    union
    {
        USHORT Ordinal;
        USHORT Hint;
    } __inner6;
    union
    {
        USHORT Type;
        USHORT NameType;
        USHORT Reserved;
    } __bitfield18;
}IMPORT_OBJECT_HEADER, * PIMPORT_OBJECT_HEADER;

//@[comment("MVI_tracked")]
typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;  // PBYTE 
        ULONGLONG Function;         // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64* PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;      // PBYTE 
        DWORD Function;             // PDWORD
        DWORD Ordinal;
        DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32* PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;         // PDWORD
    ULONGLONG AddressOfCallBacks;     // PIMAGE_TLS_CALLBACK *;
    DWORD SizeOfZeroFill;
    union {
        DWORD Characteristics;
        struct {
            DWORD Reserved0 : 20;
            DWORD Alignment : 4;
            DWORD Reserved1 : 8;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

} IMAGE_TLS_DIRECTORY64;

typedef IMAGE_TLS_DIRECTORY64* PIMAGE_TLS_DIRECTORY64;

typedef struct _IMAGE_TLS_DIRECTORY32 {
    DWORD   StartAddressOfRawData;
    DWORD   EndAddressOfRawData;
    DWORD   AddressOfIndex;             // PDWORD
    DWORD   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
    DWORD   SizeOfZeroFill;
    union {
        DWORD Characteristics;
        struct {
            DWORD Reserved0 : 20;
            DWORD Alignment : 4;
            DWORD Reserved1 : 8;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

} IMAGE_TLS_DIRECTORY32;
typedef IMAGE_TLS_DIRECTORY32* PIMAGE_TLS_DIRECTORY32;

typedef VOID(NTAPI* PIMAGE_TLS_CALLBACK) (
    PVOID DllHandle,
    DWORD Reason,
    PVOID Reserved
    );

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_5    5
#define IMAGE_REL_BASED_RESERVED              6
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_7    7
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_8    8
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_9    9
#define IMAGE_REL_BASED_DIR64                 10

typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
    //  WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED* PIMAGE_BASE_RELOCATION;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

#ifdef _WIN64
typedef IMAGE_NT_HEADERS64                 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64                PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER64            IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64           PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC        IMAGE_NT_OPTIONAL_HDR64_MAGIC

#define IMAGE_ORDINAL_FLAG                 IMAGE_ORDINAL_FLAG64
#define IMAGE_ORDINAL(Ordinal)             IMAGE_ORDINAL64(Ordinal)
typedef IMAGE_THUNK_DATA64                 IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA64                PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)     IMAGE_SNAP_BY_ORDINAL64(Ordinal)
typedef IMAGE_TLS_DIRECTORY64              IMAGE_TLS_DIRECTORY;
typedef PIMAGE_TLS_DIRECTORY64             PIMAGE_TLS_DIRECTORY;

#else
typedef IMAGE_NT_HEADERS32                 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32                PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER32            IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32           PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC        IMAGE_NT_OPTIONAL_HDR32_MAGIC

#define IMAGE_ORDINAL_FLAG                 IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL(Ordinal)             IMAGE_ORDINAL32(Ordinal)
typedef IMAGE_THUNK_DATA32                 IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA32                PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)     IMAGE_SNAP_BY_ORDINAL32(Ordinal)
typedef IMAGE_TLS_DIRECTORY32              IMAGE_TLS_DIRECTORY;
typedef PIMAGE_TLS_DIRECTORY32             PIMAGE_TLS_DIRECTORY;
#endif

typedef enum _DEBUG_DIRECTORY_TABLE_TYPE
{
    IMAGE_DEBUG_TYPE_UNKNOWN = 0x0,
    IMAGE_DEBUG_TYPE_COFF = 0x1,
    IMAGE_DEBUG_TYPE_CODEVIEW = 0x2,
    IMAGE_DEBUG_TYPE_FPO = 0x3,
    IMAGE_DEBUG_TYPE_MISC = 0x4,
    IMAGE_DEBUG_TYPE_EXCEPTION = 0x5,
    IMAGE_DEBUG_TYPE_FIXUP = 0x6,
    IMAGE_DEBUG_TYPE_OMAP_TO_SRC = 0x7,
    IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 0x8,
    IMAGE_DEBUG_TYPE_BORLAND = 0x9,
    IMAGE_DEBUG_TYPE_RESERVED10 = 0xa,
    IMAGE_DEBUG_TYPE_CLSID = 0xb,
    IMAGE_DEBUG_TYPE_VC_FEATURE = 0xc,
    IMAGE_DEBUG_TYPE_POGO = 0xd,
    IMAGE_DEBUG_TYPE_ILTCG = 0xe,
    IMAGE_DEBUG_TYPE_MPX = 0xf
} DEBUG_DIRECTORY_TABLE_TYPE, * PDEBUG_DIRECTORY_TABLE_TYPE;

typedef struct _DEBUG_DIRECTORY_TABLE
{
    DWORD characteristics;
    DWORD timeDateStamp;
    WORD majorVersion;
    WORD minorVersion;
    DEBUG_DIRECTORY_TABLE_TYPE Type;//DWORD
    DWORD sizeOfData;
    DWORD addressOfRawData;
    DWORD pointerToRawData;
}DEBUG_DIRECTORY_TABLE, * PDEBUG_DIRECTORY_TABLE;

typedef struct _EXCEPTION_DIRECTORY_ENTRY
{
    DWORD beginAddress;
    DWORD endAddress;
    DWORD unwindInformation;  //?UNWIND_INFO
}EXCEPTION_DIRECTORY_ENTRY, * PEXCEPTION_DIRECTORY_ENTRY;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY
{
    DWORD BeginAddress;
    DWORD EndAddress;
    union
    {
        DWORD UnwindInfoAddress;
        DWORD UnwindData;
    } __inner2;
}IMAGE_RUNTIME_FUNCTION_ENTRY, * PIMAGE_RUNTIME_FUNCTION_ENTRY;

typedef enum _UNWIND_OP_CODES // int32_t
{
    UWOP_PUSH_NONVOL = 0x0,
    UWOP_ALLOC_LARGE = 0x1,
    UWOP_ALLOC_SMALL = 0x2,
    UWOP_SET_FPREG = 0x3,
    UWOP_SAVE_NONVOL = 0x4,
    UWOP_SAVE_NONVOL_FAR = 0x5,
    UWOP_EPILOG = 0x6,
    UWOP_SPARE_CODE = 0x7,
    UWOP_SAVE_XMM128 = 0x8,
    UWOP_SAVE_XMM128_FAR = 0x9,
    UWOP_PUSH_MACHFRAME = 0xa
}UNWIND_OP_CODES, * PUNWIND_OP_CODES;

typedef struct _UNWIND_INFO
{
    UCHAR VersionAndFlag;
    UCHAR SizeOfProlog;
    UCHAR CountOfUnwindCodes;
    UCHAR FrameRegisterAndFrameRegisterOffset;
}UNWIND_INFO, * PUNWIND_INFO;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY
{
    PVOID ImageBase;
    IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionEntry;
}UNWIND_HISTORY_TABLE_ENTRY, * PUNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE
{
    DWORD Count;
    UCHAR LocalHint;
    UCHAR GlobalHint;
    UCHAR Search;
    UCHAR Once;
    QWORD LowAddress;
    QWORD HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[0xc];
}UNWIND_HISTORY_TABLE, * PUNWIND_HISTORY_TABLE;

typedef struct _DELAY_IMPORT_DIRECTORY
{
    DWORD attributes;
    DWORD name;
    DWORD moduleHandle;
    DWORD delayImportAddressTable;
    DWORD delayImportNameTable;
    DWORD boundDelayImportTable;
    DWORD unloadDelayImportTable;
    DWORD timestamp;
}DELAY_IMPORT_DIRECTORY, * PDELAY_IMPORT_DIRECTORY;

typedef struct GUARD_CONTROL_FLOW_FUNCTION_TABLE
{
    /*    uint32_t rvAddr;
    uint8_t metadata;*/
    DWORD rvAddr;
    UCHAR metadata;
}GUARD_CONTROL_FLOW_FUNCTION_TABLE, * PGUARD_CONTROL_FLOW_FUNCTION_TABLE;

typedef struct _IMAGE_SECURITY_CONTEXT
{
    union
    {
        PVOID PageHashes;
        QWORD Value;
        union
        {
            QWORD SecurityBeingCreated;
            QWORD SecurityMandatory;
            QWORD PageHashPointer;
        } __bitfield0;
    } __inner0;
}IMAGE_SECURITY_CONTEXT, * PIMAGE_SECURITY_CONTEXT;

typedef struct _IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY
{
    QWORD BeginAddress;
    QWORD EndAddress;
    QWORD ExceptionHandler;
    QWORD HandlerData;
    QWORD PrologEndAddress;
}IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY, * PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY
{
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD ExceptionHandler;
    DWORD HandlerData;
    DWORD PrologEndAddress;
}IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY, * PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY;

typedef union _IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA
{
    DWORD HeaderData;
    DWORD FunctionLength;
    DWORD Version;
    DWORD ExceptionDataPresent;
    DWORD EpilogInHeader;
    DWORD EpilogCount;
    DWORD CodeWords;
}IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA, * PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA;

typedef struct _IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY
{
    DWORD BeginAddress;
    union
    {
        DWORD UnwindData;
        union
        {
            DWORD Flag;
            DWORD FunctionLength;
            DWORD RegF;
            DWORD RegI;
            DWORD H;
            DWORD CR;
            DWORD FrameSize;
        } __bitfield4;
    } __inner1;
}IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY, * PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_ARM_RUNTIME_FUNCTION_ENTRY
{
    DWORD BeginAddress;
    union
    {
        DWORD UnwindData;
        union
        {
            DWORD Flag;
            DWORD FunctionLength;
            DWORD Ret;
            DWORD H;
            DWORD Reg;
            DWORD R;
            DWORD L;
            DWORD C;
            DWORD StackAdjust;
        } __bitfield4;
    } __inner1;
}IMAGE_ARM_RUNTIME_FUNCTION_ENTRY, * PIMAGE_ARM_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_AUX_SYMBOL_TOKEN_DEF
{
    UCHAR bAuxType;
    UCHAR bReserved;
    //__offset(0x2);
    DWORD SymbolTableIndex;
    UCHAR rgbReserved[0xc];
}IMAGE_AUX_SYMBOL_TOKEN_DEF, * PIMAGE_AUX_SYMBOL_TOKEN_DEF;

typedef union _IMAGE_AUX_SYMBOL
{
    struct
    {
        DWORD TagIndex;
        union
        {
            struct
            {
                WORD Linenumber;
                WORD Size;
            } LnSz;
            DWORD TotalSize;
        } Misc;
        union
        {
            struct
            {
                DWORD PointerToLinenumber;
                DWORD PointerToNextFunction;
            } Function;
            struct
            {
                WORD Dimension[0x4];
            } Array;
        } FcnAry;
        WORD TvIndex;
    } Sym;
    struct
    {
        UCHAR Name[0x12];
    } File;
    struct
    {
        DWORD Length;
        WORD NumberOfRelocations;
        WORD NumberOfLinenumbers;
        DWORD CheckSum;
        SHORT Number;
        UCHAR Selection;
        UCHAR bReserved;
        SHORT HighNumber;
    } Section;
    IMAGE_AUX_SYMBOL_TOKEN_DEF TokenDef;
    struct
    {
        DWORD crc;
        UCHAR rgbReserved[0xe];
    } CRC;
}IMAGE_AUX_SYMBOL, * PIMAGE_AUX_SYMBOL;

typedef union _IMAGE_AUX_SYMBOL_EX
{
    struct
    {
        DWORD WeakDefaultSymIndex;
        DWORD WeakSearchType;
        UCHAR rgbReserved[0xc];
    } Sym;
    struct
    {
        UCHAR Name[0x14];
    } File;
    struct
    {
        DWORD Length;
        WORD NumberOfRelocations;
        WORD NumberOfLinenumbers;
        DWORD CheckSum;
        SHORT Number;
        UCHAR Selection;
        UCHAR bReserved;
        SHORT HighNumber;
        UCHAR rgbReserved[0x2];
    } Section;
    struct
    {
        IMAGE_AUX_SYMBOL_TOKEN_DEF TokenDef;
        UCHAR rgbReserved[0x2];
    } __inner3;
    struct
    {
        DWORD crc;
        UCHAR rgbReserved[0x10];
    } CRC;
}IMAGE_AUX_SYMBOL_EX, * PIMAGE_AUX_SYMBOL_EX;

typedef struct _IMAGE_BOUND_FORWARDER_REF
{
    DWORD TimeDateStamp;
    WORD OffsetModuleName;
    WORD Reserved;
}IMAGE_BOUND_FORWARDER_REF, * PIMAGE_BOUND_FORWARDER_REF;

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR
{
    DWORD TimeDateStamp;
    WORD OffsetModuleName;
    WORD NumberOfModuleForwarderRefs;
}IMAGE_BOUND_IMPORT_DESCRIPTOR, * PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_CE_RUNTIME_FUNCTION_ENTRY
{
    DWORD FuncStart;
    union
    {
        DWORD PrologLen;
        DWORD FuncLen;
        DWORD ThirtyTwoBit;
        DWORD ExceptionFlag;
    } __bitfield4;
}IMAGE_CE_RUNTIME_FUNCTION_ENTRY, * PIMAGE_CE_RUNTIME_FUNCTION_ENTRY;

#define IMAGE_DEBUG_TYPE_UNKNOWN                0
#define IMAGE_DEBUG_TYPE_COFF                   1
#define IMAGE_DEBUG_TYPE_CODEVIEW               2
#define IMAGE_DEBUG_TYPE_FPO                    3
#define IMAGE_DEBUG_TYPE_MISC                   4
#define IMAGE_DEBUG_TYPE_EXCEPTION              5
#define IMAGE_DEBUG_TYPE_FIXUP                  6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC            7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC          8
#define IMAGE_DEBUG_TYPE_BORLAND                9
#define IMAGE_DEBUG_TYPE_RESERVED10             10
#define IMAGE_DEBUG_TYPE_BBT                    IMAGE_DEBUG_TYPE_RESERVED10
#define IMAGE_DEBUG_TYPE_CLSID                  11
#define IMAGE_DEBUG_TYPE_VC_FEATURE             12
#define IMAGE_DEBUG_TYPE_POGO                   13
#define IMAGE_DEBUG_TYPE_ILTCG                  14
#define IMAGE_DEBUG_TYPE_MPX                    15
#define IMAGE_DEBUG_TYPE_REPRO                  16
#define IMAGE_DEBUG_TYPE_SPGO                   18
#define IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS  20

typedef struct _IMAGE_DEBUG_DIRECTORY
{
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Type;
    DWORD SizeOfData;
    DWORD AddressOfRawData;
    DWORD PointerToRawData;
}IMAGE_DEBUG_DIRECTORY, * PIMAGE_DEBUG_DIRECTORY;

#define IMAGE_DEBUG_MISC_EXENAME    1

typedef struct _IMAGE_DEBUG_MISC
{
    DWORD DataType;
    DWORD Length;
    UCHAR Unicode;
    UCHAR Reserved[0x3];
    UCHAR Data[0x1];
}IMAGE_DEBUG_MISC, * PIMAGE_DEBUG_MISC;

typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR
{
    union
    {
        DWORD AllAttributes;
        DWORD RvaBased;
        DWORD ReservedAttributes;
    } Attributes;
    DWORD DllNameRVA;
    DWORD ModuleHandleRVA;
    DWORD ImportAddressTableRVA;
    DWORD ImportNameTableRVA;
    DWORD BoundImportAddressTableRVA;
    DWORD UnloadInformationTableRVA;
    DWORD TimeDateStamp;
}IMAGE_DELAYLOAD_DESCRIPTOR, * PIMAGE_DELAYLOAD_DESCRIPTOR;

typedef struct _IMAGE_DYNAMIC_RELOCATION32
{
    DWORD Symbol;
    DWORD BaseRelocSize;
}IMAGE_DYNAMIC_RELOCATION32, * PIMAGE_DYNAMIC_RELOCATION32;

typedef struct _IMAGE_DYNAMIC_RELOCATION32_V2
{
    DWORD HeaderSize;
    DWORD FixupInfoSize;
    DWORD Symbol;
    DWORD SymbolGroup;
    DWORD Flags;
}IMAGE_DYNAMIC_RELOCATION32_V2, * PIMAGE_DYNAMIC_RELOCATION32_V2;

typedef struct _IMAGE_DYNAMIC_RELOCATION64
{
    QWORD Symbol;
    DWORD BaseRelocSize;
}IMAGE_DYNAMIC_RELOCATION64, * PIMAGE_DYNAMIC_RELOCATION64;

typedef struct _IMAGE_DYNAMIC_RELOCATION64_V2
{
    DWORD HeaderSize;
    DWORD FixupInfoSize;
    QWORD Symbol;
    DWORD SymbolGroup;
    DWORD Flags;
}IMAGE_DYNAMIC_RELOCATION64_V2, * PIMAGE_DYNAMIC_RELOCATION64_V2;

typedef struct _IMAGE_DYNAMIC_RELOCATION_TABLE
{
    DWORD Version;
    DWORD Size;
}IMAGE_DYNAMIC_RELOCATION_TABLE, * PIMAGE_DYNAMIC_RELOCATION_TABLE;

typedef struct _IMAGE_ENCLAVE_CONFIG32
{
    DWORD Size;
    DWORD MinimumRequiredConfigSize;
    DWORD PolicyFlags;
    DWORD NumberOfImports;
    DWORD ImportList;
    DWORD ImportEntrySize;
    UCHAR FamilyID[0x10];
    UCHAR ImageID[0x10];
    DWORD ImageVersion;
    DWORD SecurityVersion;
    DWORD EnclaveSize;
    DWORD NumberOfThreads;
    DWORD EnclaveFlags;
}IMAGE_ENCLAVE_CONFIG32, * PIMAGE_ENCLAVE_CONFIG32;

typedef struct _IMAGE_ENCLAVE_CONFIG64
{
    DWORD Size;
    DWORD MinimumRequiredConfigSize;
    DWORD PolicyFlags;
    DWORD NumberOfImports;
    DWORD ImportList;
    DWORD ImportEntrySize;
    UCHAR FamilyID[0x10];
    UCHAR ImageID[0x10];
    DWORD ImageVersion;
    DWORD SecurityVersion;
    QWORD EnclaveSize;
    DWORD NumberOfThreads;
    DWORD EnclaveFlags;
}IMAGE_ENCLAVE_CONFIG64, * PIMAGE_ENCLAVE_CONFIG64;

#define IMAGE_ENCLAVE_POLICY_DEBUGGABLE     0x00000001
#define IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE    0x00000001

#define IMAGE_ENCLAVE_IMPORT_MATCH_NONE             0x00000000
#define IMAGE_ENCLAVE_IMPORT_MATCH_UNIQUE_ID        0x00000001
#define IMAGE_ENCLAVE_IMPORT_MATCH_AUTHOR_ID        0x00000002
#define IMAGE_ENCLAVE_IMPORT_MATCH_FAMILY_ID        0x00000003
#define IMAGE_ENCLAVE_IMPORT_MATCH_IMAGE_ID         0x00000004

typedef struct _IMAGE_ENCLAVE_IMPORT
{
    DWORD MatchType;
    DWORD MinimumSecurityVersion;
    UCHAR UniqueOrAuthorID[0x20];
    UCHAR FamilyID[0x10];
    UCHAR ImageID[0x10];
    DWORD ImportName;
    DWORD Reserved;
}IMAGE_ENCLAVE_IMPORT, * PIMAGE_ENCLAVE_IMPORT;

typedef struct _IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER
{
    DWORD EpilogueCount;
    UCHAR EpilogueByteCount;
    UCHAR BranchDescriptorElementSize;
    WORD BranchDescriptorCount;
}IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER, * PIMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER;

typedef struct _IMAGE_FUNCTION_ENTRY
{
    DWORD StartingAddress;
    DWORD EndingAddress;
    DWORD EndOfPrologue;
}IMAGE_FUNCTION_ENTRY, * PIMAGE_FUNCTION_ENTRY;

typedef struct _IMAGE_FUNCTION_ENTRY64
{
    QWORD StartingAddress;
    QWORD EndingAddress;
    union
    {
        QWORD EndOfPrologue;
        QWORD UnwindInfoAddress;
    } __inner2;
}IMAGE_FUNCTION_ENTRY64, * PIMAGE_FUNCTION_ENTRY64;

typedef struct _IMAGE_HOT_PATCH_BASE
{
    DWORD SequenceNumber;
    DWORD Flags;
    DWORD OriginalTimeDateStamp;
    DWORD OriginalCheckSum;
    DWORD CodeIntegrityInfo;
    DWORD CodeIntegritySize;
    DWORD PatchTable;
    DWORD BufferOffset;
}IMAGE_HOT_PATCH_BASE, * PIMAGE_HOT_PATCH_BASE;

typedef struct _IMAGE_HOT_PATCH_HASHES
{
    UCHAR SHA256[0x20];
    UCHAR SHA1[0x14];
}IMAGE_HOT_PATCH_HASHES, * PIMAGE_HOT_PATCH_HASHES;

typedef struct _IMAGE_HOT_PATCH_INFO
{
    DWORD Version;
    DWORD Size;
    DWORD SequenceNumber;
    DWORD BaseImageList;
    DWORD BaseImageCount;
    DWORD BufferOffset;
    DWORD ExtraPatchSize;
}IMAGE_HOT_PATCH_INFO, * PIMAGE_HOT_PATCH_INFO;

typedef struct _IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION
{
    union
    {
        DWORD PageRelativeOffset;
        DWORD IndirectCall;
        DWORD IATIndex;
    } __bitfield0;
}IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION, * PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION;

typedef struct _IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION
{
    union
    {
        WORD PageRelativeOffset;
        WORD IndirectCall;
        WORD RexWPrefix;
        WORD CfgCheck;
        DWORD Reserved;
    } __bitfield0;
}IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION, * PIMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION;

typedef struct _IMAGE_LINENUMBER
{
    union
    {
        DWORD SymbolTableIndex;
        DWORD VirtualAddress;
    } Type;
    WORD Linenumber;
}IMAGE_LINENUMBER, * PIMAGE_LINENUMBER;

#define IMAGE_HOT_PATCH_BASE_OBLIGATORY     0x00000001
#define IMAGE_HOT_PATCH_BASE_CAN_ROLL_BACK  0x00000002

#define IMAGE_HOT_PATCH_CHUNK_INVERSE       0x80000000
#define IMAGE_HOT_PATCH_CHUNK_OBLIGATORY    0x40000000
#define IMAGE_HOT_PATCH_CHUNK_RESERVED      0x3FF03000
#define IMAGE_HOT_PATCH_CHUNK_TYPE          0x000FC000
#define IMAGE_HOT_PATCH_CHUNK_SOURCE_RVA    0x00008000
#define IMAGE_HOT_PATCH_CHUNK_TARGET_RVA    0x00004000
#define IMAGE_HOT_PATCH_CHUNK_SIZE          0x00000FFF

#define IMAGE_HOT_PATCH_NONE                0x00000000
#define IMAGE_HOT_PATCH_FUNCTION            0x0001C000
#define IMAGE_HOT_PATCH_ABSOLUTE            0x0002C000
#define IMAGE_HOT_PATCH_REL32               0x0003C000
#define IMAGE_HOT_PATCH_CALL_TARGET         0x00044000
#define IMAGE_HOT_PATCH_INDIRECT            0x0005C000
#define IMAGE_HOT_PATCH_NO_CALL_TARGET      0x00064000
#define IMAGE_HOT_PATCH_DYNAMIC_VALUE       0x00078000

#define IMAGE_GUARD_CF_INSTRUMENTED                    0x00000100 // Module performs control flow integrity checks using system-supplied support
#define IMAGE_GUARD_CFW_INSTRUMENTED                   0x00000200 // Module performs control flow and write integrity checks
#define IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT          0x00000400 // Module contains valid control flow target metadata
#define IMAGE_GUARD_SECURITY_COOKIE_UNUSED             0x00000800 // Module does not make use of the /GS security cookie
#define IMAGE_GUARD_PROTECT_DELAYLOAD_IAT              0x00001000 // Module supports read only delay load IAT
#define IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION   0x00002000 // Delayload import table in its own .didat section (with nothing else in it) that can be freely reprotected
#define IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT 0x00004000 // Module contains suppressed export information. This also infers that the address taken
// taken IAT table is also present in the load config.
#define IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION       0x00008000 // Module enables suppression of exports
#define IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT          0x00010000 // Module contains longjmp target information
#define IMAGE_GUARD_RF_INSTRUMENTED                    0x00020000 // Module contains return flow instrumentation and metadata
#define IMAGE_GUARD_RF_ENABLE                          0x00040000 // Module requests that the OS enable return flow protection
#define IMAGE_GUARD_RF_STRICT                          0x00080000 // Module requests that the OS enable return flow protection in strict mode
#define IMAGE_GUARD_RETPOLINE_PRESENT                  0x00100000 // Module was built with retpoline support
// DO_NOT_USE                                          0x00200000 // Was EHCont flag on VB (20H1)
#define IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT      0x00400000 // Module contains EH continuation target information
#define IMAGE_GUARD_XFG_ENABLED                        0x00800000 // Module was built with xfg
#define IMAGE_GUARD_CASTGUARD_PRESENT                  0x01000000 // Module has CastGuard instrumentation present
#define IMAGE_GUARD_MEMCPY_PRESENT                     0x02000000 // Module has Guarded Memcpy instrumentation present

#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK        0xF0000000 // Stride of Guard CF function table encoded in these bits (additional count of bytes per element)
#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT       28         // Shift to right-justify Guard CF function table stride

//
// GFIDS table entry flags.
//

#define IMAGE_GUARD_FLAG_FID_SUPPRESSED               0x01       // The containing GFID entry is suppressed
#define IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED            0x02       // The containing GFID entry is export suppressed
#define IMAGE_GUARD_FLAG_FID_LANGEXCPTHANDLER         0x04
#define IMAGE_GUARD_FLAG_FID_XFG                      0x08

typedef struct _IMAGE_LOAD_CONFIG_CODE_INTEGRITY
{
    WORD Flags;
    WORD Catalog;
    DWORD CatalogOffset;
    DWORD Reserved;
}IMAGE_LOAD_CONFIG_CODE_INTEGRITY, * PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY32
{
    DWORD Size;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD GlobalFlagsClear;
    DWORD GlobalFlagsSet;
    DWORD CriticalSectionDefaultTimeout;
    DWORD DeCommitFreeBlockThreshold;
    DWORD DeCommitTotalFreeThreshold;
    DWORD LockPrefixTable;
    DWORD MaximumAllocationSize;
    DWORD VirtualMemoryThreshold;
    DWORD ProcessHeapFlags;
    DWORD ProcessAffinityMask;
    WORD CSDVersion;
    WORD DependentLoadFlags;
    DWORD EditList;
    DWORD SecurityCookie;
    DWORD SEHandlerTable;
    DWORD SEHandlerCount;
    DWORD GuardCFCheckFunctionPointer;
    DWORD GuardCFDispatchFunctionPointer;
    DWORD GuardCFFunctionTable;
    DWORD GuardCFFunctionCount;
    DWORD GuardFlags;
    IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    DWORD GuardAddressTakenIatEntryTable;
    DWORD GuardAddressTakenIatEntryCount;
    DWORD GuardLongJumpTargetTable;
    DWORD GuardLongJumpTargetCount;
    DWORD DynamicValueRelocTable;
    DWORD CHPEMetadataPointer;
    DWORD GuardRFFailureRoutine;
    DWORD GuardRFFailureRoutineFunctionPointer;
    DWORD DynamicValueRelocTableOffset;
    WORD DynamicValueRelocTableSection;
    WORD Reserved2;
    DWORD GuardRFVerifyStackPointerFunctionPointer;
    DWORD HotPatchTableOffset;
    DWORD Reserved3;
    DWORD EnclaveConfigurationPointer;
    DWORD VolatileMetadataPointer;
    DWORD GuardEHContinuationTable;
    DWORD GuardEHContinuationCount;
}IMAGE_LOAD_CONFIG_DIRECTORY32, * PIMAGE_LOAD_CONFIG_DIRECTORY32;

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY64
{
    DWORD Size;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD GlobalFlagsClear;
    DWORD GlobalFlagsSet;
    DWORD CriticalSectionDefaultTimeout;
    QWORD DeCommitFreeBlockThreshold;
    QWORD DeCommitTotalFreeThreshold;
    QWORD LockPrefixTable;
    QWORD MaximumAllocationSize;
    QWORD VirtualMemoryThreshold;
    QWORD ProcessAffinityMask;
    DWORD ProcessHeapFlags;
    WORD CSDVersion;
    WORD DependentLoadFlags;
    QWORD EditList;
    QWORD SecurityCookie;
    QWORD SEHandlerTable;
    QWORD SEHandlerCount;
    QWORD GuardCFCheckFunctionPointer;
    QWORD GuardCFDispatchFunctionPointer;
    QWORD GuardCFFunctionTable;
    QWORD GuardCFFunctionCount;
    DWORD GuardFlags;
    IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    QWORD GuardAddressTakenIatEntryTable;
    QWORD GuardAddressTakenIatEntryCount;
    QWORD GuardLongJumpTargetTable;
    QWORD GuardLongJumpTargetCount;
    QWORD DynamicValueRelocTable;
    QWORD CHPEMetadataPointer;
    QWORD GuardRFFailureRoutine;
    QWORD GuardRFFailureRoutineFunctionPointer;
    DWORD DynamicValueRelocTableOffset;
    WORD DynamicValueRelocTableSection;
    WORD Reserved2;
    QWORD GuardRFVerifyStackPointerFunctionPointer;
    DWORD HotPatchTableOffset;
    DWORD Reserved3;
    QWORD EnclaveConfigurationPointer;
    QWORD VolatileMetadataPointer;
    QWORD GuardEHContinuationTable;
    QWORD GuardEHContinuationCount;
}IMAGE_LOAD_CONFIG_DIRECTORY64, * PIMAGE_LOAD_CONFIG_DIRECTORY64;

typedef enum _IMAGE_MITIGATION_POLICY// int32_t
{
    ImageDepPolicy = 0x0,
    ImageAslrPolicy = 0x1,
    ImageDynamicCodePolicy = 0x2,
    ImageStrictHandleCheckPolicy = 0x3,
    ImageSystemCallDisablePolicy = 0x4,
    ImageMitigationOptionsMask = 0x5,
    ImageExtensionPointDisablePolicy = 0x6,
    ImageControlFlowGuardPolicy = 0x7,
    ImageSignaturePolicy = 0x8,
    ImageFontDisablePolicy = 0x9,
    ImageImageLoadPolicy = 0xa,
    ImagePayloadRestrictionPolicy = 0xb,
    ImageChildProcessPolicy = 0xc,
    ImageSehopPolicy = 0xd,
    ImageHeapPolicy = 0xe,
    ImageUserShadowStackPolicy = 0xf,
    MaxImageMitigationPolicy = 0x10
}IMAGE_MITIGATION_POLICY, * PIMAGE_MITIGATION_POLICY;

typedef enum _IMAGE_POLICY_ENTRY_TYPE // int32_t
{
    ImagePolicyEntryTypeNone = 0x0,
    ImagePolicyEntryTypeBool = 0x1,
    ImagePolicyEntryTypeInt8 = 0x2,
    ImagePolicyEntryTypeUInt8 = 0x3,
    ImagePolicyEntryTypeInt16 = 0x4,
    ImagePolicyEntryTypeUInt16 = 0x5,
    ImagePolicyEntryTypeInt32 = 0x6,
    ImagePolicyEntryTypeUInt32 = 0x7,
    ImagePolicyEntryTypeInt64 = 0x8,
    ImagePolicyEntryTypeUInt64 = 0x9,
    ImagePolicyEntryTypeAnsiString = 0xa,
    ImagePolicyEntryTypeUnicodeString = 0xb,
    ImagePolicyEntryTypeOverride = 0xc,
    ImagePolicyEntryTypeMaximum = 0xd
}IMAGE_POLICY_ENTRY_TYPE, * PIMAGE_POLICY_ENTRY_TYPE;

typedef enum _IMAGE_POLICY_ID // int32_t
{
    ImagePolicyIdNone = 0x0,
    ImagePolicyIdEtw = 0x1,
    ImagePolicyIdDebug = 0x2,
    ImagePolicyIdCrashDump = 0x3,
    ImagePolicyIdCrashDumpKey = 0x4,
    ImagePolicyIdCrashDumpKeyGuid = 0x5,
    ImagePolicyIdParentSd = 0x6,
    ImagePolicyIdParentSdRev = 0x7,
    ImagePolicyIdSvn = 0x8,
    ImagePolicyIdDeviceId = 0x9,
    ImagePolicyIdCapability = 0xa,
    ImagePolicyIdScenarioId = 0xb,
    ImagePolicyIdMaximum = 0xc
}IMAGE_POLICY_ID, * PIMAGE_POLICY_ID;

typedef struct _IMAGE_POLICY_ENTRY
{
    IMAGE_POLICY_ENTRY_TYPE Type;
    IMAGE_POLICY_ID PolicyId;
    union
    {
        void const* None;
        UCHAR BoolValue;
        char Int8Value;
        UCHAR UInt8Value;
        SHORT Int16Value;
        WORD UInt16Value;
        LONG Int32Value;
        DWORD UInt32Value;
        __int64 Int64Value;
        QWORD UInt64Value;
        char const* AnsiStringValue;
        PWSTR const* UnicodeStringValue;
    } u;
}IMAGE_POLICY_ENTRY, * PIMAGE_POLICY_ENTRY;

typedef struct _IMAGE_POLICY_METADATA
{
    UCHAR Version;
    UCHAR Reserved0[0x7];
    QWORD ApplicationId;
    struct _IMAGE_POLICY_ENTRY Policies[0x0];
}IMAGE_POLICY_METADATA, * PIMAGE_POLICY_METADATA;

typedef struct _IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER
{
    UCHAR PrologueByteCount;
}IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER, * PIMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER;

typedef struct _IMAGE_RELOCATION
{
    union
    {
        DWORD VirtualAddress;
        DWORD RelocCount;
    } __inner0;
    DWORD SymbolTableIndex;
    WORD Type;
}IMAGE_RELOCATION, * PIMAGE_RELOCATION;

typedef struct _IMAGE_RESOURCE_DATA_ENTRY
{
    DWORD OffsetToData;
    DWORD Size;
    DWORD CodePage;
    DWORD Reserved;
}IMAGE_RESOURCE_DATA_ENTRY, * PIMAGE_RESOURCE_DATA_ENTRY;

typedef struct _IMAGE_RESOURCE_DIRECTORY
{
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    WORD NumberOfNamedEntries;
    WORD NumberOfIdEntries;
}IMAGE_RESOURCE_DIRECTORY, * PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            DWORD NameOffset : 31;
            DWORD NameIsString : 1;
        } DUMMYSTRUCTNAME;
        DWORD   Name;
        WORD    Id;
    } DUMMYUNIONNAME;
    union {
        DWORD   OffsetToData;
        struct {
            DWORD   OffsetToDirectory : 31;
            DWORD   DataIsDirectory : 1;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
} IMAGE_RESOURCE_DIRECTORY_ENTRY, * PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING
{
    WORD Length;
    char NameString[0x1];
}IMAGE_RESOURCE_DIRECTORY_STRING, * PIMAGE_RESOURCE_DIRECTORY_STRING;

typedef struct _IMAGE_RESOURCE_DIR_STRING_U
{
    WORD Length;
    UCHAR NameString[0x1];
}IMAGE_RESOURCE_DIR_STRING_U, * PIMAGE_RESOURCE_DIR_STRING_U;

typedef struct _NON_PAGED_DEBUG_INFO {
    WORD        Signature;
    WORD        Flags;
    DWORD       Size;
    WORD        Machine;
    WORD        Characteristics;
    DWORD       TimeDateStamp;
    DWORD       CheckSum;
    DWORD       SizeOfImage;
    ULONGLONG   ImageBase;
    //DebugDirectorySize
    //IMAGE_DEBUG_DIRECTORY
} NON_PAGED_DEBUG_INFO, * PNON_PAGED_DEBUG_INFO;

#define IMAGE_SEPARATE_DEBUG_FLAGS_MASK 0x8000
#define IMAGE_SEPARATE_DEBUG_MISMATCH   0x8000  // when DBG was updated, the old checksum didn't match.

typedef struct _IMAGE_SEPARATE_DEBUG_HEADER
{
    WORD Signature;
    WORD Flags;
    WORD Machine;
    WORD Characteristics;
    DWORD TimeDateStamp;
    DWORD CheckSum;
    DWORD ImageBase;
    DWORD SizeOfImage;
    DWORD NumberOfSections;
    DWORD ExportedNamesSize;
    DWORD DebugDirectorySize;
    DWORD SectionAlignment;
    DWORD Reserved[0x2];
}IMAGE_SEPARATE_DEBUG_HEADER, * PIMAGE_SEPARATE_DEBUG_HEADER;

typedef struct _IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION
{
    union
    {
        WORD PageRelativeOffset;
        WORD RegisterNumber;
    } __bitfield0;
}IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION, * PIMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION;

#define IMAGE_SYM_UNDEFINED           (SHORT)0          // Symbol is undefined or is common.
#define IMAGE_SYM_ABSOLUTE            (SHORT)-1         // Symbol is an absolute value.
#define IMAGE_SYM_DEBUG               (SHORT)-2         // Symbol is a special debug item.
#define IMAGE_SYM_SECTION_MAX         0xFEFF            // Values 0xFF00-0xFFFF are special
#define IMAGE_SYM_SECTION_MAX_EX      MAXLONG

#define IMAGE_SYM_TYPE_NULL                 0x0000  // no type.
#define IMAGE_SYM_TYPE_VOID                 0x0001  //
#define IMAGE_SYM_TYPE_CHAR                 0x0002  // type character.
#define IMAGE_SYM_TYPE_SHORT                0x0003  // type short integer.
#define IMAGE_SYM_TYPE_INT                  0x0004  //
#define IMAGE_SYM_TYPE_LONG                 0x0005  //
#define IMAGE_SYM_TYPE_FLOAT                0x0006  //
#define IMAGE_SYM_TYPE_DOUBLE               0x0007  //
#define IMAGE_SYM_TYPE_STRUCT               0x0008  //
#define IMAGE_SYM_TYPE_UNION                0x0009  //
#define IMAGE_SYM_TYPE_ENUM                 0x000A  // enumeration.
#define IMAGE_SYM_TYPE_MOE                  0x000B  // member of enumeration.
#define IMAGE_SYM_TYPE_BYTE                 0x000C  //
#define IMAGE_SYM_TYPE_WORD                 0x000D  //
#define IMAGE_SYM_TYPE_UINT                 0x000E  //
#define IMAGE_SYM_TYPE_DWORD                0x000F  //
#define IMAGE_SYM_TYPE_PCODE                0x8000  //

#define IMAGE_SYM_DTYPE_NULL                0       // no derived type.
#define IMAGE_SYM_DTYPE_POINTER             1       // pointer.
#define IMAGE_SYM_DTYPE_FUNCTION            2       // function.
#define IMAGE_SYM_DTYPE_ARRAY               3       // array.

#define IMAGE_SYM_CLASS_END_OF_FUNCTION     (BYTE )-1
#define IMAGE_SYM_CLASS_NULL                0x0000
#define IMAGE_SYM_CLASS_AUTOMATIC           0x0001
#define IMAGE_SYM_CLASS_EXTERNAL            0x0002
#define IMAGE_SYM_CLASS_STATIC              0x0003
#define IMAGE_SYM_CLASS_REGISTER            0x0004
#define IMAGE_SYM_CLASS_EXTERNAL_DEF        0x0005
#define IMAGE_SYM_CLASS_LABEL               0x0006
#define IMAGE_SYM_CLASS_UNDEFINED_LABEL     0x0007
#define IMAGE_SYM_CLASS_MEMBER_OF_STRUCT    0x0008
#define IMAGE_SYM_CLASS_ARGUMENT            0x0009
#define IMAGE_SYM_CLASS_STRUCT_TAG          0x000A
#define IMAGE_SYM_CLASS_MEMBER_OF_UNION     0x000B
#define IMAGE_SYM_CLASS_UNION_TAG           0x000C
#define IMAGE_SYM_CLASS_TYPE_DEFINITION     0x000D
#define IMAGE_SYM_CLASS_UNDEFINED_STATIC    0x000E
#define IMAGE_SYM_CLASS_ENUM_TAG            0x000F
#define IMAGE_SYM_CLASS_MEMBER_OF_ENUM      0x0010
#define IMAGE_SYM_CLASS_REGISTER_PARAM      0x0011
#define IMAGE_SYM_CLASS_BIT_FIELD           0x0012

#define IMAGE_SYM_CLASS_FAR_EXTERNAL        0x0044  //

#define IMAGE_SYM_CLASS_BLOCK               0x0064
#define IMAGE_SYM_CLASS_FUNCTION            0x0065
#define IMAGE_SYM_CLASS_END_OF_STRUCT       0x0066
#define IMAGE_SYM_CLASS_FILE                0x0067
// new
#define IMAGE_SYM_CLASS_SECTION             0x0068
#define IMAGE_SYM_CLASS_WEAK_EXTERNAL       0x0069

#define IMAGE_SYM_CLASS_CLR_TOKEN           0x006B

#define N_BTMASK                            0x000F
#define N_TMASK                             0x0030
#define N_TMASK1                            0x00C0
#define N_TMASK2                            0x00F0
#define N_BTSHFT                            4
#define N_TSHIFT                            2
// MACROS

// Basic Type of  x
#define BTYPE(x) ((x) & N_BTMASK)

// Is x a pointer?
#ifndef ISPTR
#define ISPTR(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_POINTER << N_BTSHFT))
#endif

// Is x a function?
#ifndef ISFCN
#define ISFCN(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT))
#endif

// Is x an array?

#ifndef ISARY
#define ISARY(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_ARRAY << N_BTSHFT))
#endif

// Is x a structure, union, or enumeration TAG?
#ifndef ISTAG
#define ISTAG(x) ((x)==IMAGE_SYM_CLASS_STRUCT_TAG || (x)==IMAGE_SYM_CLASS_UNION_TAG || (x)==IMAGE_SYM_CLASS_ENUM_TAG)
#endif

#ifndef INCREF
#define INCREF(x) ((((x)&~N_BTMASK)<<N_TSHIFT)|(IMAGE_SYM_DTYPE_POINTER<<N_BTSHFT)|((x)&N_BTMASK))
#endif
#ifndef DECREF
#define DECREF(x) ((((x)>>N_TSHIFT)&~N_BTMASK)|((x)&N_BTMASK))
#endif


typedef struct _IMAGE_SYMBOL
{
    union
    {
        UCHAR ShortName[0x8];
        struct
        {
            DWORD Short;
            DWORD Long;
        } Name;
        DWORD LongName[0x2];
    } N;
    DWORD Value;
    SHORT SectionNumber;
    WORD Type;
    UCHAR StorageClass;
    UCHAR NumberOfAuxSymbols;
}IMAGE_SYMBOL, * PIMAGE_SYMBOL;

typedef struct _IMAGE_SYMBOL_EX
{
    union
    {
        UCHAR ShortName[0x8];
        struct
        {
            DWORD Short;
            DWORD Long;
        } Name;
        DWORD LongName[0x2];
    } N;
    DWORD Value;
    LONG SectionNumber;
    WORD Type;
    UCHAR StorageClass;
    UCHAR NumberOfAuxSymbols;
}IMAGE_SYMBOL_EX, * PIMAGE_SYMBOL_EX;

typedef enum _FUNCTION_TABLE_TYPE //int32_t
{
    RF_SORTED = 0x0,
    RF_UNSORTED = 0x1,
    RF_CALLBACK = 0x2,
    RF_KERNEL_DYNAMIC = 0x3
}FUNCTION_TABLE_TYPE, * PFUNCTION_TABLE_TYPE;

typedef struct _DYNAMIC_FUNCTION_TABLE
{
    LIST_ENTRY ListEntry;
    IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable;
    LARGE_INTEGER TimeStamp;
    QWORD MinimumAddress;
    QWORD MaximumAddress;
    QWORD BaseAddress;
    IMAGE_RUNTIME_FUNCTION_ENTRY* (*Callback)(QWORD, PVOID);
    PVOID Context;
    USHORT* OutOfProcessCallbackDll;
    FUNCTION_TABLE_TYPE Type;
    DWORD EntryCount;
    RTL_BALANCED_NODE TreeNodeMin;
    RTL_BALANCED_NODE TreeNodeMax;
}DYNAMIC_FUNCTION_TABLE, * PDYNAMIC_FUNCTION_TABLE;

typedef struct _INVERTED_FUNCTION_TABLE_ENTRY
{
    union
    {
        IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable;
        DYNAMIC_FUNCTION_TABLE* DynamicTable;
    } __inner0;
    PVOID ImageBase;
    DWORD SizeOfImage;
    DWORD SizeOfTable;
}INVERTED_FUNCTION_TABLE_ENTRY, * PINVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _INVERTED_FUNCTION_TABLE
{
    DWORD CurrentSize;
    DWORD MaximumSize;
    DWORD volatile Epoch;
    UCHAR Overflow;
    INVERTED_FUNCTION_TABLE_ENTRY TableEntry[0x200];
}INVERTED_FUNCTION_TABLE, * PINVERTED_FUNCTION_TABLE;

typedef struct _IMAGE_ARCHITECTURE_ENTRY
{
    DWORD FixupInstRVA;
    DWORD NewInst;
}IMAGE_ARCHITECTURE_ENTRY, * PIMAGE_ARCHITECTURE_ENTRY;

/*typedef struct _IMAGE_ARCHITECTURE_HEADER {
    unsigned int AmaskValue : 1;                 // 1 -> code section depends on mask bit
    // 0 -> new instruction depends on mask bit
    int : 7;                                     // MBZ
    unsigned int AmaskShift : 8;                 // Amask bit in question for this fixup
    int : 16;                                    // MBZ
    DWORD FirstEntryRVA;                        // RVA into .arch section to array of ARCHITECTURE_ENTRY's
} IMAGE_ARCHITECTURE_HEADER, * PIMAGE_ARCHITECTURE_HEADER;*/
/*
typedef struct _IMAGE_ARCHITECTURE_HEADER
{
    union
    {
        DWORD AmaskValue;
        DWORD AmaskShift;
    } __bitfield0;
    DWORD FirstEntryRVA;
}IMAGE_ARCHITECTURE_HEADER, * PIMAGE_ARCHITECTURE_HEADER;*/

typedef struct _IMAGE_ARCHITECTURE_HEADER {
    unsigned int AmaskValue : 1;                 // 1 -> code section depends on mask bit
    // 0 -> new instruction depends on mask bit
    int : 7;                                     // MBZ
    unsigned int AmaskShift : 8;                 // Amask bit in question for this fixup
    int : 16;                                    // MBZ
    DWORD FirstEntryRVA;                        // RVA into .arch section to array of ARCHITECTURE_ENTRY's
} IMAGE_ARCHITECTURE_HEADER, * PIMAGE_ARCHITECTURE_HEADER;

typedef struct _OSINFO
{
    DWORD dwOSPlatformId;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
}OSINFO, * POSINFO;

typedef struct _ASSEMBLYMETADATA
{
    USHORT usMajorVersion;
    USHORT usMinorVersion;
    USHORT usBuildNumber;
    USHORT usRevisionNumber;
    USHORT* szLocale;
    DWORD cbLocale;
    DWORD* rProcessor;
    DWORD ulProcessor;
    OSINFO* rOS;
    DWORD ulOS;
}ASSEMBLYMETADATA, * PASSEMBLYMETADATA;

typedef struct _JIT_DEBUG_INFO
{
    DWORD dwSize;
    DWORD dwProcessorArchitecture;
    DWORD dwThreadID;
    DWORD dwReserved0;
    QWORD lpExceptionAddress;
    QWORD lpExceptionRecord;
    QWORD lpContextRecord;
}JIT_DEBUG_INFO, * PJIT_DEBUG_INFO;

//FROM LDR 
typedef struct _LOADED_IMAGE
{
    char* ModuleName;
    PVOID hFile;
    UCHAR* MappedAddress;
    IMAGE_NT_HEADERS64* FileHeader;
    IMAGE_SECTION_HEADER* LastRvaSection;
    DWORD NumberOfSections;
    IMAGE_SECTION_HEADER* Sections;
    DWORD Characteristics;
    UCHAR fSystemImage;
    UCHAR fDOSImage;
    UCHAR fReadOnly;
    UCHAR Version;
    LIST_ENTRY Links;
    DWORD SizeOfImage;
}LOADED_IMAGE, * PLOADED_IMAGE;

typedef struct _LOAD_ASDATA_TABLE
{
    PVOID Module;
    PWSTR FilePath;
    QWORD Size;
    PVOID* Handle;
    LONG RefCount;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
}LOAD_ASDATA_TABLE, * PLOAD_ASDATA_TABLE;

typedef struct _LOAD_DLL_DEBUG_INFO
{
    PVOID hFile;
    PVOID lpBaseOfDll;
    DWORD dwDebugInfoFileOffset;
    DWORD nDebugInfoSize;
    PVOID lpImageName;
    WORD fUnicode;
}LOAD_DLL_DEBUG_INFO, * PLOAD_DLL_DEBUG_INFO;

typedef struct _LOCALMANAGEDAPPLICATION
{
    PWSTR pszDeploymentName;
    PWSTR pszPolicyName;
    PWSTR pszProductId;
    DWORD dwState;
}LOCALMANAGEDAPPLICATION, * PLOCALMANAGEDAPPLICATION;

typedef struct _HOT_PATCH_IMAGE_INFO
{
    DWORD CheckSum;
    DWORD TimeDateStamp;
}HOT_PATCH_IMAGE_INFO, * PHOT_PATCH_IMAGE_INFO;

typedef struct _MANAGEDAPPLICATION
{
    PWSTR pszPackageName;
    PWSTR pszPublisher;
    DWORD dwVersionHi;
    DWORD dwVersionLo;
    DWORD dwRevision;
    GUID GpoId;
    PWSTR pszPolicyName;
    GUID ProductId;
    USHORT Language;
    PWSTR pszOwner;
    PWSTR pszCompany;
    PWSTR pszComments;
    PWSTR pszContact;
    PWSTR pszSupportUrl;
    DWORD dwPathType;
    LONG bInstalled;
}MANAGEDAPPLICATION, * PMANAGEDAPPLICATION;

typedef struct _MANAGE_HOT_PATCH_LOAD_PATCH
{
    DWORD Version;
    UNICODE_STRING PatchPath;
    union
    {
        SID Sid;
        UCHAR Buffer[0x44];
    } UserSid;
    HOT_PATCH_IMAGE_INFO BaseInfo;
}MANAGE_HOT_PATCH_LOAD_PATCH, * PMANAGE_HOT_PATCH_LOAD_PATCH;

typedef struct _MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES
{
    DWORD Version;
    PVOID ProcessHandle;
    DWORD PatchCount;
    UNICODE_STRING* PatchPathStrings;
    HOT_PATCH_IMAGE_INFO* BaseInfos;
}MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES, * PMANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES;

typedef struct _MANAGE_HOT_PATCH_QUERY_PATCHES
{
    DWORD Version;
    union
    {
        SID Sid;
        UCHAR Buffer[0x44];
    } UserSid;
    DWORD PatchCount;
    UNICODE_STRING* PatchPathStrings;
    HOT_PATCH_IMAGE_INFO* BaseInfos;
}MANAGE_HOT_PATCH_QUERY_PATCHES, * PMANAGE_HOT_PATCH_QUERY_PATCHES;

typedef struct _MANAGE_HOT_PATCH_UNLOAD_PATCH
{
    DWORD Version;
    HOT_PATCH_IMAGE_INFO BaseInfo;
    union
    {
        SID Sid;
        UCHAR Buffer[0x44];
    } UserSid;
}MANAGE_HOT_PATCH_UNLOAD_PATCH, * PMANAGE_HOT_PATCH_UNLOAD_PATCH;

typedef struct _MANAGE_WRITES_TO_EXECUTABLE_MEMORY
{
    union
    {
        DWORD Version;
        DWORD ProcessEnableWriteExceptions;
        DWORD ThreadAllowWrites;
        DWORD Spare;
    } __bitfield0;
    PVOID KernelWriteToExecutableSignal;
}MANAGE_WRITES_TO_EXECUTABLE_MEMORY, * PMANAGE_WRITES_TO_EXECUTABLE_MEMORY;

//----------------------My personal stuff----------------------//

#define MEM_COMMIT                                             0x00001000  
#define MEM_PRIVATE                                            0x00020000
#define MEM_RESERVE                                            0x00002000  
#define MEM_REPLACE_PLACEHOLDER                                0x00004000  
#define MEM_MAPPED                                             0x00040000 
#define MEM_IMAGE                                              0x1000000
#define MEM_RESET                                              0x00080000  
#define MEM_TOP_DOWN                                           0x00100000  
#define MEM_WRITE_WATCH                                        0x00200000  
#define MEM_PHYSICAL                                           0x00400000  
#define MEM_ROTATE                                             0x00800000  
#define MEM_DIFFERENT_IMAGE_BASE_OK                            0x00800000  
#define MEM_RESET_UNDO                                         0x01000000  
#define MEM_LARGE_PAGES                                        0x20000000  
#define MEM_4MB_PAGES                                          0x80000000  
#define MEM_64K_PAGES                                          (MEM_LARGE_PAGES | MEM_PHYSICAL)  
#define MEM_UNMAP_WITH_TRANSIENT_BOOST                         0x00000001  
#define MEM_COALESCE_PLACEHOLDERS                              0x00000001  
#define MEM_PRESERVE_PLACEHOLDER                               0x00000002 
#define MEM_FREE                                               0x00010000  

typedef enum _VIRTUAL_ALLOCATION_TYPE// uint32_t
{
    /*MEM_COMMIT = 0x1000,
    MEM_RESERVE = 0x2000,
    MEM_RESET = 0x80000,
    MEM_RESET_UNDO = 0x1000000,
    MEM_REPLACE_PLACEHOLDER = 0x4000,
    MEM_LARGE_PAGES = 0x20000000,
    MEM_RESERVE_PLACEHOLDER = 0x40000,
    MEM_FREE = 0x10000*/
}VIRTUAL_ALLOCATION_TYPE, * PVIRTUAL_ALLOCATION_TYPE;

typedef enum _LOCAL_ALLOC_FLAGS // uint32_t
{
    LHND = 0x42,
    LMEM_FIXED = 0x0,
    LMEM_MOVEABLE = 0x2,
    LMEM_ZEROINIT = 0x40,
    LPTR = 0x40,
    NONZEROLHND = 0x2,
    NONZEROLPTR = 0x0
}LOCAL_ALLOC_FLAGS, * PLOCAL_ALLOC_FLAGS;

typedef enum _GLOBAL_ALLOC_FLAGS // uint32_t
{
    GHND = 0x42,
    GMEM_FIXED = 0x0,
    GMEM_MOVEABLE = 0x2,
    GMEM_ZEROINIT = 0x40,
    GPTR = 0x40
}GLOBAL_ALLOC_FLAGS, * PGLOBAL_ALLOC_FLAGS;

#define MEM_DECOMMIT                                           0x00004000  
#define MEM_RELEASE                                            0x00008000  

typedef enum _VIRTUAL_FREE_TYPE // uint32_t
{
    //MEM_DECOMMIT = 0x4000,
    //MEM_RELEASE = 0x8000
}VIRTUAL_FREE_TYPE, * PVIRTUAL_FREE_TYPE;

#define SEC_HUGE_PAGES 0x00020000
#define SEC_PARTITION_OWNER_HANDLE 0x00040000
#define SEC_64K_PAGES 0x00080000
#define SEC_BASED 0x00200000
#define SEC_NO_CHANGE 0x00400000
#define SEC_FILE 0x00800000
#define SEC_IMAGE 0x01000000
#define SEC_PROTECTED_IMAGE 0x02000000
#define SEC_RESERVE 0x04000000
#define SEC_COMMIT 0x08000000
#define SEC_NOCACHE 0x10000000
#define SEC_GLOBAL 0x20000000
#define SEC_WRITECOMBINE 0x40000000
#define SEC_LARGE_PAGES 0x80000000
#define SEC_IMAGE_NO_EXECUTE (SEC_IMAGE | SEC_NOCACHE)

#define MEM_EXECUTE_OPTION_ENABLE 0x1
#define MEM_EXECUTE_OPTION_DISABLE 0x2
#define MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION 0x4
#define MEM_EXECUTE_OPTION_PERMANENT 0x8
#define MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE 0x10
#define MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE 0x20
#define MEM_EXECUTE_OPTION_VALID_FLAGS 0x3f

typedef enum HANDLE_FLAGS //: uint32_t
{
    HANDLE_FLAG_INHERIT = 0x1,
    HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x2
}HANDLE_FLAGS, * PHANDLE_FLAGS;


#define PAGE_NOACCESS                                          0x01    
#define PAGE_READONLY                                          0x02    
#define PAGE_READWRITE                                         0x04    
#define PAGE_WRITECOPY                                         0x08    
#define PAGE_EXECUTE                                           0x10    
#define PAGE_EXECUTE_READ                                      0x20    
#define PAGE_EXECUTE_READWRITE                                 0x40    
#define PAGE_EXECUTE_WRITECOPY                                 0x80    
#define PAGE_GUARD                                             0x100    
#define PAGE_NOCACHE                                           0x200    
#define PAGE_WRITECOMBINE                                      0x400    
#define PAGE_GRAPHICS_NOACCESS                                 0x0800    
#define PAGE_GRAPHICS_READONLY                                 0x1000    
#define PAGE_GRAPHICS_READWRITE                                0x2000    
#define PAGE_GRAPHICS_EXECUTE                                  0x4000    
#define PAGE_GRAPHICS_EXECUTE_READ                             0x8000    
#define PAGE_GRAPHICS_EXECUTE_READWRITE                        0x10000    
#define PAGE_GRAPHICS_COHERENT                                 0x20000    
#define PAGE_GRAPHICS_NOCACHE                                  0x40000    
#define PAGE_ENCLAVE_THREAD_CONTROL                            0x80000000  
#define PAGE_REVERT_TO_FILE_MAP                                0x80000000  
#define PAGE_TARGETS_NO_UPDATE                                 0x40000000  
#define PAGE_TARGETS_INVALID                                   0x40000000  
#define PAGE_ENCLAVE_UNVALIDATED                               0x20000000  
#define PAGE_ENCLAVE_MASK                                      0x10000000  
#define PAGE_ENCLAVE_DECOMMIT                                  (PAGE_ENCLAVE_MASK | 0) 
#define PAGE_ENCLAVE_SS_FIRST                                  (PAGE_ENCLAVE_MASK | 1) 
#define PAGE_ENCLAVE_SS_REST                                   (PAGE_ENCLAVE_MASK | 2) 

typedef enum _PAGE_PROTECTION_FLAGS
{
    /*PAGE_NOACCESS = 0x1,
    PAGE_READONLY = 0x2,
    PAGE_READWRITE = 0x4,
    PAGE_WRITECOPY = 0x8,
    PAGE_EXECUTE = 0x10,
    PAGE_EXECUTE_READ = 0x20,
    PAGE_EXECUTE_READWRITE = 0x40,
    PAGE_EXECUTE_WRITECOPY = 0x80,
    PAGE_GUARD = 0x100,
    PAGE_NOCACHE = 0x200,
    PAGE_WRITECOMBINE = 0x400,
    PAGE_GRAPHICS_NOACCESS = 0x800,
    PAGE_GRAPHICS_READONLY = 0x1000,
    PAGE_GRAPHICS_READWRITE = 0x2000,
    PAGE_GRAPHICS_EXECUTE = 0x4000,
    PAGE_GRAPHICS_EXECUTE_READ = 0x8000,
    PAGE_GRAPHICS_EXECUTE_READWRITE = 0x10000,
    PAGE_GRAPHICS_COHERENT = 0x20000,
    PAGE_GRAPHICS_NOCACHE = 0x40000,
    PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000,
    PAGE_REVERT_TO_FILE_MAP = 0x80000000,
    PAGE_TARGETS_NO_UPDATE = 0x40000000,
    PAGE_TARGETS_INVALID = 0x40000000,
    PAGE_ENCLAVE_UNVALIDATED = 0x20000000,
    PAGE_ENCLAVE_MASK = 0x10000000,
    PAGE_ENCLAVE_DECOMMIT = 0x10000000,
    PAGE_ENCLAVE_SS_FIRST = 0x10000001,
    PAGE_ENCLAVE_SS_REST = 0x10000002,
    SEC_PARTITION_OWNER_HANDLE = 0x40000,
    SEC_64K_PAGES = 0x80000,
    SEC_FILE = 0x800000,
    SEC_IMAGE = 0x1000000,
    SEC_PROTECTED_IMAGE = 0x2000000,
    SEC_RESERVE = 0x4000000,
    SEC_COMMIT = 0x8000000,
    SEC_NOCACHE = 0x10000000,
    SEC_WRITECOMBINE = 0x40000000,
    SEC_LARGE_PAGES = 0x80000000,
    SEC_IMAGE_NO_EXECUTE = 0x11000000*/
}PAGE_PROTECTION_FLAGS, * PPAGE_PROTECTION_FLAGS;

typedef enum _PAGE_TYPE
{
    /*MEM_PRIVATE = 0x20000,
    MEM_MAPPED = 0x40000,
    MEM_IMAGE = 0x1000000*/
}PAGE_TYPE, * PPAGE_TYPE;

#define PS_ATTRIBUTE_NUMBER_MASK    0x0000ffff
#define PS_ATTRIBUTE_THREAD         0x00010000 // Attribute may be used with thread creation
#define PS_ATTRIBUTE_INPUT          0x00020000 // Attribute is input only
#define PS_ATTRIBUTE_ADDITIVE       0x00040000 // Attribute may be "accumulated", e.g. bitmasks, counters, etc.

typedef struct _OBJECT_BASIC_INFORMATION
{
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    ULONG Reserved[3];
    ULONG NameInfoSize;
    ULONG TypeInfoSize;
    ULONG SecurityDescriptorSize;
    LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
}OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION
{
    UCHAR Inherit;
    UCHAR ProtectFromClose;
}OBJECT_HANDLE_FLAG_INFORMATION, * POBJECT_HANDLE_FLAG_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS // int32_t
{
    MemoryBasicInformation = 0x0,
    MemoryWorkingSetInformation = 0x1,
    MemoryMappedFilenameInformation = 0x2,
    MemoryRegionInformation = 0x3,
    MemoryWorkingSetExInformation = 0x4,
    MemorySharedCommitInformation = 0x5,
    MemoryImageInformation = 0x6,
    MemoryRegionInformationEx = 0x7,
    MemoryPrivilegedBasicInformation = 0x8,
    MemoryEnclaveImageInformation = 0x9,
    MemoryBasicInformationCapped = 0xa,
    MemoryPhysicalContiguityInformation = 0xb
}MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

typedef enum _MEMORY_EXHAUSTION_TYPE// int32_t
{
    MemoryExhaustionTypeFailFastOnCommitFailure = 0x0,
    MemoryExhaustionTypeMax = 0x1
}MEMORY_EXHAUSTION_TYPE, * PMEMORY_EXHAUSTION_TYPE;

typedef enum _MEMORY_PHYSICAL_CONTIGUITY_UNIT_STATE // int32_t
{
    MemoryNotContiguous = 0x0,
    MemoryAlignedAndContiguous = 0x1,
    MemoryNotResident = 0x2,
    MemoryNotEligibleToMakeContiguous = 0x3,
    MemoryContiguityStateMax = 0x4
}MEMORY_PHYSICAL_CONTIGUITY_UNIT_STATE, * PMEMORY_PHYSICAL_CONTIGUITY_UNIT_STATE;

typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    DWORD  AllocationProtect;
    WORD   PartitionId;
    SIZE_T RegionSize;
    DWORD  State;   //MEM_COMMIT MEM_RESERVE MEM_RESET MEM_RESET_UNDO MEM_REPLACE_PLACEHOLDER MEM_LARGE_PAGES MEM_RESERVE_PLACEHOLDE MEM_FREE
    DWORD  Protect; //PAGE_NOACCESS PAGE_EXECUTE_READ and the like...
    DWORD  Type;    //MEM_IMAGE MEM_MAPPED MEM__PRIVATE
} MEMORY_BASIC_INFORMATION, * PMEMORY_BASIC_INFORMATION;

typedef struct _MEMORY_BASIC_INFORMATION32
{
    DWORD BaseAddress;
    DWORD AllocationBase;
    DWORD AllocationProtect;
    DWORD RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
}MEMORY_BASIC_INFORMATION32, * PMEMORY_BASIC_INFORMATION32;

typedef struct _MEMORY_BASIC_INFORMATION64
{
    QWORD BaseAddress;
    QWORD AllocationBase;
    DWORD AllocationProtect;
    DWORD __alignment1;
    QWORD RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
    DWORD __alignment2;
}MEMORY_BASIC_INFORMATION64, * PMEMORY_BASIC_INFORMATION64;

typedef struct _MEMORY_COMBINE_INFORMATION
{
    HANDLE Handle;
    QWORD PagesCombined;
}MEMORY_COMBINE_INFORMATION, * PMEMORY_COMBINE_INFORMATION;

typedef struct _MEMORY_COMBINE_INFORMATION_EX
{
    HANDLE Handle;
    QWORD PagesCombined;
    DWORD Flags;
}MEMORY_COMBINE_INFORMATION_EX, * PMEMORY_COMBINE_INFORMATION_EX;

typedef struct _MEMORY_COMBINE_INFORMATION_EX2
{
    HANDLE Handle;
    QWORD PagesCombined;
    DWORD Flags;
    HANDLE ProcessHandle;
}MEMORY_COMBINE_INFORMATION_EX2, * PMEMORY_COMBINE_INFORMATION_EX2;

typedef struct _MEMORY_IMAGE_INFORMATION
{
    PVOID ImageBase;
    QWORD SizeOfImage;
    union
    {
        DWORD ImageFlags;
        union
        {
            DWORD ImagePartialMap;
            DWORD ImageNotExecutable;
            DWORD ImageSigningLevel;
            DWORD Reserved;
        } __bitfield16;
    } __inner2;
}MEMORY_IMAGE_INFORMATION, * PMEMORY_IMAGE_INFORMATION;

typedef struct _MEMORY_ENCLAVE_IMAGE_INFORMATION
{
    MEMORY_IMAGE_INFORMATION ImageInfo;
    UCHAR UniqueID[0x20];
    UCHAR AuthorID[0x20];
}MEMORY_ENCLAVE_IMAGE_INFORMATION, * PMEMORY_ENCLAVE_IMAGE_INFORMATION;

typedef struct _MEMORY_EXHAUSTION_INFORMATION
{
    WORD Version;
    WORD Reserved;
    MEMORY_EXHAUSTION_TYPE Type;
    QWORD Value;
}MEMORY_EXHAUSTION_INFORMATION, * PMEMORY_EXHAUSTION_INFORMATION;

struct _MEMORY_FRAME_INFORMATION
{
    union
    {
        QWORD UseDescription;
        QWORD ListDescription;
        QWORD Cold;
        QWORD Pinned;
        QWORD DontUse;
        QWORD Priority;
        QWORD Reserved;
    } __bitfield0;
}MEMORY_FRAME_INFORMATION, * PMEMORY_FRAME_INFORMATION;

typedef struct _MEMORY_PARTITION_ATTRIBUTE_INFORMATION
{
    QWORD Flags;
}MEMORY_PARTITION_ATTRIBUTE_INFORMATION, * PMEMORY_PARTITION_ATTRIBUTE_INFORMATION;

typedef struct _MEMORY_PARTITION_CONFIGURATION_INFORMATION
{
    DWORD Flags;
    DWORD NumaNode;
    DWORD Channel;
    DWORD NumberOfNumaNodes;
    QWORD ResidentAvailablePages;
    QWORD CommittedPages;
    QWORD CommitLimit;
    QWORD PeakCommitment;
    QWORD TotalNumberOfPages;
    QWORD AvailablePages;
    QWORD ZeroPages;
    QWORD FreePages;
    QWORD StandbyPages;
    QWORD StandbyPageCountByPriority[0x8];
    QWORD RepurposedPagesByPriority[0x8];
    QWORD MaximumCommitLimit;
    QWORD DonatedPagesToPartitions;
    DWORD PartitionId;
}MEMORY_PARTITION_CONFIGURATION_INFORMATION, * PMEMORY_PARTITION_CONFIGURATION_INFORMATION;

typedef struct _MEMORY_PARTITION_CREATE_LARGE_PAGES_INFORMATION
{
    DWORD Flags;
    DWORD NumaNode;
    QWORD LargePageSize;
    QWORD NumberOfLargePagesToCreate;
    QWORD NumberOfLargePagesCreated;
}MEMORY_PARTITION_CREATE_LARGE_PAGES_INFORMATION, * PMEMORY_PARTITION_CREATE_LARGE_PAGES_INFORMATION;

typedef struct _MEMORY_PARTITION_PAGE_RANGE
{
    QWORD StartPage;
    QWORD NumberOfPages;
}MEMORY_PARTITION_PAGE_RANGE, * PMEMORY_PARTITION_PAGE_RANGE;

typedef struct _MEMORY_PARTITION_INITIAL_ADD_INFORMATION
{
    DWORD Flags;
    DWORD NumberOfRanges;
    QWORD NumberOfPagesAdded;
    MEMORY_PARTITION_PAGE_RANGE PartitionRanges[0x1];
}MEMORY_PARTITION_INITIAL_ADD_INFORMATION, * PMEMORY_PARTITION_INITIAL_ADD_INFORMATION;

typedef struct _MEMORY_PARTITION_MEMORY_EVENTS_INFORMATION
{
    union
    {
        DWORD CommitEvents;
        DWORD Spare;
        DWORD AllFlags;
    } Flags;
    DWORD HandleAttributes;
    DWORD DesiredAccess;
    PVOID LowCommitCondition;
    PVOID HighCommitCondition;
    PVOID MaximumCommitCondition;
}MEMORY_PARTITION_MEMORY_EVENTS_INFORMATION, * PMEMORY_PARTITION_MEMORY_EVENTS_INFORMATION;

typedef struct _MEMORY_PARTITION_NODE_PAGE_INFORMATION
{
    QWORD TotalPageCount;
    QWORD SmallFreePageCount;
    QWORD SmallZeroPageCount;
    QWORD MediumFreePageCount;
    QWORD MediumZeroPageCount;
    QWORD LargeFreePageCount;
    QWORD LargeZeroPageCount;
    QWORD HugeFreePageCount;
    QWORD HugeZeroPageCount;
}MEMORY_PARTITION_NODE_PAGE_INFORMATION, * PMEMORY_PARTITION_NODE_PAGE_INFORMATION;

typedef struct _MEMORY_PARTITION_NODE_INFORMATION
{
    DWORD NumaNodeCount;
    DWORD Flags;
    MEMORY_PARTITION_NODE_PAGE_INFORMATION* NodePageInformation;
}MEMORY_PARTITION_NODE_INFORMATION, * PMEMORY_PARTITION_NODE_INFORMATION;

typedef struct _MEMORY_PARTITION_PAGEFILE_INFORMATION
{
    UNICODE_STRING PageFileName;
    LARGE_INTEGER MinimumSize;
    LARGE_INTEGER MaximumSize;
    DWORD Flags;
}MEMORY_PARTITION_PAGEFILE_INFORMATION, * PMEMORY_PARTITION_PAGEFILE_INFORMATION;

typedef struct _MEMORY_PARTITION_PAGE_COMBINE_INFORMATION
{
    PVOID StopHandle;
    DWORD Flags;
    QWORD TotalNumberOfPages;
}MEMORY_PARTITION_PAGE_COMBINE_INFORMATION, * PMEMORY_PARTITION_PAGE_COMBINE_INFORMATION;

typedef struct _MEMORY_PARTITION_TRANSFER_INFORMATION
{
    QWORD NumberOfPages;
    DWORD NumaNode;
    DWORD Flags;
}MEMORY_PARTITION_TRANSFER_INFORMATION, * PMEMORY_PARTITION_TRANSFER_INFORMATION;

typedef struct _MEMORY_PHYSICAL_CONTIGUITY_UNIT_INFORMATION
{
    union
    {
        union
        {
            DWORD State;
            DWORD Reserved;
        } __bitfield0;
        DWORD AllInformation;
    } __inner0;
}MEMORY_PHYSICAL_CONTIGUITY_UNIT_INFORMATION, * PMEMORY_PHYSICAL_CONTIGUITY_UNIT_INFORMATION;

typedef struct _MEMORY_PHYSICAL_CONTIGUITY_INFORMATION
{
    PVOID VirtualAddress;
    QWORD Size;
    QWORD ContiguityUnitSize;
    DWORD Flags;
    MEMORY_PHYSICAL_CONTIGUITY_UNIT_INFORMATION* ContiguityUnitInformation;
}MEMORY_PHYSICAL_CONTIGUITY_INFORMATION, * PMEMORY_PHYSICAL_CONTIGUITY_INFORMATION;

typedef struct _MEMORY_PRIORITY_INFORMATION
{
    DWORD MemoryPriority;
}MEMORY_PRIORITY_INFORMATION, * PMEMORY_PRIORITY_INFORMATION;

typedef struct _MEMORY_RANGE_ENTRY
{
    PVOID VirtualAddress;
    QWORD NumberOfBytes;
}MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;

typedef struct _MEMORY_REGION_INFORMATION
{
    PVOID AllocationBase;
    DWORD AllocationProtect;
    union
    {
        DWORD RegionType;
        union
        {
            DWORD Private;
            DWORD MappedDataFile;
            DWORD MappedImage;
            DWORD MappedPageFile;
            DWORD MappedPhysical;
            DWORD DirectMapped;
            DWORD SoftwareEnclave;
            DWORD PageSize64K;
            DWORD PlaceholderReservation;
            DWORD Reserved;
        } __bitfield12;
    } __inner2;
    QWORD RegionSize;
    QWORD CommitSize;
    QWORD PartitionId;
    QWORD NodePreference;
}MEMORY_REGION_INFORMATION, * PMEMORY_REGION_INFORMATION;

typedef enum _MEMORY_RESERVE_TYPE// int32_t
{
    MemoryReserveUserApc = 0x0,
    MemoryReserveIoCompletion = 0x1,
    MemoryReserveTypeMax = 0x2
}MEMORY_RESERVE_TYPE, * PMEMORY_RESERVE_TYPE;

typedef enum _MEMORY_RESOURCE_NOTIFICATION_TYPE // int32_t
{
    LowMemoryResourceNotification = 0x0,
    HighMemoryResourceNotification = 0x1
}MEMORY_RESOURCE_NOTIFICATION_TYPE, * PMEMORY_RESOURCE_NOTIFICATION_TYPE;

typedef struct _MEMORY_SCRUB_INFORMATION
{
    PVOID Handle;
    QWORD PagesScrubbed;
}MEMORY_SCRUB_INFORMATION, * PMEMORY_SCRUB_INFORMATION;

typedef struct _MEMORY_SHARED_COMMIT_INFORMATION
{
    QWORD CommitSize;
}MEMORY_SHARED_COMMIT_INFORMATION, * PMEMORY_SHARED_COMMIT_INFORMATION;

//https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadexecutionstate
#define ES_SYSTEM_REQUIRED                       0x00000001
#define ES_DISPLAY_REQUIRED                      0x00000002
#define ES_USER_PRESENT                          0x00000004 //This value is not supported
#define ES_CONTINUOUS                            0x80000000
#define ES_AWAYMODE_REQUIRED                     0x00000040

typedef ULONG EXECUTION_STATE, * PEXECUTION_STATE;

typedef enum _SYSTEM_POWER_STATE {
    PowerSystemUnspecified = 0,
    PowerSystemWorking = 1,
    PowerSystemSleeping1 = 2,
    PowerSystemSleeping2 = 3,
    PowerSystemSleeping3 = 4,
    PowerSystemHibernate = 5,
    PowerSystemShutdown = 6,
    PowerSystemMaximum = 7
} SYSTEM_POWER_STATE, * PSYSTEM_POWER_STATE;

typedef enum _SYSTEM_POWER_CONDITION // int32_t
{
    PoAc = 0x0,
    PoDc = 0x1,
    PoHot = 0x2,
    PoConditionMaximum = 0x3
}SYSTEM_POWER_CONDITION, * PSYSTEM_POWER_CONDITION;

typedef enum _POWER_ACTION {
    PowerActionNone = 0,
    PowerActionReserved,
    PowerActionSleep,
    PowerActionHibernate,
    PowerActionShutdown,
    PowerActionShutdownReset,
    PowerActionShutdownOff,
    PowerActionWarmEject,
    PowerActionDisplayOff
} POWER_ACTION, * PPOWER_ACTION;

typedef struct _POWER_ACTION_POLICY
{
    POWER_ACTION Action;
    DWORD Flags;
    DWORD EventCode;
}POWER_ACTION_POLICY, * PPOWER_ACTION_POLICY;

typedef struct _SYSTEM_POWER_LEVEL
{
    UCHAR Enable;
    UCHAR Spare[0x3];
    DWORD BatteryLevel;
    POWER_ACTION_POLICY PowerPolicy;
    SYSTEM_POWER_STATE MinSystemState;
}SYSTEM_POWER_LEVEL, * PSYSTEM_POWER_LEVEL;

typedef enum _POWER_STATE_TYPE // int32_t
{
    SystemPowerState = 0x0,
    DevicePowerState = 0x1
}POWER_STATE_TYPE, * PPOWER_STATE_TYPE;

typedef enum _DEVICE_POWER_STATE {
    PowerDeviceUnspecified = 0,
    PowerDeviceD0,
    PowerDeviceD1,
    PowerDeviceD2,
    PowerDeviceD3,
    PowerDeviceMaximum
} DEVICE_POWER_STATE, * PDEVICE_POWER_STATE;

typedef union _POWER_STATE
{
    SYSTEM_POWER_STATE SystemState;
    DEVICE_POWER_STATE DeviceState;
}POWER_STATE, * PPOWER_STATE;

typedef enum _MONITOR_DISPLAY_STATE {
    PowerMonitorOff = 0,
    PowerMonitorOn,
    PowerMonitorDim
} MONITOR_DISPLAY_STATE, * PMONITOR_DISPLAY_STATE;

typedef enum _USER_ACTIVITY_PRESENCE {
    PowerUserPresent = 0,
    PowerUserNotPresent,
    PowerUserInactive,
    PowerUserMaximum,
    PowerUserInvalid = PowerUserMaximum
} USER_ACTIVITY_PRESENCE, * PUSER_ACTIVITY_PRESENCE;

typedef enum _SHUTDOWN_ACTION {
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef enum _POWER_INFORMATION_LEVEL // int32_t
{
    SystemPowerPolicyAc = 0x0,
    SystemPowerPolicyDc = 0x1,
    VerifySystemPolicyAc = 0x2,
    VerifySystemPolicyDc = 0x3,
    SystemPowerCapabilities = 0x4,
    SystemBatteryState = 0x5,
    SystemPowerStateHandler = 0x6,
    ProcessorStateHandler = 0x7,
    SystemPowerPolicyCurrent = 0x8,
    AdministratorPowerPolicy = 0x9,
    SystemReserveHiberFile = 0xa,
    ProcessorInformation = 0xb,
    SystemPowerInformation = 0xc,
    ProcessorStateHandler2 = 0xd,
    LastWakeTime = 0xe,
    LastSleepTime = 0xf,
    SystemExecutionState = 0x10,
    SystemPowerStateNotifyHandler = 0x11,
    ProcessorPowerPolicyAc = 0x12,
    ProcessorPowerPolicyDc = 0x13,
    VerifyProcessorPowerPolicyAc = 0x14,
    VerifyProcessorPowerPolicyDc = 0x15,
    ProcessorPowerPolicyCurrent = 0x16,
    SystemPowerStateLogging = 0x17,
    SystemPowerLoggingEntry = 0x18,
    SetPowerSettingValue = 0x19,
    NotifyUserPowerSetting = 0x1a,
    PowerInformationLevelUnused0 = 0x1b,
    SystemMonitorHiberBootPowerOff = 0x1c,
    SystemVideoState = 0x1d,
    TraceApplicationPowerMessage = 0x1e,
    TraceApplicationPowerMessageEnd = 0x1f,
    ProcessorPerfStates = 0x20,
    ProcessorIdleStates = 0x21,
    ProcessorCap = 0x22,
    SystemWakeSource = 0x23,
    SystemHiberFileInformation = 0x24,
    TraceServicePowerMessage = 0x25,
    ProcessorLoad = 0x26,
    PowerShutdownNotification = 0x27,
    MonitorCapabilities = 0x28,
    SessionPowerInit = 0x29,
    SessionDisplayState = 0x2a,
    PowerRequestCreate = 0x2b,
    PowerRequestAction = 0x2c,
    GetPowerRequestList = 0x2d,
    ProcessorInformationEx = 0x2e,
    NotifyUserModeLegacyPowerEvent = 0x2f,
    GroupPark = 0x30,
    ProcessorIdleDomains = 0x31,
    WakeTimerList = 0x32,
    SystemHiberFileSize = 0x33,
    ProcessorIdleStatesHv = 0x34,
    ProcessorPerfStatesHv = 0x35,
    ProcessorPerfCapHv = 0x36,
    ProcessorSetIdle = 0x37,
    LogicalProcessorIdling = 0x38,
    UserPresence = 0x39,
    PowerSettingNotificationName = 0x3a,
    GetPowerSettingValue = 0x3b,
    IdleResiliency = 0x3c,
    SessionRITState = 0x3d,
    SessionConnectNotification = 0x3e,
    SessionPowerCleanup = 0x3f,
    SessionLockState = 0x40,
    SystemHiberbootState = 0x41,
    PlatformInformation = 0x42,
    PdcInvocation = 0x43,
    MonitorInvocation = 0x44,
    FirmwareTableInformationRegistered = 0x45,
    SetShutdownSelectedTime = 0x46,
    SuspendResumeInvocation = 0x47,
    PlmPowerRequestCreate = 0x48,
    ScreenOff = 0x49,
    CsDeviceNotification = 0x4a,
    PlatformRole = 0x4b,
    LastResumePerformance = 0x4c,
    DisplayBurst = 0x4d,
    ExitLatencySamplingPercentage = 0x4e,
    RegisterSpmPowerSettings = 0x4f,
    PlatformIdleStates = 0x50,
    ProcessorIdleVeto = 0x51,
    PlatformIdleVeto = 0x52,
    SystemBatteryStatePrecise = 0x53,
    ThermalEvent = 0x54,
    PowerRequestActionInternal = 0x55,
    BatteryDeviceState = 0x56,
    PowerInformationInternal = 0x57,
    ThermalStandby = 0x58,
    SystemHiberFileType = 0x59,
    PhysicalPowerButtonPress = 0x5a,
    QueryPotentialDripsConstraint = 0x5b,
    EnergyTrackerCreate = 0x5c,
    EnergyTrackerQuery = 0x5d,
    UpdateBlackBoxRecorder = 0x5e,
    SessionAllowExternalDmaDevices = 0x5f,
    PowerInformationLevelMaximum = 0x60
}POWER_INFORMATION_LEVEL, * PPOWER_INFORMATION_LEVEL;

typedef enum _POWER_MONITOR_REQUEST_REASON// int32_t
{
    MonitorRequestReasonUnknown = 0x0,
    MonitorRequestReasonPowerButton = 0x1,
    MonitorRequestReasonRemoteConnection = 0x2,
    MonitorRequestReasonScMonitorpower = 0x3,
    MonitorRequestReasonUserInput = 0x4,
    MonitorRequestReasonAcDcDisplayBurst = 0x5,
    MonitorRequestReasonUserDisplayBurst = 0x6,
    MonitorRequestReasonPoSetSystemState = 0x7,
    MonitorRequestReasonSetThreadExecutionState = 0x8,
    MonitorRequestReasonFullWake = 0x9,
    MonitorRequestReasonSessionUnlock = 0xa,
    MonitorRequestReasonScreenOffRequest = 0xb,
    MonitorRequestReasonIdleTimeout = 0xc,
    MonitorRequestReasonPolicyChange = 0xd,
    MonitorRequestReasonSleepButton = 0xe,
    MonitorRequestReasonLid = 0xf,
    MonitorRequestReasonBatteryCountChange = 0x10,
    MonitorRequestReasonGracePeriod = 0x11,
    MonitorRequestReasonPnP = 0x12,
    MonitorRequestReasonDP = 0x13,
    MonitorRequestReasonSxTransition = 0x14,
    MonitorRequestReasonSystemIdle = 0x15,
    MonitorRequestReasonNearProximity = 0x16,
    MonitorRequestReasonThermalStandby = 0x17,
    MonitorRequestReasonResumePdc = 0x18,
    MonitorRequestReasonResumeS4 = 0x19,
    MonitorRequestReasonTerminal = 0x1a,
    MonitorRequestReasonPdcSignal = 0x1b,
    MonitorRequestReasonAcDcDisplayBurstSuppressed = 0x1c,
    MonitorRequestReasonSystemStateEntered = 0x1d,
    MonitorRequestReasonWinrt = 0x1e,
    MonitorRequestReasonUserInputKeyboard = 0x1f,
    MonitorRequestReasonUserInputMouse = 0x20,
    MonitorRequestReasonUserInputTouch = 0x21,
    MonitorRequestReasonUserInputPen = 0x22,
    MonitorRequestReasonUserInputAccelerometer = 0x23,
    MonitorRequestReasonUserInputHid = 0x24,
    MonitorRequestReasonUserInputPoUserPresent = 0x25,
    MonitorRequestReasonUserInputSessionSwitch = 0x26,
    MonitorRequestReasonUserInputInitialization = 0x27,
    MonitorRequestReasonPdcSignalWindowsMobilePwrNotif = 0x28,
    MonitorRequestReasonPdcSignalWindowsMobileShell = 0x29,
    MonitorRequestReasonPdcSignalHeyCortana = 0x2a,
    MonitorRequestReasonPdcSignalHolographicShell = 0x2b,
    MonitorRequestReasonPdcSignalFingerprint = 0x2c,
    MonitorRequestReasonDirectedDrips = 0x2d,
    MonitorRequestReasonDim = 0x2e,
    MonitorRequestReasonBuiltinPanel = 0x2f,
    MonitorRequestReasonDisplayRequiredUnDim = 0x30,
    MonitorRequestReasonBatteryCountChangeSuppressed = 0x31,
    MonitorRequestReasonResumeModernStandby = 0x32,
    MonitorRequestReasonMax = 0x33
}POWER_MONITOR_REQUEST_REASON, * PPOWER_MONITOR_REQUEST_REASON;

typedef enum _POWER_MONITOR_REQUEST_TYPE //int32_t
{
    MonitorRequestTypeOff = 0x0,
    MonitorRequestTypeOnAndPresent = 0x1,
    MonitorRequestTypeToggleOn = 0x2
}POWER_MONITOR_REQUEST_TYPE, * PPOWER_MONITOR_REQUEST_TYPE;

typedef enum _POWER_REQUEST_TYPE //int32_t
{
    PowerRequestDisplayRequired = 0x0,
    PowerRequestSystemRequired = 0x1,
    PowerRequestAwayModeRequired = 0x2,
    PowerRequestExecutionRequired = 0x3
}POWER_REQUEST_TYPE, * PPOWER_REQUEST_TYPE;

typedef enum _POWER_STATE_DISABLED_TYPE // int32_t
{
    PoDisabledStateSleeping1 = 0x0,
    PoDisabledStateSleeping2 = 0x1,
    PoDisabledStateSleeping3 = 0x2,
    PoDisabledStateSleeping4 = 0x3,
    PoDisabledStateSleeping0Idle = 0x4,
    PoDisabledStateReserved5 = 0x5,
    PoDisabledStateSleeping4Firmware = 0x6,
    PoDisabledStateMaximum = 0x7
}POWER_STATE_DISABLED_TYPE, * PPOWER_STATE_DISABLED_TYPE;

typedef enum _POWER_STATE_HANDLER_TYPE // int32_t
{
    PowerStateSleeping1 = 0x0,
    PowerStateSleeping2 = 0x1,
    PowerStateSleeping3 = 0x2,
    PowerStateSleeping4 = 0x3,
    PowerStateShutdownOff = 0x4,
    PowerStateShutdownReset = 0x5,
    PowerStateSleeping4Firmware = 0x6,
    PowerStateMaximum = 0x7
}POWER_STATE_HANDLER_TYPE, * PPOWER_STATE_HANDLER_TYPE;

typedef enum _POWER_USER_PRESENCE_TYPE // int32_t
{
    UserNotPresent = 0x0,
    UserPresent = 0x1,
    UserUnknown = 0xff
}POWER_USER_PRESENCE_TYPE, * PPOWER_USER_PRESENCE_TYPE;


typedef enum _PS_ATTRIBUTE_NUM
{
    /*PsAttributeParentProcess,                   // in HANDLE
    PsAttributeDebugPort,                       // in HANDLE
    PsAttributeToken,                           // in HANDLE
    PsAttributeClientId,                        // out PCLIENT_ID
    PsAttributeTebAddress,                      // out PTEB
    PsAttributeImageName,                       // in PWSTR
    PsAttributeImageInfo,                       // out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve,                   // in PPS_MEMORY_RESERVE
    PsAttributePriorityClass,                   // in UCHAR
    PsAttributeErrorMode,                       // in ULONG
    PsAttributeStdHandleInfo,                   // in PPS_STD_HANDLE_INFO
    PsAttributeHandleList,                      // in PHANDLE
    PsAttributeGroupAffinity,                   // in PGROUP_AFFINITY
    PsAttributePreferredNode,                   // in PUSHORT
    PsAttributeIdealProcessor,                  // in PPROCESSOR_NUMBER
    PsAttributeUmsThread,                       // see MSDN UpdateProceThreadAttributeList (CreateProcessW) - in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions,               // in UCHAR
    PsAttributeProtectionLevel,                 // in ULONG
    PsAttributeSecureProcess,                   // since THRESHOLD (Virtual Secure Mode, Device Guard)
    PsAttributeJobList,
    PsAttributeChildProcessPolicy,              // since THRESHOLD2
    PsAttributeAllApplicationPackagesPolicy,    // since REDSTONE
    PsAttributeWin32kFilter,
    PsAttributeSafeOpenPromptOriginClaim,
    PsAttributeBnoIsolation,
    PsAttributeDesktopAppPolicy,
    PsAttributeMax*/
    PsAttributeParentProcess = 0x0,
    PsAttributeDebugObject = 0x1,
    PsAttributeToken = 0x2,
    PsAttributeClientId = 0x3,
    PsAttributeTebAddress = 0x4,
    PsAttributeImageName = 0x5,
    PsAttributeImageInfo = 0x6,
    PsAttributeMemoryReserve = 0x7,
    PsAttributePriorityClass = 0x8,
    PsAttributeErrorMode = 0x9,
    PsAttributeStdHandleInfo = 0xa,
    PsAttributeHandleList = 0xb,
    PsAttributeGroupAffinity = 0xc,
    PsAttributePreferredNode = 0xd,
    PsAttributeIdealProcessor = 0xe,
    PsAttributeUmsThread = 0xf,
    PsAttributeMitigationOptions = 0x10,
    PsAttributeProtectionLevel = 0x11,
    PsAttributeSecureProcess = 0x12,
    PsAttributeJobList = 0x13,
    PsAttributeChildProcessPolicy = 0x14,
    PsAttributeAllApplicationPackagesPolicy = 0x15,
    PsAttributeWin32kFilter = 0x16,
    PsAttributeSafeOpenPromptOriginClaim = 0x17,
    PsAttributeBnoIsolation = 0x18,
    PsAttributeDesktopAppPolicy = 0x19,
    PsAttributeChpe = 0x1a,
    PsAttributeMitigationAuditOptions = 0x1b,
    PsAttributeMachineType = 0x1c,
    PsAttributeComponentFilter = 0x1d,
    PsAttributeMax = 0x1e
} PS_ATTRIBUTE_NUM;

typedef enum _PROC_THREAD_ATTRIBUTE_NUM // int32_t
{
    ProcThreadAttributeParentProcess = 0x0,
    ProcThreadAttributeHandleList = 0x2,
    ProcThreadAttributeGroupAffinity = 0x3,
    ProcThreadAttributePreferredNode = 0x4,
    ProcThreadAttributeIdealProcessor = 0x5,
    ProcThreadAttributeUmsThread = 0x6,
    ProcThreadAttributeMitigationPolicy = 0x7,
    ProcThreadAttributeSecurityCapabilities = 0x9,
    ProcThreadAttributeProtectionLevel = 0xb,
    ProcThreadAttributeJobList = 0xd,
    ProcThreadAttributeChildProcessPolicy = 0xe,
    ProcThreadAttributeAllApplicationPackagesPolicy = 0xf,
    ProcThreadAttributeWin32kFilter = 0x10,
    ProcThreadAttributeSafeOpenPromptOriginClaim = 0x11,
    ProcThreadAttributeDesktopAppPolicy = 0x12,
    ProcThreadAttributePseudoConsole = 0x16,
    ProcThreadAttributeMitigationAuditPolicy = 0x18,
    ProcThreadAttributeMachineType = 0x19,
    ProcThreadAttributeComponentFilter = 0x1a
}PROC_THREAD_ATTRIBUTE_NUM, * PPROC_THREAD_ATTRIBUTE_NUM;

typedef enum _PS_MITIGATION_OPTION// int32_t
{
    PS_MITIGATION_OPTION_NX = 0x0,
    PS_MITIGATION_OPTION_SEHOP = 0x1,
    PS_MITIGATION_OPTION_FORCE_RELOCATE_IMAGES = 0x2,
    PS_MITIGATION_OPTION_HEAP_TERMINATE = 0x3,
    PS_MITIGATION_OPTION_BOTTOM_UP_ASLR = 0x4,
    PS_MITIGATION_OPTION_HIGH_ENTROPY_ASLR = 0x5,
    PS_MITIGATION_OPTION_STRICT_HANDLE_CHECKS = 0x6,
    PS_MITIGATION_OPTION_WIN32K_SYSTEM_CALL_DISABLE = 0x7,
    PS_MITIGATION_OPTION_EXTENSION_POINT_DISABLE = 0x8,
    PS_MITIGATION_OPTION_PROHIBIT_DYNAMIC_CODE = 0x9,
    PS_MITIGATION_OPTION_CONTROL_FLOW_GUARD = 0xa,
    PS_MITIGATION_OPTION_BLOCK_NON_MICROSOFT_BINARIES = 0xb,
    PS_MITIGATION_OPTION_FONT_DISABLE = 0xc,
    PS_MITIGATION_OPTION_IMAGE_LOAD_NO_REMOTE = 0xd,
    PS_MITIGATION_OPTION_IMAGE_LOAD_NO_LOW_LABEL = 0xe,
    PS_MITIGATION_OPTION_IMAGE_LOAD_PREFER_SYSTEM32 = 0xf,
    PS_MITIGATION_OPTION_RETURN_FLOW_GUARD = 0x10,
    PS_MITIGATION_OPTION_LOADER_INTEGRITY_CONTINUITY = 0x11,
    PS_MITIGATION_OPTION_STRICT_CONTROL_FLOW_GUARD = 0x12,
    PS_MITIGATION_OPTION_RESTRICT_SET_THREAD_CONTEXT = 0x13,
    PS_MITIGATION_OPTION_ROP_STACKPIVOT = 0x14,
    PS_MITIGATION_OPTION_ROP_CALLER_CHECK = 0x15,
    PS_MITIGATION_OPTION_ROP_SIMEXEC = 0x16,
    PS_MITIGATION_OPTION_EXPORT_ADDRESS_FILTER = 0x17,
    PS_MITIGATION_OPTION_EXPORT_ADDRESS_FILTER_PLUS = 0x18,
    PS_MITIGATION_OPTION_RESTRICT_CHILD_PROCESS_CREATION = 0x19,
    PS_MITIGATION_OPTION_IMPORT_ADDRESS_FILTER = 0x1a,
    PS_MITIGATION_OPTION_MODULE_TAMPERING_PROTECTION = 0x1b,
    PS_MITIGATION_OPTION_RESTRICT_INDIRECT_BRANCH_PREDICTION = 0x1c,
    PS_MITIGATION_OPTION_SPECULATIVE_STORE_BYPASS_DISABLE = 0x1d,
    PS_MITIGATION_OPTION_ALLOW_DOWNGRADE_DYNAMIC_CODE_POLICY = 0x1e,
    PS_MITIGATION_OPTION_CET_USER_SHADOW_STACKS = 0x1f,
    PS_MITIGATION_OPTION_USER_CET_SET_CONTEXT_IP_VALIDATION = 0x20,
    PS_MITIGATION_OPTION_BLOCK_NON_CET_BINARIES = 0x21,
    PS_MITIGATION_OPTION_CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY = 0x24,
    PS_MITIGATION_OPTION_REDIRECTION_TRUST = 0x25
}PS_MITIGATION_OPTION, * PPS_MITIGATION_OPTION;

typedef enum _PS_PROTECTED_SIGNER // int32_t
{
    PsProtectedSignerNone = 0x0,
    PsProtectedSignerAuthenticode = 0x1,
    PsProtectedSignerCodeGen = 0x2,
    PsProtectedSignerAntimalware = 0x3,
    PsProtectedSignerLsa = 0x4,
    PsProtectedSignerWindows = 0x5,
    PsProtectedSignerWinTcb = 0x6,
    PsProtectedSignerWinSystem = 0x7,
    PsProtectedSignerApp = 0x8,
    PsProtectedSignerMax = 0x9
}PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

typedef enum _PS_PROTECTED_TYPE // int32_t
{
    PsProtectedTypeNone = 0x0,
    PsProtectedTypeProtectedLight = 0x1,
    PsProtectedTypeProtected = 0x2,
    PsProtectedTypeMax = 0x3
}PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_WAKE_REASON // int32_t
{
    PsWakeReasonUser = 0x0,
    PsWakeReasonExecutionRequired = 0x1,
    PsWakeReasonKernel = 0x2,
    PsWakeReasonInstrumentation = 0x3,
    PsWakeReasonPreserveProcess = 0x4,
    PsWakeReasonActivityReference = 0x5,
    PsWakeReasonWorkOnBehalf = 0x6,
    PsMaxWakeReasons = 0x7
}PS_WAKE_REASON, * PPS_WAKE_REASON;

#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE) // 0x60000
#define PS_ATTRIBUTE_DEBUG_PORT \
    PsAttributeValue(PsAttributeDebugPort, FALSE, TRUE, TRUE) // 0x60001
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE) // 0x60002
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE) // 0x10003
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE) // 0x10004
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE) // 0x20005
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE) // 0x6
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE) // 0x20007
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE) // 0x20008
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE) // 0x20009
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE) // 0x2000A
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE) // 0x2000B
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE) // 0x2000C
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE) // 0x2000D
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE) // 0x2000E
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, TRUE) // 0x60010
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, FALSE) // 0x20011

#define DELETE                                  0x00010000L
#define READ_CONTROL                            0x00020000L
#define WRITE_DAC                               0x00040000L
#define WRITE_OWNER                             0x00080000L
#define SYNCHRONIZE                             0x00100000L
#define STANDARD_RIGHTS_REQUIRED                0x000F0000L
#define STANDARD_RIGHTS_READ                    READ_CONTROL
#define STANDARD_RIGHTS_WRITE                   READ_CONTROL
#define STANDARD_RIGHTS_EXECUTE                 READ_CONTROL
#define STANDARD_RIGHTS_ALL                     0x001F0000L
#define SPECIFIC_RIGHTS_ALL                     0x0000FFFFL
#define ACCESS_SYSTEM_SECURITY                  0x01000000L
#define MAXIMUM_ALLOWED                         0x02000000L
#define GENERIC_READ                            0x80000000L
#define GENERIC_WRITE                           0x40000000L
#define GENERIC_EXECUTE                         0x20000000L
#define GENERIC_ALL                             0x10000000L

#define 	FILE_SUPERSEDE                      0x00000000
#define 	FILE_OPEN                           0x00000001
#define 	FILE_CREATE                         0x00000002
#define 	FILE_OPEN_IF                        0x00000003
#define 	FILE_OVERWRITE                      0x00000004
#define 	FILE_MAXIMUM_DISPOSITION            0x00000005

typedef enum _NT_CREATE_FILE_DISPOSITION// uint32_t
{
    /*FILE_SUPERSEDE = 0x0,
    FILE_CREATE = 0x2,
    FILE_OPEN = 0x1,
    FILE_OPEN_IF = 0x3,
    FILE_OVERWRITE = 0x4,*/
    FILE_OVERWRITE_IF = 0x5
}NT_CREATE_FILE_DISPOSITION, * PNT_CREATE_FILE_DISPOSITION;


#define 	FILE_DIRECTORY_FILE                 0x00000001
#define 	FILE_WRITE_THROUGH                  0x00000002
#define 	FILE_SEQUENTIAL_ONLY                0x00000004
#define 	FILE_NO_INTERMEDIATE_BUFFERING      0x00000008
#define 	FILE_SYNCHRONOUS_IO_ALERT           0x00000010
#define 	FILE_SYNCHRONOUS_IO_NONALERT        0x00000020
#define 	FILE_NON_DIRECTORY_FILE             0x00000040
#define 	FILE_CREATE_TREE_CONNECTION         0x00000080
#define 	FILE_COMPLETE_IF_OPLOCKED           0x00000100
#define 	FILE_NO_EA_KNOWLEDGE                0x00000200
#define 	FILE_OPEN_FOR_RECOVERY              0x00000400
#define 	FILE_RANDOM_ACCESS                  0x00000800
#define 	FILE_DELETE_ON_CLOSE                0x00001000
#define 	FILE_OPEN_BY_FILE_ID                0x00002000
#define 	FILE_OPEN_FOR_BACKUP_INTENT         0x00004000
#define 	FILE_NO_COMPRESSION                 0x00008000
#define 	FILE_OPEN_REQUIRING_OPLOCK          0x00010000
#define 	FILE_DISALLOW_EXCLUSIVE             0x00020000
#define 	FILE_SESSION_AWARE                  0x00040000
#define 	FILE_RESERVE_OPFILTER               0x00100000
#define 	FILE_OPEN_REPARSE_POINT             0x00200000
#define 	FILE_OPEN_NO_RECALL                 0x00400000
#define 	FILE_OPEN_FOR_FREE_SPACE_QUERY      0x00800000
#define 	FILE_COPY_STRUCTURED_STORAGE        0x00000041
#define 	FILE_STRUCTURED_STORAGE             0x00000441
#define 	FILE_SUPERSEDED                     0x00000000
#define 	FILE_OPENED                         0x00000001
#define 	FILE_CREATED                        0x00000002
#define 	FILE_OVERWRITTEN                    0x00000003
#define 	FILE_EXISTS                         0x00000004
#define 	FILE_DOES_NOT_EXIST                 0x00000005
#define 	FILE_WRITE_TO_END_OF_FILE           0xffffffff
#define 	FILE_USE_FILE_POINTER_POSITION      0xfffffffe

#define FILE_SHARE_READ                         0x00000001  
#define FILE_SHARE_WRITE                        0x00000002  
#define FILE_SHARE_DELETE                       0x00000004  
#define FILE_ATTRIBUTE_READONLY                 0x00000001  
#define FILE_ATTRIBUTE_HIDDEN                   0x00000002  
#define FILE_ATTRIBUTE_SYSTEM                   0x00000004  
#define FILE_ATTRIBUTE_DIRECTORY                0x00000010  
#define FILE_ATTRIBUTE_ARCHIVE                  0x00000020  
#define FILE_ATTRIBUTE_DEVICE                   0x00000040  
#define FILE_ATTRIBUTE_NORMAL                   0x00000080  
#define FILE_ATTRIBUTE_TEMPORARY                0x00000100  
#define FILE_ATTRIBUTE_SPARSE_FILE              0x00000200  
#define FILE_ATTRIBUTE_REPARSE_POINT            0x00000400  
#define FILE_ATTRIBUTE_COMPRESSED               0x00000800  
#define FILE_ATTRIBUTE_OFFLINE                  0x00001000  
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED      0x00002000  
#define FILE_ATTRIBUTE_ENCRYPTED                0x00004000  
#define FILE_ATTRIBUTE_INTEGRITY_STREAM         0x00008000  
#define FILE_ATTRIBUTE_VIRTUAL                  0x00010000  
#define FILE_ATTRIBUTE_NO_SCRUB_DATA            0x00020000  
#define FILE_ATTRIBUTE_EA                       0x00040000  
#define FILE_ATTRIBUTE_PINNED                   0x00080000  
#define FILE_ATTRIBUTE_UNPINNED                 0x00100000  
#define FILE_ATTRIBUTE_RECALL_ON_OPEN           0x00040000  
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS    0x00400000 

#define FILE_FLAG_WRITE_THROUGH                 0x80000000
#define FILE_FLAG_OVERLAPPED                    0x40000000
#define FILE_FLAG_NO_BUFFERING                  0x20000000
#define FILE_FLAG_RANDOM_ACCESS                 0x10000000
#define FILE_FLAG_SEQUENTIAL_SCAN               0x8000000
#define FILE_FLAG_DELETE_ON_CLOSE               0x4000000
#define FILE_FLAG_BACKUP_SEMANTICS              0x2000000
#define FILE_FLAG_POSIX_SEMANTICS               0x1000000
#define FILE_FLAG_SESSION_AWARE                 0x800000
#define FILE_FLAG_OPEN_REPARSE_POINT            0x200000
#define FILE_FLAG_OPEN_NO_RECALL                0x100000
#define FILE_FLAG_FIRST_PIPE_INSTANCE           0x80000

typedef enum _FILE_CREATION_DISPOSITION
{
    CREATE_NEW = 0x1,
    CREATE_ALWAYS = 0x2,
    OPEN_EXISTING = 0x3,
    OPEN_ALWAYS = 0x4,
    TRUNCATE_EXISTING = 0x5
}FILE_CREATION_DISPOSITION, * PFILE_CREATION_DISPOSITION;

typedef enum _FILE_ACCESS_FLAGS
{
    FILE_READ_DATA = 0x1,
    FILE_LIST_DIRECTORY = 0x1,
    FILE_WRITE_DATA = 0x2,
    FILE_ADD_FILE = 0x2,
    FILE_APPEND_DATA = 0x4,
    FILE_ADD_SUBDIRECTORY = 0x4,
    FILE_CREATE_PIPE_INSTANCE = 0x4,
    FILE_READ_EA = 0x8,
    FILE_WRITE_EA = 0x10,
    FILE_EXECUTE = 0x20,
    FILE_TRAVERSE = 0x20,
    FILE_DELETE_CHILD = 0x40,
    FILE_READ_ATTRIBUTES = 0x80,
    FILE_WRITE_ATTRIBUTES = 0x100,
    //READ_CONTROL = 0x20000,
    //SYNCHRONIZE = 0x100000,
    //STANDARD_RIGHTS_REQUIRED = 0xf0000,
    //STANDARD_RIGHTS_READ = 0x20000,
    //STANDARD_RIGHTS_WRITE = 0x20000,
    //STANDARD_RIGHTS_EXECUTE = 0x20000,
    //STANDARD_RIGHTS_ALL = 0x1f0000,
    //SPECIFIC_RIGHTS_ALL = 0xffff,
    FILE_ALL_ACCESS = 0x1f01ff,
    FILE_GENERIC_READ = 0x120089,
    FILE_GENERIC_WRITE = 0x120116,
    FILE_GENERIC_EXECUTE = 0x1200a0
}FILE_ACCESS_FLAGS, * PFILE_ACCESS_FLAGS;

typedef enum _FILE_FLAGS_AND_ATTRIBUTES
{
    /*FILE_ATTRIBUTE_READONLY = 0x1,
    FILE_ATTRIBUTE_HIDDEN = 0x2,
    FILE_ATTRIBUTE_SYSTEM = 0x4,
    FILE_ATTRIBUTE_DIRECTORY = 0x10,
    FILE_ATTRIBUTE_ARCHIVE = 0x20,
    FILE_ATTRIBUTE_DEVICE = 0x40,
    FILE_ATTRIBUTE_NORMAL = 0x80,
    FILE_ATTRIBUTE_TEMPORARY = 0x100,
    FILE_ATTRIBUTE_SPARSE_FILE = 0x200,
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400,
    FILE_ATTRIBUTE_COMPRESSED = 0x800,
    FILE_ATTRIBUTE_OFFLINE = 0x1000,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000,
    FILE_ATTRIBUTE_ENCRYPTED = 0x4000,
    FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x8000,
    FILE_ATTRIBUTE_VIRTUAL = 0x10000,
    FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x20000,
    FILE_ATTRIBUTE_EA = 0x40000,
    FILE_ATTRIBUTE_PINNED = 0x80000,
    FILE_ATTRIBUTE_UNPINNED = 0x100000,
    FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000,
    FILE_FLAG_WRITE_THROUGH = 0x80000000,
    FILE_FLAG_OVERLAPPED = 0x40000000,
    FILE_FLAG_NO_BUFFERING = 0x20000000,
    FILE_FLAG_RANDOM_ACCESS = 0x10000000,
    FILE_FLAG_SEQUENTIAL_SCAN = 0x8000000,
    FILE_FLAG_DELETE_ON_CLOSE = 0x4000000,
    FILE_FLAG_BACKUP_SEMANTICS = 0x2000000,
    FILE_FLAG_POSIX_SEMANTICS = 0x1000000,
    FILE_FLAG_SESSION_AWARE = 0x800000,
    FILE_FLAG_OPEN_REPARSE_POINT = 0x200000,
    FILE_FLAG_OPEN_NO_RECALL = 0x100000,
    FILE_FLAG_FIRST_PIPE_INSTANCE = 0x80000,*/
    PIPE_ACCESS_DUPLEX = 0x3,
    PIPE_ACCESS_INBOUND = 0x1,
    PIPE_ACCESS_OUTBOUND = 0x2,
    SECURITY_ANONYMOUS = 0x0,
    SECURITY_IDENTIFICATION = 0x10000,
    SECURITY_IMPERSONATION = 0x20000,
    SECURITY_DELEGATION = 0x30000,
    SECURITY_CONTEXT_TRACKING = 0x40000,
    SECURITY_EFFECTIVE_ONLY = 0x80000,
    SECURITY_SQOS_PRESENT = 0x100000,
    SECURITY_VALID_SQOS_FLAGS = 0x1f0000
}FILE_FLAGS_AND_ATTRIBUTES, * PFILE_FLAGS_AND_ATTRIBUTES;

typedef enum _FILE_MAP// : uint32_t
{
    FILE_MAP_WRITE = 0x2,
    FILE_MAP_READ = 0x4,
    FILE_MAP_ALL_ACCESS = 0xf001f,
    FILE_MAP_EXECUTE = 0x20,
    FILE_MAP_COPY = 0x1,
    FILE_MAP_RESERVE = 0x80000000,
    FILE_MAP_TARGETS_INVALID = 0x40000000,
    FILE_MAP_LARGE_PAGES = 0x20000000
}FILE_MAP, * PFILE_MAP;

typedef enum _FILE_NAME // uint32_t
{
    FILE_NAME_NORMALIZED = 0x0,
    FILE_NAME_OPENED = 0x8
}FILE_NAME, * PFILE_NAME;

typedef struct _ACCESS_REASONS
{
    DWORD Data[0x20];
}ACCESS_REASONS, * PACCESS_REASONS;

typedef enum _ACCESS_REASON_TYPE // int32_t
{
    AccessReasonNone = 0x0,
    AccessReasonAllowedAce = 0x10000,
    AccessReasonDeniedAce = 0x20000,
    AccessReasonAllowedParentAce = 0x30000,
    AccessReasonDeniedParentAce = 0x40000,
    AccessReasonNotGrantedByCape = 0x50000,
    AccessReasonNotGrantedByParentCape = 0x60000,
    AccessReasonNotGrantedToAppContainer = 0x70000,
    AccessReasonMissingPrivilege = 0x100000,
    AccessReasonFromPrivilege = 0x200000,
    AccessReasonIntegrityLevel = 0x300000,
    AccessReasonOwnership = 0x400000,
    AccessReasonNullDacl = 0x500000,
    AccessReasonEmptyDacl = 0x600000,
    AccessReasonNoSD = 0x700000,
    AccessReasonNoGrant = 0x800000,
    AccessReasonTrustLabel = 0x900000,
    AccessReasonFilterAce = 0xa00000
}ACCESS_REASON_TYPE, * PACCESS_REASON_TYPE;

typedef enum _TOKEN_PRIVILEGES_ATTRIBUTES // uint32_t
{
    SE_PRIVILEGE_ENABLED = 0x2,
    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1,
    SE_PRIVILEGE_REMOVED = 0x4,
    SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000
}TOKEN_PRIVILEGES_ATTRIBUTES, * PTOKEN_PRIVILEGES_ATTRIBUTES;

typedef struct LUID_AND_ATTRIBUTES
{
    LUID Luid;
    TOKEN_PRIVILEGES_ATTRIBUTES Attributes;
}LUID_AND_ATTRIBUTES, * PLUID_AND_ATTRIBUTES;

typedef struct _PRIVILEGE_SET
{
    DWORD PrivilegeCount;
    DWORD Control;
    LUID_AND_ATTRIBUTES* Privilege;

}PRIVILEGE_SET, * PPRIVILEGE_SET;
typedef struct _INITIAL_PRIVILEGE_SET
{
    DWORD PrivilegeCount;
    DWORD Control;
    LUID_AND_ATTRIBUTES Privilege[0x3];
}INITIAL_PRIVILEGE_SET, * PINITIAL_PRIVILEGE_SET;

typedef enum _SECURITY_IMPERSONATION_LEVEL // uint32_t
{
    SecurityAnonymous = 0x0,
    SecurityIdentification = 0x1,
    SecurityImpersonation = 0x2,
    SecurityDelegation = 0x3
}SECURITY_IMPERSONATION_LEVEL, * PSECURITY_IMPERSONATION_LEVEL;

typedef struct _SECURITY_SUBJECT_CONTEXT
{
    PVOID ClientToken;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    PVOID PrimaryToken;
    PVOID ProcessAuditId;
}SECURITY_SUBJECT_CONTEXT, * PSECURITY_SUBJECT_CONTEXT;

typedef struct _ACCESS_STATE
{
    LUID OperationID;
    UCHAR SecurityEvaluated;
    UCHAR GenerateAudit;
    UCHAR GenerateOnClose;
    UCHAR PrivilegesAllocated;
    DWORD Flags;
    DWORD RemainingDesiredAccess;
    DWORD PreviouslyGrantedAccess;
    DWORD OriginalDesiredAccess;

    SECURITY_SUBJECT_CONTEXT SubjectSecurityContext;
    PVOID SecurityDescriptor;
    PVOID AuxData;
    union
    {
        INITIAL_PRIVILEGE_SET InitialPrivilegeSet;
        PRIVILEGE_SET PrivilegeSet;
    } Privileges;
    UCHAR AuditPrivileges;
    UNICODE_STRING ObjectName;
    UNICODE_STRING ObjectTypeName;
}ACCESS_STATE, * PACCESS_STATE;


typedef enum _TOKEN_ACCESS_MASK //: uint32_t
{
    TOKEN_DELETE = 0x10000,
    TOKEN_READ_CONTROL = 0x20000,
    TOKEN_WRITE_DAC = 0x40000,
    TOKEN_WRITE_OWNER = 0x80000,
    TOKEN_ACCESS_SYSTEM_SECURITY = 0x1000000,
    TOKEN_ASSIGN_PRIMARY = 0x1,
    TOKEN_DUPLICATE = 0x2,
    TOKEN_IMPERSONATE = 0x4,
    TOKEN_QUERY = 0x8,
    TOKEN_QUERY_SOURCE = 0x10,
    TOKEN_ADJUST_PRIVILEGES = 0x20,
    TOKEN_ADJUST_GROUPS = 0x40,
    TOKEN_ADJUST_DEFAULT = 0x80,
    TOKEN_ADJUST_SESSIONID = 0x100,
    TOKEN_ALL_ACCESS = 0xf00ff
}TOKEN_ACCESS_MASK, * PTOKEN_ACCESS_MASK;

typedef enum _TOKEN_INFORMATION_CLASS// : uint32_t
{
    TokenUser = 0x1,
    TokenGroups = 0x2,
    TokenPrivileges = 0x3,
    TokenOwner = 0x4,
    TokenPrimaryGroup = 0x5,
    TokenDefaultDacl = 0x6,
    TokenSource = 0x7,
    TokenType = 0x8,
    TokenImpersonationLevel = 0x9,
    TokenStatistics = 0xa,
    TokenRestrictedSids = 0xb,
    TokenSessionId = 0xc,
    TokenGroupsAndPrivileges = 0xd,
    TokenSessionReference = 0xe,
    TokenSandBoxInert = 0xf,
    TokenAuditPolicy = 0x10,
    TokenOrigin = 0x11,
    TokenElevationType = 0x12,
    TokenLinkedToken = 0x13,
    TokenElevation = 0x14,
    TokenHasRestrictions = 0x15,
    TokenAccessInformation = 0x16,
    TokenVirtualizationAllowed = 0x17,
    TokenVirtualizationEnabled = 0x18,
    TokenIntegrityLevel = 0x19,
    TokenUIAccess = 0x1a,
    TokenMandatoryPolicy = 0x1b,
    TokenLogonSid = 0x1c,
    TokenIsAppContainer = 0x1d,
    TokenCapabilities = 0x1e,
    TokenAppContainerSid = 0x1f,
    TokenAppContainerNumber = 0x20,
    TokenUserClaimAttributes = 0x21,
    TokenDeviceClaimAttributes = 0x22,
    TokenRestrictedUserClaimAttributes = 0x23,
    TokenRestrictedDeviceClaimAttributes = 0x24,
    TokenDeviceGroups = 0x25,
    TokenRestrictedDeviceGroups = 0x26,
    TokenSecurityAttributes = 0x27,
    TokenIsRestricted = 0x28,
    TokenProcessTrustLevel = 0x29,
    TokenPrivateNameSpace = 0x2a,
    TokenSingletonAttributes = 0x2b,
    TokenBnoIsolation = 0x2c,
    TokenChildProcessFlags = 0x2d,
    TokenIsLessPrivilegedAppContainer = 0x2e,
    TokenIsSandboxed = 0x2f,
    MaxTokenInfoClass = 0x30
}TOKEN_INFORMATION_CLASS, * PTOKEN_INFORMATION_CLASS;

typedef struct _TOKEN_LINKED_TOKEN
{
    PVOID LinkedToken;
}TOKEN_LINKED_TOKEN, * PTOKEN_LINKED_TOKEN;

typedef struct _TOKEN_MANDATORY_LABEL
{
    SID_AND_ATTRIBUTES Label;
}TOKEN_MANDATORY_LABEL, * PTOKEN_MANDATORY_LABEL;

typedef struct _TOKEN_MANDATORY_POLICY
{
    DWORD Policy;
}TOKEN_MANDATORY_POLICY, * PTOKEN_MANDATORY_POLICY;

typedef struct _TOKEN_ORIGIN
{
    LUID OriginatingLogonSession;
}TOKEN_ORIGIN, * PTOKEN_ORIGIN;

typedef struct _TOKEN_OWNER
{
    PVOID Owner;
}TOKEN_OWNER, * PTOKEN_OWNER;

typedef struct _TOKEN_PRIMARY_GROUP
{
    PVOID PrimaryGroup;
}TOKEN_PRIMARY_GROUP, * PTOKEN_PRIMARY_GROUP;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
    QWORD Version;
    UNICODE_STRING Name;
}TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
    PVOID pValue;
    DWORD ValueLength;
}TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
    UNICODE_STRING Name;
    WORD ValueType;
    WORD Reserved;
    DWORD Flags;
    DWORD ValueCount;

    union
    {
        __int64* pInt64;
        QWORD* pUint64;
        UNICODE_STRING* pString;
        TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE* pFqbn;
        TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE* pOctetString;
    } Values;
}TOKEN_SECURITY_ATTRIBUTE_V1, * PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
    WORD Version;
    WORD Reserved;
    DWORD AttributeCount;
    union
    {
        TOKEN_SECURITY_ATTRIBUTE_V1* pAttributeV1;
    } Attribute;
}TOKEN_SECURITY_ATTRIBUTES_INFORMATION, * PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef enum _TOKEN_SECURITY_ATTRIBUTE_OPERATION // int32_t
{
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_NONE = 0x0,
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_REPLACE_ALL = 0x1,
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_ADD = 0x2,
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_DELETE = 0x3,
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_REPLACE = 0x4
}TOKEN_SECURITY_ATTRIBUTE_OPERATION, * PTOKEN_SECURITY_ATTRIBUTE_OPERATION;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION
{
    TOKEN_SECURITY_ATTRIBUTES_INFORMATION* Attributes;
    TOKEN_SECURITY_ATTRIBUTE_OPERATION* Operations;
}TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION, * PTOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_RELATIVE_V1
{
    DWORD Name;
    WORD ValueType;
    WORD Reserved;
    DWORD Flags;
    DWORD ValueCount;
    union
    {
        DWORD pInt64[0x1];
        DWORD pUint64[0x1];
        DWORD ppString[0x1];
        DWORD pFqbn[0x1];
        DWORD pOctetString[0x1];
    } Values;
}TOKEN_SECURITY_ATTRIBUTE_RELATIVE_V1, * PTOKEN_SECURITY_ATTRIBUTE_RELATIVE_V1;

typedef struct _TOKEN_SID_INFORMATION
{
    PVOID Sid;
}TOKEN_SID_INFORMATION, * PTOKEN_SID_INFORMATION;

typedef struct _TOKEN_SOURCE
{
    char SourceName[0x8];
    LUID SourceIdentifier;
}TOKEN_SOURCE, * PTOKEN_SOURCE;

typedef enum _TOKEN_TYPE// int32_t
{
    TokenPrimary = 0x1,
    TokenImpersonation = 0x2
}TOKEN_TYPE, * PTOKEN_TYPE;

typedef struct _TOKEN_STATISTICS
{
    LUID TokenId;
    LUID AuthenticationId;
    LARGE_INTEGER ExpirationTime;
    TOKEN_TYPE TokenType;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    DWORD DynamicCharged;
    DWORD DynamicAvailable;
    DWORD GroupCount;
    DWORD PrivilegeCount;
    LUID ModifiedId;
}TOKEN_STATISTICS, * PTOKEN_STATISTICS;

typedef struct _TOKEN_USER
{
    SID_AND_ATTRIBUTES User;
}TOKEN_USER, * PTOKEN_USER;

typedef struct _TOKEN_USER_CLAIMS
{
    PVOID UserClaims;
}TOKEN_USER_CLAIMS, * PTOKEN_USER_CLAIMS;

typedef enum _TRUSTEE_FORM // uint32_t
{
    TRUSTEE_IS_SID = 0x0,
    TRUSTEE_IS_NAME = 0x1,
    TRUSTEE_BAD_FORM = 0x2,
    TRUSTEE_IS_OBJECTS_AND_SID = 0x3,
    TRUSTEE_IS_OBJECTS_AND_NAME = 0x4
}TRUSTEE_FORM, * PTRUSTEE_FORM;

typedef enum _TRUSTEE_TYPE // uint32_t
{
    TRUSTEE_IS_UNKNOWN = 0x0,
    TRUSTEE_IS_USER = 0x1,
    TRUSTEE_IS_GROUP = 0x2,
    TRUSTEE_IS_DOMAIN = 0x3,
    TRUSTEE_IS_ALIAS = 0x4,
    TRUSTEE_IS_WELL_KNOWN_GROUP = 0x5,
    TRUSTEE_IS_DELETED = 0x6,
    TRUSTEE_IS_INVALID = 0x7,
    TRUSTEE_IS_COMPUTER = 0x8
}TRUSTEE_TYPE, * PTRUSTEE_TYPE;

typedef enum _WELL_KNOWN_SID_TYPE // uint32_t
{
    WinNullSid = 0x0,
    WinWorldSid = 0x1,
    WinLocalSid = 0x2,
    WinCreatorOwnerSid = 0x3,
    WinCreatorGroupSid = 0x4,
    WinCreatorOwnerServerSid = 0x5,
    WinCreatorGroupServerSid = 0x6,
    WinNtAuthoritySid = 0x7,
    WinDialupSid = 0x8,
    WinNetworkSid = 0x9,
    WinBatchSid = 0xa,
    WinInteractiveSid = 0xb,
    WinServiceSid = 0xc,
    WinAnonymousSid = 0xd,
    WinProxySid = 0xe,
    WinEnterpriseControllersSid = 0xf,
    WinSelfSid = 0x10,
    WinAuthenticatedUserSid = 0x11,
    WinRestrictedCodeSid = 0x12,
    WinTerminalServerSid = 0x13,
    WinRemoteLogonIdSid = 0x14,
    WinLogonIdsSid = 0x15,
    WinLocalSystemSid = 0x16,
    WinLocalServiceSid = 0x17,
    WinNetworkServiceSid = 0x18,
    WinBuiltinDomainSid = 0x19,
    WinBuiltinAdministratorsSid = 0x1a,
    WinBuiltinUsersSid = 0x1b,
    WinBuiltinGuestsSid = 0x1c,
    WinBuiltinPowerUsersSid = 0x1d,
    WinBuiltinAccountOperatorsSid = 0x1e,
    WinBuiltinSystemOperatorsSid = 0x1f,
    WinBuiltinPrintOperatorsSid = 0x20,
    WinBuiltinBackupOperatorsSid = 0x21,
    WinBuiltinReplicatorSid = 0x22,
    WinBuiltinPreWindows2000CompatibleAccessSid = 0x23,
    WinBuiltinRemoteDesktopUsersSid = 0x24,
    WinBuiltinNetworkConfigurationOperatorsSid = 0x25,
    WinAccountAdministratorSid = 0x26,
    WinAccountGuestSid = 0x27,
    WinAccountKrbtgtSid = 0x28,
    WinAccountDomainAdminsSid = 0x29,
    WinAccountDomainUsersSid = 0x2a,
    WinAccountDomainGuestsSid = 0x2b,
    WinAccountComputersSid = 0x2c,
    WinAccountControllersSid = 0x2d,
    WinAccountCertAdminsSid = 0x2e,
    WinAccountSchemaAdminsSid = 0x2f,
    WinAccountEnterpriseAdminsSid = 0x30,
    WinAccountPolicyAdminsSid = 0x31,
    WinAccountRasAndIasServersSid = 0x32,
    WinNTLMAuthenticationSid = 0x33,
    WinDigestAuthenticationSid = 0x34,
    WinSChannelAuthenticationSid = 0x35,
    WinThisOrganizationSid = 0x36,
    WinOtherOrganizationSid = 0x37,
    WinBuiltinIncomingForestTrustBuildersSid = 0x38,
    WinBuiltinPerfMonitoringUsersSid = 0x39,
    WinBuiltinPerfLoggingUsersSid = 0x3a,
    WinBuiltinAuthorizationAccessSid = 0x3b,
    WinBuiltinTerminalServerLicenseServersSid = 0x3c,
    WinBuiltinDCOMUsersSid = 0x3d,
    WinBuiltinIUsersSid = 0x3e,
    WinIUserSid = 0x3f,
    WinBuiltinCryptoOperatorsSid = 0x40,
    WinUntrustedLabelSid = 0x41,
    WinLowLabelSid = 0x42,
    WinMediumLabelSid = 0x43,
    WinHighLabelSid = 0x44,
    WinSystemLabelSid = 0x45,
    WinWriteRestrictedCodeSid = 0x46,
    WinCreatorOwnerRightsSid = 0x47,
    WinCacheablePrincipalsGroupSid = 0x48,
    WinNonCacheablePrincipalsGroupSid = 0x49,
    WinEnterpriseReadonlyControllersSid = 0x4a,
    WinAccountReadonlyControllersSid = 0x4b,
    WinBuiltinEventLogReadersGroup = 0x4c,
    WinNewEnterpriseReadonlyControllersSid = 0x4d,
    WinBuiltinCertSvcDComAccessGroup = 0x4e,
    WinMediumPlusLabelSid = 0x4f,
    WinLocalLogonSid = 0x50,
    WinConsoleLogonSid = 0x51,
    WinThisOrganizationCertificateSid = 0x52,
    WinApplicationPackageAuthoritySid = 0x53,
    WinBuiltinAnyPackageSid = 0x54,
    WinCapabilityInternetClientSid = 0x55,
    WinCapabilityInternetClientServerSid = 0x56,
    WinCapabilityPrivateNetworkClientServerSid = 0x57,
    WinCapabilityPicturesLibrarySid = 0x58,
    WinCapabilityVideosLibrarySid = 0x59,
    WinCapabilityMusicLibrarySid = 0x5a,
    WinCapabilityDocumentsLibrarySid = 0x5b,
    WinCapabilitySharedUserCertificatesSid = 0x5c,
    WinCapabilityEnterpriseAuthenticationSid = 0x5d,
    WinCapabilityRemovableStorageSid = 0x5e,
    WinBuiltinRDSRemoteAccessServersSid = 0x5f,
    WinBuiltinRDSEndpointServersSid = 0x60,
    WinBuiltinRDSManagementServersSid = 0x61,
    WinUserModeDriversSid = 0x62,
    WinBuiltinHyperVAdminsSid = 0x63,
    WinAccountCloneableControllersSid = 0x64,
    WinBuiltinAccessControlAssistanceOperatorsSid = 0x65,
    WinBuiltinRemoteManagementUsersSid = 0x66,
    WinAuthenticationAuthorityAssertedSid = 0x67,
    WinAuthenticationServiceAssertedSid = 0x68,
    WinLocalAccountSid = 0x69,
    WinLocalAccountAndAdministratorSid = 0x6a,
    WinAccountProtectedUsersSid = 0x6b,
    WinCapabilityAppointmentsSid = 0x6c,
    WinCapabilityContactsSid = 0x6d,
    WinAccountDefaultSystemManagedSid = 0x6e,
    WinBuiltinDefaultSystemManagedGroupSid = 0x6f,
    WinBuiltinStorageReplicaAdminsSid = 0x70,
    WinAccountKeyAdminsSid = 0x71,
    WinAccountEnterpriseKeyAdminsSid = 0x72,
    WinAuthenticationKeyTrustSid = 0x73,
    WinAuthenticationKeyPropertyMFASid = 0x74,
    WinAuthenticationKeyPropertyAttestationSid = 0x75,
    WinAuthenticationFreshKeyAuthSid = 0x76,
    WinBuiltinDeviceOwnersSid = 0x77
}WELL_KNOWN_SID_TYPE, * PWELL_KNOWN_SID_TYPE;

typedef struct _TRUSTEE_W
{
    struct TRUSTEE_W* pMultipleTrustee;
    enum MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
    enum TRUSTEE_FORM TrusteeForm;
    enum TRUSTEE_TYPE TrusteeType;
    PWSTR ptstrName;
}TRUSTEE_W, * PTRUSTEE_W;

/*typedef struct _TOKEN_PRIVILEGES
{
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[0x1];
}TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;*/
typedef struct _TOKEN_PRIVILEGES
{
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES* Privileges;
}TOKEN_PRIVILEGES, * PTOKEN_PRIVILEGES;

typedef struct _TOKEN_GROUPS
{
    DWORD GroupCount;
    SID_AND_ATTRIBUTES Groups[0x1];
}TOKEN_GROUPS, * PTOKEN_GROUPS;

typedef struct _TOKEN_GROUPS_AND_PRIVILEGES
{
    DWORD SidCount;
    DWORD SidLength;
    SID_AND_ATTRIBUTES* Sids;
    DWORD RestrictedSidCount;
    DWORD RestrictedSidLength;
    SID_AND_ATTRIBUTES* RestrictedSids;
    DWORD PrivilegeCount;
    DWORD PrivilegeLength;
    LUID_AND_ATTRIBUTES* Privileges;
    LUID AuthenticationId;
}TOKEN_GROUPS_AND_PRIVILEGES, * PTOKEN_GROUPS_AND_PRIVILEGES;

typedef enum _SECURITY_AUTO_INHERIT_FLAGS // uint32_t
{
    SEF_AVOID_OWNER_CHECK = 0x10,
    SEF_AVOID_OWNER_RESTRICTION = 0x1000,
    SEF_AVOID_PRIVILEGE_CHECK = 0x8,
    SEF_DACL_AUTO_INHERIT = 0x1,
    SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT = 0x4,
    SEF_DEFAULT_GROUP_FROM_PARENT = 0x40,
    SEF_DEFAULT_OWNER_FROM_PARENT = 0x20,
    SEF_MACL_NO_EXECUTE_UP = 0x400,
    SEF_MACL_NO_READ_UP = 0x200,
    SEF_MACL_NO_WRITE_UP = 0x100,
    SEF_SACL_AUTO_INHERIT = 0x2
}SECURITY_AUTO_INHERIT_FLAGS, * PSECURITY_AUTO_INHERIT_FLAGS;

typedef enum _SID_NAME_USE // uint32_t
{
    SidTypeUser = 0x1,
    SidTypeGroup = 0x2,
    SidTypeDomain = 0x3,
    SidTypeAlias = 0x4,
    SidTypeWellKnownGroup = 0x5,
    SidTypeDeletedAccount = 0x6,
    SidTypeInvalid = 0x7,
    SidTypeUnknown = 0x8,
    SidTypeComputer = 0x9,
    SidTypeLabel = 0xa,
    SidTypeLogonSession = 0xb
}SID_NAME_USE, * PSID_NAME_USE;

typedef enum _FIND_FIRST_EX_FLAGS
{
    FIND_FIRST_EX_CASE_SENSITIVE = 0x1,
    FIND_FIRST_EX_LARGE_FETCH = 0x2,
    FIND_FIRST_EX_ON_DISK_ENTRIES_ONLY = 0x4
}FIND_FIRST_EX_FLAGS, * PFIND_FIRST_EX_FLAGS;

typedef enum _FINDEX_INFO_LEVELS // uint32_t
{
    FindExInfoStandard = 0x0,
    FindExInfoBasic = 0x1,
    FindExInfoMaxInfoLevel = 0x2
}FINDEX_INFO_LEVELS, * PFINDEX_INFO_LEVELS;

typedef enum _FINDEX_SEARCH_OPS /// uint32_t
{
    FindExSearchNameMatch = 0x0,
    FindExSearchLimitToDirectories = 0x1,
    FindExSearchLimitToDevices = 0x2,
    FindExSearchMaxSearchOp = 0x3
}FINDEX_SEARCH_OPS, * PFINDEX_SEARCH_OPS;

typedef enum _GET_FILEEX_INFO_LEVELS // uint32_t
{
    GetFileExInfoStandard = 0x0,
    GetFileExMaxInfoLevel = 0x1
}GET_FILEEX_INFO_LEVELS, * PGET_FILEEX_INFO_LEVELS;

typedef enum _REG_CREATE_KEY_DISPOSITION // uint32_t
{
    REG_CREATED_NEW_KEY = 0x1,
    REG_OPENED_EXISTING_KEY = 0x2
}REG_CREATE_KEY_DISPOSITION, * PREG_CREATE_KEY_DISPOSITION;

typedef enum _REG_OPEN_CREATE_OPTIONS // uint32_t
{
    REG_OPTION_RESERVED = 0x0,
    REG_OPTION_NON_VOLATILE = 0x0,
    REG_OPTION_VOLATILE = 0x1,
    REG_OPTION_CREATE_LINK = 0x2,
    REG_OPTION_BACKUP_RESTORE = 0x4,
    REG_OPTION_OPEN_LINK = 0x8,
    REG_OPTION_DONT_VIRTUALIZE = 0x10
}REG_OPEN_CREATE_OPTIONS, * PREG_OPEN_CREATE_OPTIONS;

typedef struct _WIN32_FIND_DATAA
{
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[0x104];
    CHAR cAlternateFileName[0xe];
}WIN32_FIND_DATAA, * PWIN32_FIND_DATAA;

typedef struct _WIN32_FIND_DATAW
{
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    char cFileName[0x104];
    char cAlternateFileName[0xe];
}WIN32_FIND_DATAW, * PWIN32_FIND_DATAW;

typedef enum _REG_SAM_FLAGS //: uint32_t
{
    KEY_QUERY_VALUE = 0x1,
    KEY_SET_VALUE = 0x2,
    KEY_CREATE_SUB_KEY = 0x4,
    KEY_ENUMERATE_SUB_KEYS = 0x8,
    KEY_NOTIFY = 0x10,
    KEY_CREATE_LINK = 0x20,
    KEY_WOW64_32KEY = 0x200,
    KEY_WOW64_64KEY = 0x100,
    KEY_WOW64_RES = 0x300,
    KEY_READ = 0x20019,
    KEY_WRITE = 0x20006,
    KEY_EXECUTE = 0x20019,
    KEY_ALL_ACCESS = 0xf003f
}REG_SAM_FLAGS, * PREG_SAM_FLAGS;

typedef enum _REG_VALUE_TYPE //: uint32_t
{
    REG_NONE = 0x0,
    REG_SZ = 0x1,
    REG_EXPAND_SZ = 0x2,
    REG_BINARY = 0x3,
    REG_DWORD = 0x4,
    REG_DWORD_LITTLE_ENDIAN = 0x4,
    REG_DWORD_BIG_ENDIAN = 0x5,
    REG_LINK = 0x6,
    REG_MULTI_SZ = 0x7,
    REG_RESOURCE_LIST = 0x8,
    REG_FULL_RESOURCE_DESCRIPTOR = 0x9,
    REG_RESOURCE_REQUIREMENTS_LIST = 0xa,
    REG_QWORD = 0xb,
    REG_QWORD_LITTLE_ENDIAN = 0xb
}REG_VALUE_TYPE, * PREG_VALUE_TYPE;

typedef enum _REG_NOTIFY_CLASS //int32_t
{
    RegNtDeleteKey = 0x0,
    RegNtPreDeleteKey = 0x0,
    RegNtSetValueKey = 0x1,
    RegNtPreSetValueKey = 0x1,
    RegNtDeleteValueKey = 0x2,
    RegNtPreDeleteValueKey = 0x2,
    RegNtSetInformationKey = 0x3,
    RegNtPreSetInformationKey = 0x3,
    RegNtRenameKey = 0x4,
    RegNtPreRenameKey = 0x4,
    RegNtEnumerateKey = 0x5,
    RegNtPreEnumerateKey = 0x5,
    RegNtEnumerateValueKey = 0x6,
    RegNtPreEnumerateValueKey = 0x6,
    RegNtQueryKey = 0x7,
    RegNtPreQueryKey = 0x7,
    RegNtQueryValueKey = 0x8,
    RegNtPreQueryValueKey = 0x8,
    RegNtQueryMultipleValueKey = 0x9,
    RegNtPreQueryMultipleValueKey = 0x9,
    RegNtPreCreateKey = 0xa,
    RegNtPostCreateKey = 0xb,
    RegNtPreOpenKey = 0xc,
    RegNtPostOpenKey = 0xd,
    RegNtKeyHandleClose = 0xe,
    RegNtPreKeyHandleClose = 0xe,
    RegNtPostDeleteKey = 0xf,
    RegNtPostSetValueKey = 0x10,
    RegNtPostDeleteValueKey = 0x11,
    RegNtPostSetInformationKey = 0x12,
    RegNtPostRenameKey = 0x13,
    RegNtPostEnumerateKey = 0x14,
    RegNtPostEnumerateValueKey = 0x15,
    RegNtPostQueryKey = 0x16,
    RegNtPostQueryValueKey = 0x17,
    RegNtPostQueryMultipleValueKey = 0x18,
    RegNtPostKeyHandleClose = 0x19,
    RegNtPreCreateKeyEx = 0x1a,
    RegNtPostCreateKeyEx = 0x1b,
    RegNtPreOpenKeyEx = 0x1c,
    RegNtPostOpenKeyEx = 0x1d,
    RegNtPreFlushKey = 0x1e,
    RegNtPostFlushKey = 0x1f,
    RegNtPreLoadKey = 0x20,
    RegNtPostLoadKey = 0x21,
    RegNtPreUnLoadKey = 0x22,
    RegNtPostUnLoadKey = 0x23,
    RegNtPreQueryKeySecurity = 0x24,
    RegNtPostQueryKeySecurity = 0x25,
    RegNtPreSetKeySecurity = 0x26,
    RegNtPostSetKeySecurity = 0x27,
    RegNtCallbackObjectContextCleanup = 0x28,
    RegNtPreRestoreKey = 0x29,
    RegNtPostRestoreKey = 0x2a,
    RegNtPreSaveKey = 0x2b,
    RegNtPostSaveKey = 0x2c,
    RegNtPreReplaceKey = 0x2d,
    RegNtPostReplaceKey = 0x2e,
    RegNtPreQueryKeyName = 0x2f,
    RegNtPostQueryKeyName = 0x30,
    MaxRegNtNotifyClass = 0x31
}REG_NOTIFY_CLASS, * PREG_NOTIFY_CLASS;

#define PIPE_ACCESS_DUPLEX                      0x3
#define PIPE_ACCESS_INBOUND                     0x1
#define PIPE_ACCESS_OUTBOUND                    0x2
#define SECURITY_ANONYMOUS                      0x0
#define SECURITY_IDENTIFICATION                 0x10000
#define SECURITY_IMPERSONATION                  0x20000
#define SECURITY_DELEGATION                     0x30000
#define SECURITY_CONTEXT_TRACKING               0x40000
#define SECURITY_EFFECTIVE_ONLY                 0x80000
#define SECURITY_SQOS_PRESENT                   0x100000
#define SECURITY_VALID_SQOS_FLAGS               0x1f0000

#define FILE_MAP_WRITE                          0x2
#define FILE_MAP_READ                           0x4
#define FILE_MAP_ALL_ACCESS                     0xf001f
#define FILE_MAP_EXECUTE                        0x20
#define FILE_MAP_COPY                           0x1
#define FILE_MAP_RESERVE                        0x80000000
#define FILE_MAP_TARGETS_INVALID                0x40000000
#define FILE_MAP_LARGE_PAGES                    0x20000000

#define OBJ_INHERIT                             0x00000002
#define OBJ_PERMANENT                           0x00000010
#define	OBJ_EXCLUSIVE                           0x00000020
#define	OBJ_CASE_INSENSITIVE                    0x00000040
#define	OBJ_OPENIF                              0x00000080
#define	OBJ_OPENLINK                            0x00000100
#define	OBJ_KERNEL_HANDLE                       0x00000200
#define	OBJ_FORCE_ACCESS_CHECK                  0x00000400
#define	OBJ_VALID_ATTRIBUTES                    0x000007f2

#define SE_MIN_WELL_KNOWN_PRIVILEGE             (2L)
#define SE_CREATE_TOKEN_PRIVILEGE               (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE         (3L)
#define SE_LOCK_MEMORY_PRIVILEGE                (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE             (5L)
#define SE_MACHINE_ACCOUNT_PRIVILEGE            (6L)
#define SE_TCB_PRIVILEGE                        (7L)
#define SE_SECURITY_PRIVILEGE                   (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE             (9L)
#define SE_LOAD_DRIVER_PRIVILEGE                (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE             (11L)
#define SE_SYSTEMTIME_PRIVILEGE                 (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE        (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE          (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE            (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE           (16L)
#define SE_BACKUP_PRIVILEGE                     (17L)
#define SE_RESTORE_PRIVILEGE                    (18L)
#define SE_SHUTDOWN_PRIVILEGE                   (19L)
#define SE_DEBUG_PRIVILEGE                      (20L)
#define SE_AUDIT_PRIVILEGE                      (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE         (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE              (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE            (24L)
#define SE_UNDOCK_PRIVILEGE                     (25L)
#define SE_SYNC_AGENT_PRIVILEGE                 (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE          (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE              (28L)
#define SE_IMPERSONATE_PRIVILEGE                (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE              (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE     (31L)
#define SE_RELABEL_PRIVILEGE                    (32L)
#define SE_INC_WORKING_SET_PRIVILEGE            (33L)
#define SE_TIME_ZONE_PRIVILEGE                  (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE       (35L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE SE_CREATE_SYMBOLIC_LINK_PRIVILEGE

#define PROCESS_CREATE_FLAGS_BREAKAWAY                      0x00000001 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT               0x00000002 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES                0x00000004 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE         0x00000008 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_LARGE_PAGES                    0x00000010 // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL          0x00000020 // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS              0x00000040 // NtCreateUserProcess only
#define PROCESS_CREATE_FLAGS_CREATE_SESSION                 0x00000080 // NtCreateProcessEx & NtCreateUserProcess, requires SeLoadDriver
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT            0x00000100 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_SUSPENDED                      0x00000200 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY                0x00000400 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_MINIMAL_PROCESS                0x00000800 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_RELEASE_SECTION                0x00001000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL                  0x00002000 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL_REDUCED_COMMIT   0x00004000 //
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS              0x00008000 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_CREATE_STORE                   0x00020000 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT      0x00040000 // NtCreateProcessEx & NtCreateUserProces

typedef enum _SYSTEM_DLL_TYPE //int32_t
{
    PsNativeSystemDll = 0x0,
    PsWowX86SystemDll = 0x1,
    PsWowArm32SystemDll = 0x2,
    PsWowAmd64SystemDll = 0x3,
    PsWowChpeX86SystemDll = 0x4,
    PsVsmEnclaveRuntimeDll = 0x5,
    PsSystemDllTotalTypes = 0x6
}SYSTEM_DLL_TYPE, * PSYSTEM_DLL_TYPE;

typedef enum _PROCESS_SECTION_TYPE // int32_t
{
    ProcessSectionData = 0x0,
    ProcessSectionImage = 0x1,
    ProcessSectionImageNx = 0x2,
    ProcessSectionPagefileBacked = 0x3,
    ProcessSectionMax = 0x4
}PROCESS_SECTION_TYPE, * PPROCESS_SECTION_TYPE;

typedef enum _PROCESS_TERMINATE_REQUEST_REASON // int32_t
{
    ProcessTerminateRequestReasonNone = 0x0,
    ProcessTerminateCommitFail = 0x1,
    ProcessTerminateWriteToExecuteMemory = 0x2,
    ProcessTerminateAttachedWriteToExecuteMemory = 0x3,
    ProcessTerminateRequestReasonMax = 0x4
}PROCESS_TERMINATE_REQUEST_REASON, * PPROCESS_TERMINATE_REQUEST_REASON;

typedef enum _PROCESS_VA_TYPE // int32_t
{
    ProcessVAImage = 0x0,
    ProcessVASection = 0x1,
    ProcessVAPrivate = 0x2,
    ProcessVAMax = 0x3
}PROCESS_VA_TYPE, * PPROCESS_VA_TYPE;

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED                0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH              0x00000002 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER              0x00000004 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER                   0x00000010 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT                0x00000020 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE           0x00000040 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_INITIAL_THREAD                  0x00000080 // ?

typedef enum _THREAD_CREATION_FLAGS // uint32_t
{
    THREAD_CREATE_RUN_IMMEDIATELY = 0x0,
    THREAD_CREATE_SUSPENDED = 0x4,
    STACK_SIZE_PARAM_IS_A_RESERVATION = 0x10000
}THREAD_CREATION_FLAGS, * PTHREAD_CREATION_FLAGS;

typedef enum _WORKER_THREAD_FLAGS // uint32_t
{
    WT_EXECUTEDEFAULT = 0x0,
    WT_EXECUTEINIOTHREAD = 0x1,
    WT_EXECUTEINPERSISTENTTHREAD = 0x80,
    WT_EXECUTEINWAITTHREAD = 0x4,
    WT_EXECUTELONGFUNCTION = 0x10,
    WT_EXECUTEONLYONCE = 0x8,
    WT_TRANSFER_IMPERSONATION = 0x100,
    WT_EXECUTEINTIMERTHREAD = 0x20
}WORKER_THREAD_FLAGS, * PWORKER_THREAD_FLAGS;


#define RTL_MAX_DRIVE_LETTERS                               32
#define RTL_DRIVE_LETTER_VALID                              (USHORT)0x0001

#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED              0x01
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_USER            0x02
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_KERNEL          0x04
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_SERVER          0x08
#define RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB             0x20
#define RTL_USER_PROCESS_PARAMETERS_RESERVE_16MB            0x40
#define RTL_USER_PROCESS_PARAMETERS_CASE_SENSITIVE          0x80
#define RTL_USER_PROCESS_PARAMETERS_DISABLE_HEAP_DECOMMIT   0x100
#define RTL_USER_PROCESS_PARAMETERS_DLL_REDIRECTION_LOCAL   0x1000
#define RTL_USER_PROCESS_PARAMETERS_APP_MANIFEST_PRESENT    0x2000
#define RTL_USER_PROCESS_PARAMETERS_IMAGE_KEY_MISSING       0x4000
#define RTL_USER_PROCESS_PARAMETERS_NX_OPTIN                0x20000

#define PROCESS_TERMINATE                                   0x0001
#define PROCESS_CREATE_THREAD                               0x0002
#define PROCESS_SET_SESSIONID                               0x0004
#define PROCESS_VM_OPERATION                                0x0008
#define PROCESS_VM_READ                                     0x0010
#define PROCESS_VM_WRITE                                    0x0020
//#define PROCESS_DUP_HANDLE 0x0040
#define PROCESS_CREATE_PROCESS                              0x0080
#define PROCESS_SET_QUOTA                                   0x0100
#define PROCESS_SET_INFORMATION                             0x0200
#define PROCESS_QUERY_INFORMATION                           0x0400
#define PROCESS_SET_PORT                                    0x0800
#define PROCESS_SUSPEND_RESUME                              0x0800
#define PROCESS_QUERY_LIMITED_INFORMATION                   0x1000

#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

typedef struct _CREATE_PROCESS_DEBUG_INFO
{
    PVOID hFile;
    HANDLE hProcess;
    HANDLE hThread;
    HANDLE lpBaseOfImage;
    DWORD dwDebugInfoFileOffset;
    DWORD nDebugInfoSize;
    PVOID lpThreadLocalBase;
    PVOID(*lpStartAddress)(void*);//uint32_t(*lpStartAddress)(void*);
    PVOID lpImageName;
    USHORT fUnicode;

}CREATE_PROCESS_DEBUG_INFO, * PCREATE_PROCESS_DEBUG_INFO;

typedef struct _CREATE_THREAD_DEBUG_INFO
{
    HANDLE hThread;
    PVOID lpThreadLocalBase;
    //uint32_t(*lpStartAddress)(void*);
    PVOID(*lpStartAddress)(void*);
}CREATE_THREAD_DEBUG_INFO, * PCREATE_THREAD_DEBUG_INFO;

typedef struct _CRITICAL_PROCESS_EXCEPTION_DATA
{
    GUID ReportId;
    UNICODE_STRING ModuleName;
    DWORD ModuleTimestamp;
    DWORD ModuleSize;
    QWORD Offset;
}CRITICAL_PROCESS_EXCEPTION_DATA, * PCRITICAL_PROCESS_EXCEPTION_DATA;

typedef enum _THREAD_ACCESS_RIGHTS // uint32_t
{
    THREAD_TERMINATE = 0x1,
    THREAD_SUSPEND_RESUME = 0x2,
    THREAD_GET_CONTEXT = 0x8,
    THREAD_SET_CONTEXT = 0x10,
    THREAD_SET_INFORMATION = 0x20,
    THREAD_QUERY_INFORMATION = 0x40,
    THREAD_SET_THREAD_TOKEN = 0x80,
    THREAD_IMPERSONATE = 0x100,
    THREAD_DIRECT_IMPERSONATION = 0x200,
    THREAD_SET_LIMITED_INFORMATION = 0x400,
    THREAD_QUERY_LIMITED_INFORMATION = 0x800,
    THREAD_RESUME = 0x1000,
    //THREAD_ALL_ACCESS = 0x1fffff,
    THREAD_DELETE = 0x10000,
    THREAD_READ_CONTROL = 0x20000,
    THREAD_WRITE_DAC = 0x40000,
    THREAD_WRITE_OWNER = 0x80000,
    THREAD_SYNCHRONIZE = 0x100000,
    THREAD_STANDARD_RIGHTS_REQUIRED = 0xf0000
}THREAD_ACCESS_RIGHTS, * PTHREAD_ACCESS_RIGHTS;

typedef enum _THREAD_ERROR_MODE //uint32_t
{
    SEM_ALL_ERRORS = 0x0,
    SEM_FAILCRITICALERRORS = 0x1,
    SEM_NOGPFAULTERRORBOX = 0x2,
    SEM_NOOPENFILEERRORBOX = 0x8000,
    SEM_NOALIGNMENTFAULTEXCEPT = 0x4
}THREAD_ERROR_MODE, * PTHREAD_ERROR_MODE;

typedef enum _THREAD_PRIORITY // uint32_t
{
    THREAD_MODE_BACKGROUND_BEGIN = 0x10000,
    THREAD_MODE_BACKGROUND_END = 0x20000,
    THREAD_PRIORITY_ABOVE_NORMAL = 0x1,
    THREAD_PRIORITY_BELOW_NORMAL = 0xffffffff,
    THREAD_PRIORITY_HIGHEST = 0x2,
    THREAD_PRIORITY_IDLE = 0xfffffff1,
    THREAD_PRIORITY_MIN = 0xfffffffe,
    THREAD_PRIORITY_LOWEST = 0xfffffffe,
    THREAD_PRIORITY_NORMAL = 0x0,
    THREAD_PRIORITY_TIME_CRITICAL = 0xf
}THREAD_PRIORITY, * PTHREAD_PRIORITY;

typedef enum _CREATE_PROCESS_LOGON_FLAGS // uint32_t
{
    LOGON_WITH_PROFILE = 0x1,
    LOGON_NETCREDENTIALS_ONLY = 0x2
}CREATE_PROCESS_LOGON_FLAGS, * PCREATE_PROCESS_LOGON_FLAGS;

typedef enum _PROCESS_ACCESS_RIGHTS // uint32_t
{
    //PROCESS_TERMINATE = 0x1,
    //PROCESS_CREATE_THREAD = 0x2,
    //PROCESS_SET_SESSIONID = 0x4,
    //PROCESS_VM_OPERATION = 0x8,
    //PROCESS_VM_READ = 0x10,
    //PROCESS_VM_WRITE = 0x20,
    PROCESS_DUP_HANDLE = 0x40,
    //PROCESS_CREATE_PROCESS = 0x80,
    //PROCESS_SET_QUOTA = 0x100,
    //PROCESS_SET_INFORMATION = 0x200,
    //PROCESS_QUERY_INFORMATION = 0x400,
    //PROCESS_SUSPEND_RESUME = 0x800,
    //PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
    PROCESS_SET_LIMITED_INFORMATION = 0x2000,
    //PROCESS_ALL_ACCESS = 0x1fffff,
    PROCESS_DELETE = 0x10000,
    PROCESS_READ_CONTROL = 0x20000,
    PROCESS_WRITE_DAC = 0x40000,
    PROCESS_WRITE_OWNER = 0x80000,
    PROCESS_SYNCHRONIZE = 0x100000,
    PROCESS_STANDARD_RIGHTS_REQUIRED = 0xf0000
}PROCESS_ACCESS_RIGHTS, * PPROCESS_ACCESS_RIGHTS;

typedef enum _PROCESS_MITIGATION_POLICY // uint32_t
{
    ProcessDEPPolicy = 0x0,
    ProcessASLRPolicy = 0x1,
    ProcessDynamicCodePolicy = 0x2,
    ProcessStrictHandleCheckPolicy = 0x3,
    ProcessSystemCallDisablePolicy = 0x4,
    ProcessMitigationOptionsMask = 0x5,
    ProcessExtensionPointDisablePolicy = 0x6,
    ProcessControlFlowGuardPolicy = 0x7,
    ProcessSignaturePolicy = 0x8,
    ProcessFontDisablePolicy = 0x9,
    ProcessImageLoadPolicy = 0xa,
    ProcessSystemCallFilterPolicy = 0xb,
    ProcessPayloadRestrictionPolicy = 0xc,
    ProcessChildProcessPolicy = 0xd,
    ProcessSideChannelIsolationPolicy = 0xe,
    ProcessUserShadowStackPolicy = 0xf,
    ProcessRedirectionTrustPolicy = 0x10,
    MaxProcessMitigationPolicy = 0x11
}PROCESS_MITIGATION_POLICY, * PPROCESS_MITIGATION_POLICY;

typedef struct _PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD RaiseExceptionOnInvalidHandleReference;
            DWORD HandleExceptionsPermanentlyEnabled;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY, * PPROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY;

typedef struct _PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD DisallowWin32kSystemCalls;
            DWORD AuditDisallowWin32kSystemCalls;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY, * PPROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY;

typedef struct _PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD FilterId;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY, * PPROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY;

typedef struct _PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD EnableUserShadowStack;
            DWORD AuditUserShadowStack;
            DWORD SetContextIpValidation;
            DWORD AuditSetContextIpValidation;
            DWORD EnableUserShadowStackStrictMode;
            DWORD BlockNonCetBinaries;
            DWORD BlockNonCetBinariesNonEhcont;
            DWORD AuditBlockNonCetBinaries;
            DWORD CetDynamicApisOutOfProcOnly;
            DWORD SetContextIpValidationRelaxedMode;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY, * PPROCESS_MITIGATION_USER_SHADOW_STACK_POLICY;

typedef struct _PROCESS_MITIGATION_ASLR_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD EnableBottomUpRandomization;
            DWORD EnableForceRelocateImages;
            DWORD EnableHighEntropy;
            DWORD DisallowStrippedImages;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_ASLR_POLICY, * PPROCESS_MITIGATION_ASLR_POLICY;

typedef struct _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD MicrosoftSignedOnly;
            DWORD StoreSignedOnly;
            DWORD MitigationOptIn;
            DWORD AuditMicrosoftSignedOnly;
            DWORD AuditStoreSignedOnly;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, * PPROCESS_MITIGATION_BINARY_SIGNATURE_POLICY;

typedef struct _PROCESS_MITIGATION_CHILD_PROCESS_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD NoChildProcessCreation;
            DWORD AuditNoChildProcessCreation;
            DWORD AllowSecureProcessCreation;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_CHILD_PROCESS_POLICY, * PPROCESS_MITIGATION_CHILD_PROCESS_POLICY;

typedef struct _PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD EnableControlFlowGuard;
            DWORD EnableExportSuppression;
            DWORD StrictMode;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY, * PPROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY;

typedef struct _PROCESS_MITIGATION_DEP_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD Enable;
            DWORD DisableAtlThunkEmulation;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
    UCHAR Permanent;
}PROCESS_MITIGATION_DEP_POLICY, * PPROCESS_MITIGATION_DEP_POLICY;

typedef struct _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD ProhibitDynamicCode;
            DWORD AllowThreadOptOut;
            DWORD AllowRemoteDowngrade;
            DWORD AuditProhibitDynamicCode;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, * PPROCESS_MITIGATION_DYNAMIC_CODE_POLICY;

typedef struct _PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD DisableExtensionPoints;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, * PPROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY;

typedef struct _PROCESS_MITIGATION_FONT_DISABLE_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD DisableNonSystemFonts;
            DWORD AuditNonSystemFontLoading;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_FONT_DISABLE_POLICY, * PPROCESS_MITIGATION_FONT_DISABLE_POLICY;

typedef struct _PROCESS_MITIGATION_IMAGE_LOAD_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD NoRemoteImages;
            DWORD NoLowMandatoryLabelImages;
            DWORD PreferSystem32Images;
            DWORD AuditNoRemoteImages;
            DWORD AuditNoLowMandatoryLabelImages;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_IMAGE_LOAD_POLICY, * PPROCESS_MITIGATION_IMAGE_LOAD_POLICY;

typedef struct _PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD EnableExportAddressFilter;
            DWORD AuditExportAddressFilter;
            DWORD EnableExportAddressFilterPlus;
            DWORD AuditExportAddressFilterPlus;
            DWORD EnableImportAddressFilter;
            DWORD AuditImportAddressFilter;
            DWORD EnableRopStackPivot;
            DWORD AuditRopStackPivot;
            DWORD EnableRopCallerCheck;
            DWORD AuditRopCallerCheck;
            DWORD EnableRopSimExec;
            DWORD AuditRopSimExec;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY, * PPROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY;

typedef struct _PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD SmtBranchTargetIsolation;
            DWORD IsolateSecurityDomain;
            DWORD DisablePageCombine;
            DWORD SpeculativeStoreBypassDisable;
            DWORD ReservedFlags;
        } __bitfield0;
    } __inner0;
}PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY, * PPROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY;

typedef struct _PROCESS_MITIGATION_POLICY_INFORMATION
{
    PROCESS_MITIGATION_POLICY Policy;
    union
    {
        PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;
        PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY SystemCallDisablePolicy;
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy;
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy;
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SignaturePolicy;
        PROCESS_MITIGATION_FONT_DISABLE_POLICY FontDisablePolicy;
        PROCESS_MITIGATION_IMAGE_LOAD_POLICY ImageLoadPolicy;
        PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY SystemCallFilterPolicy;
        PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY PayloadRestrictionPolicy;
        PROCESS_MITIGATION_CHILD_PROCESS_POLICY ChildProcessPolicy;
        PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY SideChannelIsolationPolicy;
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY UserShadowStackPolicy;
    } __inner1;
}PROCESS_MITIGATION_POLICY_INFORMATION, * PPROCESS_MITIGATION_POLICY_INFORMATION;

typedef union _RTL_IMAGE_MITIGATION_POLICY
{
    QWORD AuditState;
    QWORD AuditFlag;
    QWORD EnableAdditionalAuditingOption;
    QWORD Reserved;
    QWORD PolicyState;
    QWORD AlwaysInherit;
    QWORD EnableAdditionalPolicyOption;
    QWORD AuditReserved;
}RTL_IMAGE_MITIGATION_POLICY, * PRTL_IMAGE_MITIGATION_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_ASLR_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY ForceRelocateImages;
    RTL_IMAGE_MITIGATION_POLICY BottomUpRandomization;
    RTL_IMAGE_MITIGATION_POLICY HighEntropyRandomization;
}RTL_IMAGE_MITIGATION_ASLR_POLICY, * PRTL_IMAGE_MITIGATION_ASLR_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockNonMicrosoftSignedBinaries;
    RTL_IMAGE_MITIGATION_POLICY EnforceSigningOnModuleDependencies;
}RTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY, * PRTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY;

struct _RTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY DisallowChildProcessCreation;
}RTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY, * PRTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY ControlFlowGuard;
    RTL_IMAGE_MITIGATION_POLICY StrictControlFlowGuard;
}RTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY, * PRTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_DEP_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY Dep;
}RTL_IMAGE_MITIGATION_DEP_POLICY, * PRTL_IMAGE_MITIGATION_DEP_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockDynamicCode;
}RTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY, * PRTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY DisableExtensionPoints;
}RTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, * PRTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY DisableNonSystemFonts;
}RTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY, * PRTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_HEAP_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY TerminateOnHeapErrors;
}RTL_IMAGE_MITIGATION_HEAP_POLICY, * PRTL_IMAGE_MITIGATION_HEAP_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockRemoteImageLoads;
    RTL_IMAGE_MITIGATION_POLICY BlockLowLabelImageLoads;
    RTL_IMAGE_MITIGATION_POLICY PreferSystem32;
}RTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY, * PRTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY;

typedef enum _RTL_IMAGE_MITIGATION_OPTION_STATE // int32_t
{
    RtlMitigationOptionStateNotConfigured = 0x0,
    RtlMitigationOptionStateOn = 0x1,
    RtlMitigationOptionStateOff = 0x2
}RTL_IMAGE_MITIGATION_OPTION_STATE, * PRTL_IMAGE_MITIGATION_OPTION_STATE;

typedef struct _RTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY EnableExportAddressFilter;
    RTL_IMAGE_MITIGATION_POLICY EnableExportAddressFilterPlus;
    RTL_IMAGE_MITIGATION_POLICY EnableImportAddressFilter;
    RTL_IMAGE_MITIGATION_POLICY EnableRopStackPivot;
    RTL_IMAGE_MITIGATION_POLICY EnableRopCallerCheck;
    RTL_IMAGE_MITIGATION_POLICY EnableRopSimExec;
    USHORT EafPlusModuleList[0x200];
}RTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY, * PRTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_SEHOP_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY Sehop;
}RTL_IMAGE_MITIGATION_SEHOP_POLICY, * PRTL_IMAGE_MITIGATION_SEHOP_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY StrictHandleChecks;
}RTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY, * PRTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockWin32kSystemCalls;
}RTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY, * PRTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY;

typedef struct _RTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY UserShadowStack;
    RTL_IMAGE_MITIGATION_POLICY SetContextIpValidation;
    RTL_IMAGE_MITIGATION_POLICY BlockNonCetBinaries;
}RTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY, * PRTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY;

typedef struct _RTL_IMAGE_POLICY_METADATA
{
    IMAGE_POLICY_METADATA const* PolicyMetadata;
    QWORD LBound;
    QWORD UBound;
}RTL_IMAGE_POLICY_METADATA, * PRTL_IMAGE_POLICY_METADATA;

#define THREAD_QUERY_INFORMATION                            0x0040
#define THREAD_SET_THREAD_TOKEN                             0x0080
#define THREAD_IMPERSONATE                                  0x0100
#define THREAD_DIRECT_IMPERSONATION                         0x0200
#define THREAD_ALERT                                        0x0004

#define PROCESS_PRIORITY_CLASS_UNKNOWN                      0
#define PROCESS_PRIORITY_CLASS_IDLE                         1
#define PROCESS_PRIORITY_CLASS_NORMAL                       2
#define PROCESS_PRIORITY_CLASS_HIGH                         3
#define PROCESS_PRIORITY_CLASS_REALTIME                     4
#define PROCESS_PRIORITY_CLASS_BELOW_NORMAL                 5
#define PROCESS_PRIORITY_CLASS_ABOVE_NORMAL                 6

#define DONT_RESOLVE_DLL_REFERENCES                         0x1
#define LOAD_LIBRARY_AS_DATAFILE                            0x2
#define LOAD_WITH_ALTERED_SEARCH_PATH                       0x8
#define LOAD_IGNORE_CODE_AUTHZ_LEVEL                        0x10
#define LOAD_LIBRARY_AS_IMAGE_RESOURCE                      0x20
#define LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE                  0x40
#define LOAD_LIBRARY_REQUIRE_SIGNED_TARGET                  0x80
#define LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR                    0x100
#define LOAD_LIBRARY_SEARCH_APPLICATION_DIR                 0x200
#define LOAD_LIBRARY_SEARCH_USER_DIRS                       0x400
#define LOAD_LIBRARY_SEARCH_SYSTEM32                        0x800
#define LOAD_LIBRARY_SEARCH_DEFAULT_DIRS                    0x1000
#define LOAD_LIBRARY_SAFE_CURRENT_DIRS                      0x2000
#define LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER           0x4000

typedef enum _LOAD_LIBRARY_FLAGS
{
    /* DONT_RESOLVE_DLL_REFERENCES = 0x1,
     LOAD_LIBRARY_AS_DATAFILE = 0x2,
     LOAD_WITH_ALTERED_SEARCH_PATH = 0x8,
     LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x10,
     LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x20,
     LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x40,
     LOAD_LIBRARY_REQUIRE_SIGNED_TARGET = 0x80,
     LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x100,
     LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x200,
     LOAD_LIBRARY_SEARCH_USER_DIRS = 0x400,
     LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800,
     LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x1000,
     LOAD_LIBRARY_SAFE_CURRENT_DIRS = 0x2000,
     LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER = 0x4000*/
}LOAD_LIBRARY_FLAGS, * PLOAD_LIBRARY_FLAGS;

typedef enum _PROCESS_CREATION_FLAGS
{
    DEBUG_PROCESS = 0x1,
    DEBUG_ONLY_THIS_PROCESS = 0x2,
    CREATE_SUSPENDED = 0x4,
    DETACHED_PROCESS = 0x8,
    CREATE_NEW_CONSOLE = 0x10,
    NORMAL_PRIORITY_CLASS = 0x20,
    IDLE_PRIORITY_CLASS = 0x40,
    HIGH_PRIORITY_CLASS = 0x80,
    REALTIME_PRIORITY_CLASS = 0x100,
    CREATE_NEW_PROCESS_GROUP = 0x200,
    CREATE_UNICODE_ENVIRONMENT = 0x400,
    CREATE_SEPARATE_WOW_VDM = 0x800,
    CREATE_SHARED_WOW_VDM = 0x1000,
    CREATE_FORCEDOS = 0x2000,
    BELOW_NORMAL_PRIORITY_CLASS = 0x4000,
    ABOVE_NORMAL_PRIORITY_CLASS = 0x8000,
    INHERIT_PARENT_AFFINITY = 0x10000,
    INHERIT_CALLER_PRIORITY = 0x20000,
    CREATE_PROTECTED_PROCESS = 0x40000,
    EXTENDED_STARTUPINFO_PRESENT = 0x80000,
    PROCESS_MODE_BACKGROUND_BEGIN = 0x100000,
    PROCESS_MODE_BACKGROUND_END = 0x200000,
    CREATE_SECURE_PROCESS = 0x400000,
    CREATE_BREAKAWAY_FROM_JOB = 0x1000000,
    CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x2000000,
    CREATE_DEFAULT_ERROR_MODE = 0x4000000,
    CREATE_NO_WINDOW = 0x8000000,
    PROFILE_USER = 0x10000000,
    PROFILE_KERNEL = 0x20000000,
    PROFILE_SERVER = 0x40000000,
    CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
}PROCESS_CREATION_FLAGS, * PPROCESS_CREATION_FLAGS;

typedef struct _BATTERY_REPORTING_SCALE
{
    DWORD Granularity;
    DWORD Capacity;
}BATTERY_REPORTING_SCALE, * PBATTERY_REPORTING_SCALE;

typedef struct _CPINFO
{
    DWORD MaxCharSize;
    UCHAR DefaultChar[0x2];
    UCHAR LeadByte[0xc];
}CPINFO, * PCPINFO;

typedef struct _CPINFOEXW
{
    DWORD MaxCharSize;
    UCHAR DefaultChar[0x2];
    UCHAR LeadByte[0xc];
    char UnicodeDefaultChar;
    DWORD CodePage;
    char CodePageName[0x104];
}CPINFOEXW, * PCPINFOEXW;

typedef struct _CREATEFILE2_EXTENDED_PARAMETERS
{
    DWORD dwSize;
    DWORD dwFileAttributes;
    DWORD dwFileFlags;
    DWORD dwSecurityQosFlags;
    SECURITY_ATTRIBUTES* lpSecurityAttributes;
    HANDLE hTemplateFile;
}CREATEFILE2_EXTENDED_PARAMETERS, * PCREATEFILE2_EXTENDED_PARAMETERS;

typedef enum _DEVICE_TEXT_TYPE //int32_t
{
    DeviceTextDescription = 0x0,
    DeviceTextLocationInformation = 0x1
}DEVICE_TEXT_TYPE, * PDEVICE_TEXT_TYPE;

typedef enum _DISPLAYCONFIG_SCANLINE_ORDERING // int32_t
{
    DISPLAYCONFIG_SCANLINE_ORDERING_UNSPECIFIED = 0x0,
    DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE = 0x1,
    DISPLAYCONFIG_SCANLINE_ORDERING_INTERLACED = 0x2,
    DISPLAYCONFIG_SCANLINE_ORDERING_INTERLACED_UPPERFIELDFIRST = 0x2,
    DISPLAYCONFIG_SCANLINE_ORDERING_INTERLACED_LOWERFIELDFIRST = 0x3,
    DISPLAYCONFIG_SCANLINE_ORDERING_FORCE_UINT32 = 0xff
}DISPLAYCONFIG_SCANLINE_ORDERING, * PDISPLAYCONFIG_SCANLINE_ORDERING;

typedef enum _ENUM_DATE_FORMATS_FLAGS // uint32_t
{
    DATE_SHORTDATE = 0x1,
    DATE_LONGDATE = 0x2,
    DATE_YEARMONTH = 0x8,
    DATE_MONTHDAY = 0x80,
    DATE_AUTOLAYOUT = 0x40,
    DATE_LTRREADING = 0x10,
    DATE_RTLREADING = 0x20,
    DATE_USE_ALT_CALENDAR = 0x4
}ENUM_DATE_FORMATS_FLAGS, * PENUM_DATE_FORMATS_FLAGS;

typedef struct _ENUM_PAGE_FILE_INFORMATION
{
    DWORD cb;
    DWORD Reserved;
    QWORD* TotalSize;
    QWORD* TotalInUse;
    QWORD* PeakUsage;
}ENUM_PAGE_FILE_INFORMATION, * PENUM_PAGE_FILE_INFORMATION;

typedef enum _ENUM_PROCESS_MODULES_EX_FLAGS // uint32_t
{
    LIST_MODULES_ALL = 0x3,
    LIST_MODULES_DEFAULT = 0x0,
    LIST_MODULES_32BIT = 0x1,
    LIST_MODULES_64BIT = 0x2
}ENUM_PROCESS_MODULES_EX_FLAGS, * PENUM_PROCESS_MODULES_EX_FLAGS;

typedef struct _MODULEINFO
{
    PVOID lpBaseOfDll;
    DWORD SizeOfImage;
    PVOID EntryPoint;
}MODULEINFO, * PMODULEINFO;

typedef enum _ENUM_SYSTEM_CODE_PAGES_FLAGS // uint32_t
{
    CP_INSTALLED = 0x1,
    CP_SUPPORTED = 0x2
}ENUM_SYSTEM_CODE_PAGES_FLAGS, * PENUM_SYSTEM_CODE_PAGES_FLAGS;

typedef enum _ENUM_SYSTEM_LANGUAGE_GROUPS_FLAGS // uint32_t
{
    LGRPID_INSTALLED = 0x1,
    LGRPID_SUPPORTED = 0x2
}ENUM_SYSTEM_LANGUAGE_GROUPS_FLAGS, * PENUM_SYSTEM_LANGUAGE_GROUPS_FLAGS;

typedef enum _JOB_OBJECT_IO_RATE_CONTROL_FLAGS // int32_t
{
    JOB_OBJECT_IO_RATE_CONTROL_ENABLE = 0x1,
    JOB_OBJECT_IO_RATE_CONTROL_STANDALONE_VOLUME = 0x2,
    JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ALL = 0x4,
    JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ON_SOFT_CAP = 0x8,
    JOB_OBJECT_IO_RATE_CONTROL_VALID_FLAGS = 0xf
}JOB_OBJECT_IO_RATE_CONTROL_FLAGS, * PJOB_OBJECT_IO_RATE_CONTROL_FLAGS;

typedef enum _JOB_OBJECT_NET_RATE_CONTROL_FLAGS // int32_t
{
    JOB_OBJECT_NET_RATE_CONTROL_ENABLE = 0x1,
    JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH = 0x2,
    JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG = 0x4,
    JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS = 0x7
}JOB_OBJECT_NET_RATE_CONTROL_FLAGS, * PJOB_OBJECT_NET_RATE_CONTROL_FLAGS;

typedef enum _LSA_FOREST_TRUST_RECORD_TYPE // int32_t
{
    ForestTrustTopLevelName = 0x0,
    ForestTrustTopLevelNameEx = 0x1,
    ForestTrustDomainInfo = 0x2,
    ForestTrustBinaryInfo = 0x3,
    ForestTrustScannerInfo = 0x4,
    ForestTrustRecordTypeLast = 0x4
}LSA_FOREST_TRUST_RECORD_TYPE, * PLSA_FOREST_TRUST_RECORD_TYPE;

typedef enum _PROCESSOR_FEATURE_ID //: uint32_t
{
    PF_ARM_64BIT_LOADSTORE_ATOMIC = 0x19,
    PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE = 0x18,
    PF_ARM_EXTERNAL_CACHE_AVAILABLE = 0x1a,
    PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE = 0x1b,
    PF_ARM_VFP_32_REGISTERS_AVAILABLE = 0x12,
    PF_3DNOW_INSTRUCTIONS_AVAILABLE = 0x7,
    PF_CHANNELS_ENABLED = 0x10,
    PF_COMPARE_EXCHANGE_DOUBLE = 0x2,
    PF_COMPARE_EXCHANGE128 = 0xe,
    PF_COMPARE64_EXCHANGE128 = 0xf,
    PF_FASTFAIL_AVAILABLE = 0x17,
    PF_FLOATING_POINT_EMULATED = 0x1,
    PF_FLOATING_POINT_PRECISION_ERRATA = 0x0,
    PF_MMX_INSTRUCTIONS_AVAILABLE = 0x3,
    PF_NX_ENABLED = 0xc,
    PF_PAE_ENABLED = 0x9,
    PF_RDTSC_INSTRUCTION_AVAILABLE = 0x8,
    PF_RDWRFSGSBASE_AVAILABLE = 0x16,
    PF_SECOND_LEVEL_ADDRESS_TRANSLATION = 0x14,
    PF_SSE3_INSTRUCTIONS_AVAILABLE = 0xd,
    PF_VIRT_FIRMWARE_ENABLED = 0x15,
    PF_XMMI_INSTRUCTIONS_AVAILABLE = 0x6,
    PF_XMMI64_INSTRUCTIONS_AVAILABLE = 0xa,
    PF_XSAVE_ENABLED = 0x11,
    PF_ARM_V8_INSTRUCTIONS_AVAILABLE = 0x1d,
    PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE = 0x1e,
    PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE = 0x1f,
    PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE = 0x22
}PROCESSOR_FEATURE_ID, * PPROCESSOR_FEATURE_ID;

typedef enum _LOCK_FILE_FLAGS
{
    LOCKFILE_EXCLUSIVE_LOCK = 0x2,
    LOCKFILE_FAIL_IMMEDIATELY = 0x1
}LOCK_FILE_FLAGS, * PLOCK_FILE_FLAGS;

typedef enum _MOVE_FILE_FLAGS
{
    MOVEFILE_COPY_ALLOWED = 0x2,
    MOVEFILE_CREATE_HARDLINK = 0x10,
    MOVEFILE_DELAY_UNTIL_REBOOT = 0x4,
    MOVEFILE_REPLACE_EXISTING = 0x1,
    MOVEFILE_WRITE_THROUGH = 0x8,
    MOVEFILE_FAIL_IF_NOT_TRACKABLE = 0x20
}MOVE_FILE_FLAGS, * PMOVE_FILE_FLAGS;


typedef enum _STARTUPINFOW_FLAGS // uint32_t
{
    STARTF_FORCEONFEEDBACK = 0x40,
    STARTF_FORCEOFFFEEDBACK = 0x80,
    STARTF_PREVENTPINNING = 0x2000,
    STARTF_RUNFULLSCREEN = 0x20,
    STARTF_TITLEISAPPID = 0x1000,
    STARTF_TITLEISLINKNAME = 0x800,
    STARTF_UNTRUSTEDSOURCE = 0x8000,
    STARTF_USECOUNTCHARS = 0x8,
    STARTF_USEFILLATTRIBUTE = 0x10,
    STARTF_USEHOTKEY = 0x200,
    STARTF_USEPOSITION = 0x4,
    STARTF_USESHOWWINDOW = 0x1,
    STARTF_USESIZE = 0x2,
    STARTF_USESTDHANDLES = 0x100
}STARTUPINFOW_FLAGS, * PSTARTUPINFOW_FLAGS;

typedef struct _STARTUPINFOA
{
    DWORD cb;
    char* lpReserved;
    char* lpDesktop;
    char* lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    UCHAR* lpReserved2;
    PVOID hStdInput;
    PVOID hStdOutput;
    PVOID hStdError;
}STARTUPINFOA, * PSTARTUPINFOA;

typedef struct _STARTUPINFOW
{
    DWORD cb;
    PWSTR lpReserved;
    PWSTR lpDesktop;
    PWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    STARTUPINFOW_FLAGS dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    CHAR* lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
}STARTUPINFOW, * PSTARTUPINFOW;

typedef struct _PROCESS_INFORMATION
{
    PVOID hProcess;
    PVOID hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
}PROCESS_INFORMATION, * PPROCESS_INFORMATION;

typedef struct _SHCREATEPROCESSINFOW
{
    DWORD cbSize;
    DWORD fMask;
    struct HWND__* hwnd;
    USHORT const* pszFile;
    USHORT const* pszParameters;
    USHORT const* pszCurrentDirectory;
    PVOID hUserToken;
    SECURITY_ATTRIBUTES* lpProcessAttributes;
    SECURITY_ATTRIBUTES* lpThreadAttributes;
    LONG bInheritHandles;
    DWORD dwCreationFlags;
    STARTUPINFOW* lpStartupInfo;
    PROCESS_INFORMATION* lpProcessInformation;
}SHCREATEPROCESSINFOW, * PSHCREATEPROCESSINFOW;

typedef struct _SHELLEXECUTEINFOA
{
    DWORD cbSize;
    DWORD fMask;
    struct HWND__* hwnd;
    char const* lpVerb;
    char const* lpFile;
    char const* lpParameters;
    char const* lpDirectory;
    LONG nShow;
    struct HINSTANCE__* hInstApp;
    void* lpIDList;
    char const* lpClass;
    struct HKEY__* hkeyClass;
    DWORD dwHotKey;
    union
    {
        PVOID hIcon;
        PVOID hMonitor;
    } __inner13;
    PVOID hProcess;
}SHELLEXECUTEINFOA, * PSHELLEXECUTEINFOA;

typedef struct _SHELLEXECUTEINFOW
{
    DWORD cbSize;
    DWORD fMask;
    struct HWND__* hwnd;
    USHORT const* lpVerb;
    USHORT const* lpFile;
    USHORT const* lpParameters;
    USHORT const* lpDirectory;
    LONG nShow;
    struct HINSTANCE__* hInstApp;
    PVOID lpIDList;
    USHORT const* lpClass;
    struct HKEY__* hkeyClass;
    DWORD dwHotKey;
    union
    {
        PVOID hIcon;
        PVOID hMonitor;
    } __inner13;
    PVOID hProcess;
}SHELLEXECUTEINFOW, * PSHELLEXECUTEINFOW;

typedef struct _PROC_THREAD_ATTRIBUTE
{
    QWORD Attribute;
    QWORD Size;
    QWORD Value;
}PROC_THREAD_ATTRIBUTE, * PPROC_THREAD_ATTRIBUTE;

typedef struct _PROC_THREAD_ATTRIBUTE_LIST
{
    DWORD PresentFlags;
    DWORD AttributeCount;
    DWORD LastAttribute;
    DWORD SpareUlong0;
    PROC_THREAD_ATTRIBUTE* ExtendedFlagsAttribute;
    PROC_THREAD_ATTRIBUTE Attributes[0x1];
}PROC_THREAD_ATTRIBUTE_LIST, * PPROC_THREAD_ATTRIBUTE_LIST;

typedef struct _STARTUPINFOEXA
{
    STARTUPINFOA StartupInfo;
    PROC_THREAD_ATTRIBUTE_LIST* lpAttributeList;
}STARTUPINFOEXA, * PSTARTUPINFOEXA;

typedef struct _STARTUPINFOEXW
{
    STARTUPINFOW StartupInfo;
    PROC_THREAD_ATTRIBUTE_LIST* lpAttributeList;
}STARTUPINFOEXW, * PSTARTUPINFOEXW;

typedef enum _STD_HANDLE //uint32_t
{
    STD_INPUT_HANDLE = 0xfffffff6,
    STD_OUTPUT_HANDLE = 0xfffffff5,
    STD_ERROR_HANDLE = 0xfffffff4
}STD_HANDLE, * PSTD_HANDLE;

typedef struct _SYSTEMTIME
{
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
}SYSTEMTIME, * PSYSTEMTIME;

typedef struct _TIME_ZONE_INFORMATION
{
    LONG Bias;
    char StandardName[0x20];
    SYSTEMTIME StandardDate;
    LONG StandardBias;
    char DaylightName[0x20];
    SYSTEMTIME DaylightDate;
    LONG DaylightBias;
}TIME_ZONE_INFORMATION, * PTIME_ZONE_INFORMATION;

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread() NtCurrentThread()
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)
#define ZwCurrentSession() NtCurrentSession()

typedef struct DECLSPEC_ALIGN(16) _XSAVE_FORMAT {
    WORD   ControlWord;
    WORD   StatusWord;
    BYTE  TagWord;
    BYTE  Reserved1;
    WORD   ErrorOpcode;
    DWORD ErrorOffset;
    WORD   ErrorSelector;
    WORD   Reserved2;
    DWORD DataOffset;
    WORD   DataSelector;
    WORD   Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];

#if defined(_WIN64)

    M128A XmmRegisters[16];
    BYTE  Reserved4[96];

#else

    M128A XmmRegisters[8];
    BYTE  Reserved4[224];

#endif

} XSAVE_FORMAT, * PXSAVE_FORMAT;
typedef XSAVE_FORMAT XMM_SAVE_AREA32, * PXMM_SAVE_AREA32;

typedef struct DECLSPEC_ALIGN(16) DECLSPEC_NOINITALL _CONTEXT {

    //
    // Register parameter home addresses.
    //
    // N.B. These fields are for convience - they could be used to extend the
    //      context record in the future.
    //

    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;

    //
    // Control flags.
    //

    DWORD ContextFlags;
    DWORD MxCsr;

    //
    // Segment Registers and processor flags.
    //

    WORD   SegCs;
    WORD   SegDs;
    WORD   SegEs;
    WORD   SegFs;
    WORD   SegGs;
    WORD   SegSs;
    DWORD EFlags;

    //
    // Debug registers
    //

    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;

    //
    // Integer registers.
    //

    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;

    //
    // Program counter.
    //

    DWORD64 Rip;

    //
    // Floating point state.
    //

    union {
        XMM_SAVE_AREA32 FltSave;
        struct {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    //
    // Vector registers.
    //

    M128A VectorRegister[26];
    DWORD64 VectorControl;

    //
    // Special debug control registers.
    //

    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
} CONTEXT64, * PCONTEXT64;

#define WOW64_SIZE_OF_80387_REGISTERS      80

#define WOW64_MAXIMUM_SUPPORTED_EXTENSION     512

#define WOW64_CONTEXT_i386	0x00010000

#define WOW64_CONTEXT_CONTROL		    (WOW64_CONTEXT_i386 | 0x00000001L)
#define WOW64_CONTEXT_INTEGER		    (WOW64_CONTEXT_i386 | 0x00000002L)
#define WOW64_CONTEXT_SEGMENTS		    (WOW64_CONTEXT_i386 | 0x00000004L)
#define WOW64_CONTEXT_FLOATING_POINT	    (WOW64_CONTEXT_i386 | 0x00000008L)
#define WOW64_CONTEXT_DEBUG_REGISTERS	    (WOW64_CONTEXT_i386 | 0x00000010L)
#define WOW64_CONTEXT_EXTENDED_REGISTERS    (WOW64_CONTEXT_i386 | 0x00000020L)

#define WOW64_CONTEXT_FULL      (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS)

#define WOW64_CONTEXT_ALL       (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS | \
                                 WOW64_CONTEXT_FLOATING_POINT | WOW64_CONTEXT_DEBUG_REGISTERS | \
                                 WOW64_CONTEXT_EXTENDED_REGISTERS)

typedef enum _WOW64_SHARED_INFORMATION // int32_t
{
    SharedNtdll32LdrInitializeThunk = 0x0,
    SharedNtdll32KiUserExceptionDispatcher = 0x1,
    SharedNtdll32KiUserApcDispatcher = 0x2,
    SharedNtdll32KiUserCallbackDispatcher = 0x3,
    SharedNtdll32RtlUserThreadStart = 0x4,
    SharedNtdll32pQueryProcessDebugInformationRemote = 0x5,
    SharedNtdll32BaseAddress = 0x6,
    SharedNtdll32LdrSystemDllInitBlock = 0x7,
    SharedNtdll32RtlpFreezeTimeBias = 0x8,
    Wow64SharedPageEntriesCount = 0x9
}WOW64_SHARED_INFORMATION, * PWOW64_SHARED_INFORMATION;


typedef struct _WOW64_FLOATING_SAVE_AREA {
    DWORD   ControlWord;
    DWORD   StatusWord;
    DWORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    BYTE    RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
    DWORD   Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA;

typedef WOW64_FLOATING_SAVE_AREA* PWOW64_FLOATING_SAVE_AREA;

typedef struct _WOW64_CONTEXT {

    //
    // The flags values within this flag control the contents of
    // a CONTEXT record.
    //
    // If the context record is used as an input parameter, then
    // for each portion of the context record controlled by a flag
    // whose value is set, it is assumed that that portion of the
    // context record contains valid context. If the context record
    // is being used to modify a threads context, then only that
    // portion of the threads context will be modified.
    //
    // If the context record is used as an IN OUT parameter to capture
    // the context of a thread, then only those portions of the thread's
    // context corresponding to set flags will be returned.
    //
    // The context record is never used as an OUT only parameter.
    //

    DWORD ContextFlags;

    //
    // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
    // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
    // included in CONTEXT_FULL.
    //

    DWORD   Dr0;
    DWORD   Dr1;
    DWORD   Dr2;
    DWORD   Dr3;
    DWORD   Dr6;
    DWORD   Dr7;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
    //

    WOW64_FLOATING_SAVE_AREA FloatSave;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_SEGMENTS.
    //

    DWORD   SegGs;
    DWORD   SegFs;
    DWORD   SegEs;
    DWORD   SegDs;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_INTEGER.
    //

    DWORD   Edi;
    DWORD   Esi;
    DWORD   Ebx;
    DWORD   Edx;
    DWORD   Ecx;
    DWORD   Eax;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_CONTROL.
    //

    DWORD   Ebp;
    DWORD   Eip;
    DWORD   SegCs;              // MUST BE SANITIZED
    DWORD   EFlags;             // MUST BE SANITIZED
    DWORD   Esp;
    DWORD   SegSs;

    //
    // This section is specified/returned if the ContextFlags word
    // contains the flag CONTEXT_EXTENDED_REGISTERS.
    // The format and contexts are processor specific
    //

    BYTE    ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];

} WOW64_CONTEXT;

typedef WOW64_CONTEXT* PWOW64_CONTEXT;

typedef struct _SETJMP_FLOAT128
{
    QWORD Part[0x2];
}SETJMP_FLOAT128, * PSETJMP_FLOAT128;

typedef struct _JUMP_BUFFER
{
    QWORD Frame;
    QWORD Rbx;
    QWORD Rsp;
    QWORD Rbp;
    QWORD Rsi;
    QWORD Rdi;
    QWORD R12;
    QWORD R13;
    QWORD R14;
    QWORD R15;
    QWORD Rip;
    DWORD MxCsr;
    WORD FpCsr;
    WORD Spare;
    SETJMP_FLOAT128 Xmm6;
    SETJMP_FLOAT128 Xmm7;
    SETJMP_FLOAT128 Xmm8;
    SETJMP_FLOAT128 Xmm9;
    SETJMP_FLOAT128 Xmm10;
    SETJMP_FLOAT128 Xmm11;
    SETJMP_FLOAT128 Xmm12;
    SETJMP_FLOAT128 Xmm13;
    SETJMP_FLOAT128 Xmm14;
    SETJMP_FLOAT128 Xmm15;
}JUMP_BUFFER, * PJUMP_BUFFER;

#ifdef _WIN64
typedef PCONTEXT64               PCONTEXT;
typedef CONTEXT64                CONTEXT;
#else
typedef PWOW64_CONTEXT           PCONTEXT;
typedef WOW64_CONTEXT            CONTEXT;
#endif

typedef struct _CONTEXT_CHUNK
{
    LONG Offset;
    ULONG Length;
}CONTEXT_CHUNK, * PCONTEXT_CHUNK;

typedef struct _CONTEXT_EX
{
    CONTEXT_CHUNK All;
    CONTEXT_CHUNK Legacy;
    CONTEXT_CHUNK XState;
}CONTEXT_EX, * PCONTEXT_EX;

typedef enum _EXCEPTION_DISPOSITION // int32_t
{
    ExceptionContinueExecution = 0x0,
    ExceptionContinueSearch = 0x1,
    ExceptionNestedException = 0x2,
    ExceptionCollidedUnwind = 0x3
}EXCEPTION_DISPOSITION, * PEXCEPTION_DISPOSITION;

typedef struct _EXCEPTION_RECORD
{
    NTSTATUS ExceptionCode;
    DWORD ExceptionFlags;
    struct EXCEPTION_RECORD* ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    QWORD* ExceptionInformation[0xf];//uint64_t*
}EXCEPTION_RECORD, * PEXCEPTION_RECORD;

typedef enum _ELEVATION_REASON // int32_t
{
    ELEVATION_REASON_APPCOMPAT_EXPLICIT = 0x0,
    ELEVATION_REASON_APPCOMPAT_HEURISTIC = 0x1,
    ELEVATION_REASON_FUSION = 0x2,
    ELEVATION_REASON_INSTALLER = 0x3,
    ELEVATION_REASON_CLSID = 0x4,
    ELEVATION_REASON_MSI = 0x5,
    ELEVATION_REASON_REQUEST = 0x6,
    ELEVATION_REASON_AXIS = 0x7,
    ELEVATION_REASON_PACKAGED_APP = 0x8,
    ELEVATION_REASON_NUM_REASONS = 0x9
}ELEVATION_REASON, * PELEVATION_REASON;

typedef enum _ELEVATION_STATE // int32_t
{
    ELEVATION_NOT_CHECKED = 0x0,
    ELEVATION_CHECKED_SHIELD = 0x1,
    ELEVATION_CHECKED_NOSHIELD = 0x2
}ELEVATION_STATE, * PELEVATION_STATE;

typedef struct _EXCEPTION_POINTERS
{
    EXCEPTION_RECORD* ExceptionRecord;
    CONTEXT* ContextRecord;
}EXCEPTION_POINTERS, * PEXCEPTION_POINTERS;

typedef LONG(*LPTOP_LEVEL_EXCEPTION_FILTER)(EXCEPTION_POINTERS* ExceptionInfo);

typedef struct _OVERLAPPED
{
    QWORD* Internal;//uint64_t*
    QWORD* InternalHigh;
    union
    {
        struct
        {
            DWORD Offset;
            DWORD OffsetHigh;
        };
        void* Pointer;
    };
    HANDLE hEvent;
}OVERLAPPED, * POVERLAPPED;

typedef void (*LPWSAOVERLAPPED_COMPLETION_ROUTINE)(DWORD dwError, DWORD cbTransferred, OVERLAPPED* lpOverlapped, DWORD dwFlags);
typedef void (*PAPCFUNC)(QWORD* Parameter);

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


typedef EXCEPTION_DISPOSITION NTAPI EXCEPTION_ROUTINE(
    struct _EXCEPTION_RECORD* ExceptionRecord,
    PVOID EstablisherFrame,
    struct _CONTEXT* ContextRecord,
    PVOID DispatcherContext
);

typedef EXCEPTION_ROUTINE* PEXCEPTION_ROUTINE;

typedef struct _EXCEPTION_REGISTRATION_RECORD
{
    struct _EXCEPTION_REGISTRATION_RECORD* Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD, * PEXCEPTION_REGISTRATION_RECORD;

typedef struct _NT_TIB32 {
    PEXCEPTION_REGISTRATION_RECORD ExceptionList;  //_EXCEPTION_REGISTRATION_RECORD *ExceptionList; DWORD
    DWORD StackBase;
    DWORD StackLimit;
    DWORD SubSystemTib;
    union {
        DWORD FiberData;
        DWORD Version;
    };
    DWORD ArbitraryUserPointer;
    DWORD Self;
} NT_TIB32, * PNT_TIB32;

typedef struct _NT_TIB64 {
    PEXCEPTION_REGISTRATION_RECORD ExceptionList; //_EXCEPTION_REGISTRATION_RECORD *ExceptionList; DWORD64
    DWORD64 StackBase;
    DWORD64 StackLimit;
    DWORD64 SubSystemTib;
    union {
        DWORD64 FiberData;
        DWORD Version;
    };
    DWORD64 ArbitraryUserPointer;
    DWORD64 Self;
} NT_TIB64, * PNT_TIB64;

#ifdef _WIN64
typedef NT_TIB64                 NT_TIB;
#else
typedef NT_TIB32                 NT_TIB;
#endif

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    struct _ACTIVATION_CONTEXT* ActivationContext;
    ULONG                                       Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION
{
    PVOID ReflectionProcessHandle;
    PVOID ReflectionThreadHandle;
    CLIENT_ID ReflectionClientId;
}RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION, * PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;

typedef struct _RTLP_PROCESS_REFLECTION_CONTEXT
{
    QWORD ReflectionContextSize;
    DWORD ReflectionFlags;
    LONG(*ReflectionRoutine)(PVOID);
    PVOID ReflectionParameter;
    PVOID ReflectedProcessCreatedEvent;
    PVOID ReflectedProcessHandlesDuplicatedEvent;
    PVOID ReflectionStartEvent;
    RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION ReflectionInformation;
}RTLP_PROCESS_REFLECTION_CONTEXT, * PRTLP_PROCESS_REFLECTION_CONTEXT;

/*typedef struct _ACTIVATION_CONTEXT_STACK
{
    ULONG                               Flags;
    ULONG                               NextCookieSequenceNumber;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    LIST_ENTRY                          FrameListCache;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;*/

typedef struct _ACTIVATION_CONTEXT_STACK
{
    RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    LIST_ENTRY FrameListCache;
    DWORD Flags;
    DWORD NextCookieSequenceNumber;
    DWORD StackId;

} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;;

typedef struct _GDI_TEB_BATCH
{
    ULONG  Offset;
    HANDLE HDC;
    ULONG  Buffer[0x136];
} GDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG       Flags;
    const char* FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
    ULONG                     Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    TEB_ACTIVE_FRAME_CONTEXT* Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _TEB
{                                                                 /* win32/win64 */
    NT_TIB                       Tib;                               /* 000/0000 */
    PVOID                        EnvironmentPointer;                /* 01c/0038 */
    CLIENT_ID                    ClientId;                          /* 020/0040 */
    PVOID                        ActiveRpcHandle;                   /* 028/0050 */
    PVOID                        ThreadLocalStoragePointer;         /* 02c/0058 */
    PPEB                         Peb;                               /* 030/0060 */
    ULONG                        LastErrorValue;                    /* 034/0068 */
    ULONG                        CountOfOwnedCriticalSections;      /* 038/006c */
    PVOID                        CsrClientThread;                   /* 03c/0070 */
    PVOID                        Win32ThreadInfo;                   /* 040/0078 */
    ULONG                        Win32ClientInfo[31];               /* 044/0080 used for user32 private data in Wine */
    PVOID                        WOW32Reserved;                     /* 0c0/0100 used for ntdll syscall thunks */
    ULONG                        CurrentLocale;                     /* 0c4/0108 */
    ULONG                        FpSoftwareStatusRegister;          /* 0c8/010c */
    PVOID                        SystemReserved1[54];               /* 0cc/0110 used for krnl386.exe16 private data in Wine */
    LONG                         ExceptionCode;                     /* 1a4/02c0 */
    ACTIVATION_CONTEXT_STACK     ActivationContextStack;            /* 1a8/02c8 */
    BYTE                         SpareBytes1[24];                   /* 1bc/02e8 */
    PVOID                        SystemReserved2[10];               /* 1d4/0300 used for ntdll platform-specific private data in Wine */
    GDI_TEB_BATCH                GdiTebBatch;                       /* 1fc/0350 used for ntdll private data in Wine */
    HANDLE                       gdiRgn;                            /* 6dc/0838 */
    HANDLE                       gdiPen;                            /* 6e0/0840 */
    HANDLE                       gdiBrush;                          /* 6e4/0848 */
    CLIENT_ID                    RealClientId;                      /* 6e8/0850 */
    HANDLE                       GdiCachedProcessHandle;            /* 6f0/0860 */
    ULONG                        GdiClientPID;                      /* 6f4/0868 */
    ULONG                        GdiClientTID;                      /* 6f8/086c */
    PVOID                        GdiThreadLocaleInfo;               /* 6fc/0870 */
    ULONG                        UserReserved[5];                   /* 700/0878 */
    PVOID                        glDispatchTable[280];              /* 714/0890 */
    PVOID                        glReserved1[26];                   /* b74/1150 */
    PVOID                        glReserved2;                       /* bdc/1220 */
    PVOID                        glSectionInfo;                     /* be0/1228 */
    PVOID                        glSection;                         /* be4/1230 */
    PVOID                        glTable;                           /* be8/1238 */
    PVOID                        glCurrentRC;                       /* bec/1240 */
    PVOID                        glContext;                         /* bf0/1248 */
    ULONG                        LastStatusValue;                   /* bf4/1250 */
    UNICODE_STRING               StaticUnicodeString;               /* bf8/1258 used by advapi32 */
    WCHAR                        StaticUnicodeBuffer[261];          /* c00/1268 used by advapi32 */
    PVOID                        DeallocationStack;                 /* e0c/1478 */
    PVOID                        TlsSlots[64];                      /* e10/1480 */
    LIST_ENTRY                   TlsLinks;                          /* f10/1680 */
    PVOID                        Vdm;                               /* f18/1690 */
    PVOID                        ReservedForNtRpc;                  /* f1c/1698 */
    PVOID                        DbgSsReserved[2];                  /* f20/16a0 */
    ULONG                        HardErrorDisabled;                 /* f28/16b0 */
    PVOID                        Instrumentation[16];               /* f2c/16b8 */
    PVOID                        WinSockData;                       /* f6c/1738 */
    ULONG                        GdiBatchCount;                     /* f70/1740 */
    ULONG                        Spare2;                            /* f74/1744 */
    PVOID                        Spare3;                            /* f78/1748 used for fakedll thunks */
    PVOID                        Spare4;                            /* f7c/1750 */
    PVOID                        ReservedForOle;                    /* f80/1758 */
    ULONG                        WaitingOnLoaderLock;               /* f84/1760 */
    PVOID                        Reserved5[3];                      /* f88/1768 used for x86_64 OSX and wineserver shared memory */
    PVOID* TlsExpansionSlots;                 /* f94/1780 */
#ifdef _WIN64
    PVOID                        DeallocationBStore;                /*    /1788 */
    PVOID                        BStoreLimit;                       /*    /1790 */
#endif
    ULONG                        ImpersonationLocale;               /* f98/1798 */
    ULONG                        IsImpersonating;                   /* f9c/179c */
    PVOID                        NlsCache;                          /* fa0/17a0 */
    PVOID                        ShimData;                          /* fa4/17a8 */
    ULONG                        HeapVirtualAffinity;               /* fa8/17b0 */
    PVOID                        CurrentTransactionHandle;          /* fac/17b8 */
    TEB_ACTIVE_FRAME* ActiveFrame;                       /* fb0/17c0 */
    PVOID* FlsSlots;                          /* fb4/17c8 */
} TEB, * PTEB;

typedef struct _PROCESSOR_NUMBER
{
    WORD Group;
    UCHAR Number;
    UCHAR Reserved;
}PROCESSOR_NUMBER, * PPROCESSOR_NUMBER;

typedef struct _GDI_TEB_BATCH32
{
    union
    {
        DWORD Offset;
        DWORD HasRenderingCommand;
    } __bitfield0;
    DWORD HDC;
    DWORD Buffer[0x136];
}GDI_TEB_BATCH32, * PGDI_TEB_BATCH32;

typedef struct _GDI_TEB_BATCH64
{
    union
    {
        DWORD Offset;
        DWORD HasRenderingCommand;
    } __bitfield0;
    QWORD HDC;
    DWORD Buffer[0x136];
}GDI_TEB_BATCH64, * PGDI_TEB_BATCH64;

typedef struct _ACTIVATION_CONTEXT_STACK32
{
    DWORD ActiveFrame;
    LIST_ENTRY FrameListCache;
    DWORD Flags;
    DWORD NextCookieSequenceNumber;
    DWORD StackId;
}ACTIVATION_CONTEXT_STACK32, * PACTIVATION_CONTEXT_STACK32;

typedef struct _ACTIVATION_CONTEXT_STACK64
{
    QWORD ActiveFrame;
    LIST_ENTRY FrameListCache;
    DWORD Flags;
    DWORD NextCookieSequenceNumber;
    DWORD StackId;

}ACTIVATION_CONTEXT_STACK64, * PACTIVATION_CONTEXT_STACK64;

typedef struct _TEB64
{
    NT_TIB64 NtTib;
    QWORD EnvironmentPointer;
    CLIENT_ID ClientId;
    QWORD ActiveRpcHandle;
    QWORD ThreadLocalStoragePointer;
    QWORD ProcessEnvironmentBlock;
    DWORD LastErrorValue;
    DWORD CountOfOwnedCriticalSections;
    QWORD CsrClientThread;
    QWORD Win32ThreadInfo;
    DWORD User32Reserved[0x1a];
    DWORD UserReserved[0x5];
    QWORD WOW32Reserved;
    DWORD CurrentLocale;
    DWORD FpSoftwareStatusRegister;
    QWORD ReservedForDebuggerInstrumentation[0x10];
    QWORD SystemReserved1[0x1e];
    char PlaceholderCompatibilityMode;
    UCHAR PlaceholderHydrationAlwaysExplicit;
    char PlaceholderReserved[0xa];
    DWORD ProxiedProcessId;
    ACTIVATION_CONTEXT_STACK64 _ActivationStack;
    UCHAR WorkingOnBehalfTicket[0x8];
    LONG ExceptionCode;
    UCHAR Padding0[0x4];
    QWORD ActivationContextStackPointer;
    QWORD InstrumentationCallbackSp;
    QWORD InstrumentationCallbackPreviousPc;
    QWORD InstrumentationCallbackPreviousSp;
    DWORD TxFsContext;
    UCHAR InstrumentationCallbackDisabled;
    UCHAR UnalignedLoadStoreExceptions;
    UCHAR Padding1[0x2];
    GDI_TEB_BATCH64 GdiTebBatch;
    CLIENT_ID RealClientId;
    QWORD GdiCachedProcessHandle;
    DWORD GdiClientPID;
    DWORD GdiClientTID;
    QWORD GdiThreadLocalInfo;
    QWORD Win32ClientInfo[0x3e];
    QWORD glDispatchTable[0xe9];
    QWORD glReserved1[0x1d];
    QWORD glReserved2;
    QWORD glSectionInfo;
    QWORD glSection;
    QWORD glTable;
    QWORD glCurrentRC;
    QWORD glContext;
    DWORD LastStatusValue;
    UCHAR Padding2[0x4];
    STRING64 StaticUnicodeString;
    unsigned short StaticUnicodeBuffer[0x105];
    UCHAR Padding3[0x6];
    QWORD DeallocationStack;
    QWORD TlsSlots[0x40];
    LIST_ENTRY TlsLinks;
    QWORD Vdm;
    QWORD ReservedForNtRpc;
    QWORD DbgSsReserved[0x2];
    DWORD HardErrorMode;
    UCHAR Padding4[0x4];
    QWORD Instrumentation[0xb];
    GUID ActivityId;
    QWORD SubProcessTag;
    QWORD PerflibData;
    QWORD EtwTraceData;
    QWORD WinSockData;
    DWORD GdiBatchCount;
    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        DWORD IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        } __inner2;
    } __inner68;
    DWORD GuaranteedStackBytes;
    UCHAR Padding5[0x4];
    QWORD ReservedForPerf;
    QWORD ReservedForOle;
    DWORD WaitingOnLoaderLock;
    UCHAR Padding6[0x4];
    QWORD SavedPriorityState;
    QWORD ReservedForCodeCoverage;
    QWORD ThreadPoolData;
    QWORD TlsExpansionSlots;
    QWORD DeallocationBStore;
    QWORD BStoreLimit;
    DWORD MuiGeneration;
    DWORD IsImpersonating;
    QWORD NlsCache;
    QWORD pShimData;
    DWORD HeapData;
    UCHAR Padding7[0x4];
    QWORD CurrentTransactionHandle;
    QWORD ActiveFrame;
    QWORD FlsData;
    QWORD PreferredLanguages;
    QWORD UserPrefLanguages;
    QWORD MergedPrefLanguages;
    DWORD MuiImpersonation;
    union
    {
        WORD volatile CrossTebFlags;
        union
        {
            WORD SpareCrossTebBits;
        } __bitfield6124;
    } __inner94;
    union
    {
        WORD SameTebFlags;
        union
        {
            WORD SafeThunkCall;
            WORD InDebugPrint;
            WORD HasFiberData;
            WORD SkipThreadAttach;
            WORD WerInShipAssertCode;
            WORD RanProcessInit;
            WORD ClonedThread;
            WORD SuppressDebugMsg;
            WORD DisableUserStackWalk;
            WORD RtlExceptionAttached;
            WORD InitialThread;
            WORD SessionAware;
            WORD LoadOwner;
            WORD LoaderWorker;
            WORD SkipLoaderInit;
            WORD SpareSameTebBits;
        } __bitfield6126;
    } __inner95;
    QWORD TxnScopeEnterCallback;
    QWORD TxnScopeExitCallback;
    QWORD TxnScopeContext;
    DWORD LockCount;
    LONG WowTebOffset;
    QWORD ResourceRetValue;
    QWORD ReservedForWdf;
    QWORD ReservedForCrt;
    struct _GUID EffectiveContainerId;
}TEB64, * PTEB64;

typedef struct _TEB32
{
    NT_TIB32 NtTib;
    DWORD EnvironmentPointer;
    CLIENT_ID ClientId;
    DWORD ActiveRpcHandle;
    DWORD ThreadLocalStoragePointer;
    DWORD ProcessEnvironmentBlock;
    DWORD LastErrorValue;
    DWORD CountOfOwnedCriticalSections;
    DWORD CsrClientThread;
    DWORD Win32ThreadInfo;
    DWORD User32Reserved[0x1a];
    DWORD UserReserved[0x5];
    DWORD WOW32Reserved;
    DWORD CurrentLocale;
    DWORD FpSoftwareStatusRegister;
    DWORD ReservedForDebuggerInstrumentation[0x10];
    DWORD SystemReserved1[0x1a];
    char PlaceholderCompatibilityMode;
    UCHAR PlaceholderHydrationAlwaysExplicit;
    char PlaceholderReserved[0xa];
    DWORD ProxiedProcessId;
    ACTIVATION_CONTEXT_STACK32 _ActivationStack;
    UCHAR WorkingOnBehalfTicket[0x8];
    LONG ExceptionCode;
    DWORD ActivationContextStackPointer;
    DWORD InstrumentationCallbackSp;
    DWORD InstrumentationCallbackPreviousPc;
    DWORD InstrumentationCallbackPreviousSp;
    UCHAR InstrumentationCallbackDisabled;
    UCHAR SpareBytes[0x17];
    DWORD TxFsContext;
    GDI_TEB_BATCH32 GdiTebBatch;
    CLIENT_ID RealClientId;
    DWORD GdiCachedProcessHandle;
    DWORD GdiClientPID;
    DWORD GdiClientTID;
    DWORD GdiThreadLocalInfo;
    DWORD Win32ClientInfo[0x3e];
    DWORD glDispatchTable[0xe9];
    DWORD glReserved1[0x1d];
    DWORD glReserved2;
    DWORD glSectionInfo;
    DWORD glSection;
    DWORD glTable;
    DWORD glCurrentRC;
    DWORD glContext;
    DWORD LastStatusValue;
    STRING32 StaticUnicodeString;
    unsigned short StaticUnicodeBuffer[0x105];
    DWORD DeallocationStack;
    DWORD TlsSlots[0x40];
    LIST_ENTRY TlsLinks;
    DWORD Vdm;
    DWORD ReservedForNtRpc;
    DWORD DbgSsReserved[0x2];
    DWORD HardErrorMode;
    DWORD Instrumentation[0x9];
    GUID ActivityId;
    DWORD SubProcessTag;
    DWORD PerflibData;
    DWORD EtwTraceData;
    DWORD WinSockData;
    DWORD GdiBatchCount;
    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        DWORD IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        } __inner2;
    } __inner63;
    DWORD GuaranteedStackBytes;
    DWORD ReservedForPerf;
    DWORD ReservedForOle;
    DWORD WaitingOnLoaderLock;
    DWORD SavedPriorityState;
    DWORD ReservedForCodeCoverage;
    DWORD ThreadPoolData;
    DWORD TlsExpansionSlots;
    DWORD MuiGeneration;
    DWORD IsImpersonating;
    DWORD NlsCache;
    DWORD pShimData;
    DWORD HeapData;
    DWORD CurrentTransactionHandle;
    DWORD ActiveFrame;
    DWORD FlsData;
    DWORD PreferredLanguages;
    DWORD UserPrefLanguages;
    DWORD MergedPrefLanguages;
    DWORD MuiImpersonation;
    union
    {
        WORD volatile CrossTebFlags;
        union
        {
            WORD SpareCrossTebBits;
        } __bitfield4040;
    } __inner84;
    union
    {
        WORD SameTebFlags;
        union
        {
            WORD SafeThunkCall;
            WORD InDebugPrint;
            WORD HasFiberData;
            WORD SkipThreadAttach;
            WORD WerInShipAssertCode;
            WORD RanProcessInit;
            WORD ClonedThread;
            WORD SuppressDebugMsg;
            WORD DisableUserStackWalk;
            WORD RtlExceptionAttached;
            WORD InitialThread;
            WORD SessionAware;
            WORD LoadOwner;
            WORD LoaderWorker;
            WORD SkipLoaderInit;
            WORD SpareSameTebBits;
        } __bitfield4042;
    } __inner85;
    DWORD TxnScopeEnterCallback;
    DWORD TxnScopeExitCallback;
    DWORD TxnScopeContext;
    DWORD LockCount;
    LONG WowTebOffset;
    DWORD ResourceRetValue;
    DWORD ReservedForWdf;
    QWORD ReservedForCrt;
    GUID EffectiveContainerId;
}TEB32, * PTEB32;

typedef struct _FIBER
{
    PVOID FiberData;
    EXCEPTION_REGISTRATION_RECORD* ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID DeallocationStack;
    CONTEXT FiberContext;
    struct _Wx86TIB* Wx86Tib;
    ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
    PVOID FlsData;
    DWORD GuaranteedStackBytes;
    WORD TebFlags;
    WORD ReservedPad;
    QWORD FiberCookie;

}FIBER, * PFIBER;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PWCHAR Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName;
    UNICODE_STRING HeapPartitionName;
    PVOID DefaultThreadpoolCpuSetMasks; //uint64_t* DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState = 0x0,
    PsCreateFailOnFileOpen = 0x1,
    PsCreateFailOnSectionCreate = 0x2,
    PsCreateFailExeFormat = 0x3,
    PsCreateFailMachineMismatch = 0x4,
    PsCreateFailExeName = 0x5,
    PsCreateSuccess = 0x6,
    PsCreateMaximumStates = 0x7
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                } s1;
            } u1;
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // From Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                } s2;
            } u2;
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;                // PROC_THREAD_ATTRIBUTE_XXX | PROC_THREAD_ATTRIBUTE_XXX modifiers, see ProcThreadAttributeValue macro and Windows Internals 6 (372)
    SIZE_T Size;                        // Size of Value or *ValuePtr
    union
    {
        ULONG_PTR Value;                // Reserve 8 bytes for data (such as a Handle or a data pointer)
        PVOID ValuePtr;                 // data pointer
    };
    PSIZE_T ReturnLength;               // Either 0 or specifies size of data returned to caller via "ValuePtr"
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;                 // sizeof(PS_ATTRIBUTE_LIST)
    PS_ATTRIBUTE Attributes[2];         // Depends on how many attribute entries should be supplied to NtCreateUserProcess
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef enum _MEM_EXTENDED_PARAMETER_TYPE {
    MemExtendedParameterInvalidType = 0,
    MemExtendedParameterAddressRequirements,
    MemExtendedParameterNumaNode,
    MemExtendedParameterPartitionHandle,
    MemExtendedParameterUserPhysicalHandle,
    MemExtendedParameterAttributeFlags,
    MemExtendedParameterImageMachine,
    MemExtendedParameterMax
}  MEM_EXTENDED_PARAMETER_TYPE, * PMEM_EXTENDED_PARAMETER_TYPE;

typedef struct _MEM_ADDRESS_REQUIREMENTS {
    PVOID  LowestStartingAddress;
    PVOID  HighestEndingAddress;
    SIZE_T Alignment;
} MEM_ADDRESS_REQUIREMENTS, * PMEM_ADDRESS_REQUIREMENTS;


//https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-mem_extended_parameter
typedef struct MEM_EXTENDED_PARAMETER {
    struct {
        DWORD64 Type : 1;//MEM_EXTENDED_PARAMETER_TYPE_BITS  //MEM_EXTENDED_PARAMETER_TYPE
        DWORD64 Reserved : 64 - 1;//MEM_EXTENDED_PARAMETER_TYPE_BITS // MEM_EXTENDED_PARAMETER_TYPE
    } DUMMYSTRUCTNAME;
    union {
        DWORD64 ULong64;
        PVOID   Pointer;
        SIZE_T  Size;
        HANDLE  Handle;
        DWORD   ULong;
    } DUMMYUNIONNAME;
} MEM_EXTENDED_PARAMETER, * PMEM_EXTENDED_PARAMETER;

//-------------------

typedef enum _ACE_FLAGS // uint32_t
{
    CONTAINER_INHERIT_ACE = 0x2,
    FAILED_ACCESS_ACE_FLAG = 0x80,
    INHERIT_ONLY_ACE = 0x8,
    INHERITED_ACE = 0x10,
    NO_PROPAGATE_INHERIT_ACE = 0x4,
    OBJECT_INHERIT_ACE = 0x1,
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x40,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x3,
    SUB_CONTAINERS_ONLY_INHERIT = 0x2,
    SUB_OBJECTS_ONLY_INHERIT = 0x1,
    INHERIT_NO_PROPAGATE = 0x4,
    INHERIT_ONLY = 0x8,
    NO_INHERITANCE = 0x0
}ACE_FLAGS, * PACE_FLAGS;

typedef struct _ACE_HEADER
{
    UCHAR AceType;
    UCHAR AceFlags;
    WORD AceSize;
}ACE_HEADER, * PACE_HEADER;

typedef struct _ACCESS_ALLOWED_ACE
{
    ACE_HEADER Header;
    DWORD Mask;
    DWORD SidStart;
}ACCESS_ALLOWED_ACE, * PACCESS_ALLOWED_ACE;

typedef struct _ACCESS_ALLOWED_CALLBACK_ACE
{
    ACE_HEADER Header;
    DWORD Mask;
    DWORD SidStart;
}ACCESS_ALLOWED_CALLBACK_ACE, * PACCESS_ALLOWED_CALLBACK_ACE;

typedef struct _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
{
    ACE_HEADER Header;
    DWORD Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
}ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, * PACCESS_ALLOWED_CALLBACK_OBJECT_ACE;

typedef struct _ACCESS_ALLOWED_OBJECT_ACE
{
    ACE_HEADER Header;
    DWORD Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
}ACCESS_ALLOWED_OBJECT_ACE, * PACCESS_ALLOWED_OBJECT_ACE;

typedef struct _ACCESS_DENIED_ACE
{
    ACE_HEADER Header;
    DWORD Mask;
    DWORD SidStart;
}ACCESS_DENIED_ACE, * PACCESS_DENIED_ACE;

typedef struct _ACCESS_DENIED_CALLBACK_ACE
{
    ACE_HEADER Header;
    DWORD Mask;
    DWORD SidStart;
}ACCESS_DENIED_CALLBACK_ACE, * PACCESS_DENIED_CALLBACK_ACE;

typedef struct _ACCESS_DENIED_CALLBACK_OBJECT_ACE
{
    ACE_HEADER Header;
    DWORD Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
}ACCESS_DENIED_CALLBACK_OBJECT_ACE, * PACCESS_DENIED_CALLBACK_OBJECT_ACE;

typedef struct _ACCESS_DENIED_OBJECT_ACE
{
    ACE_HEADER Header;
    DWORD Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
}ACCESS_DENIED_OBJECT_ACE, * PACCESS_DENIED_OBJECT_ACE;

typedef enum _SYSTEM_AUDIT_OBJECT_ACE_FLAGS // uint32_t
{
    ACE_OBJECT_TYPE_PRESENT = 0x1,
    ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2
}SYSTEM_AUDIT_OBJECT_ACE_FLAGS, * PSYSTEM_AUDIT_OBJECT_ACE_FLAGS;

typedef struct _ACTCTXW
{
    DWORD cbSize;
    DWORD dwFlags;
    PWSTR lpSource;
    WORD wProcessorArchitecture;
    WORD wLangId;
    PWSTR lpAssemblyDirectory;
    PWSTR lpResourceName;
    PWSTR lpApplicationName;
    HINSTANCE hModule;
}ACTCTXW, * PACTCTXW;

typedef enum _ACTCTX_COMPATIBILITY_ELEMENT_TYPE // int32_t
{
    ACTCTX_COMPATIBILITY_ELEMENT_TYPE_UNKNOWN = 0x0,
    ACTCTX_COMPATIBILITY_ELEMENT_TYPE_OS = 0x1,
    ACTCTX_COMPATIBILITY_ELEMENT_TYPE_MITIGATION = 0x2,
    ACTCTX_COMPATIBILITY_ELEMENT_TYPE_MAXVERSIONTESTED = 0x3
}ACTCTX_COMPATIBILITY_ELEMENT_TYPE, * PACTCTX_COMPATIBILITY_ELEMENT_TYPE;

typedef enum _ACTCTX_REQUESTED_RUN_LEVEL // int32_t
{
    ACTCTX_RUN_LEVEL_UNSPECIFIED = 0x0,
    ACTCTX_RUN_LEVEL_AS_INVOKER = 0x1,
    ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE = 0x2,
    ACTCTX_RUN_LEVEL_REQUIRE_ADMIN = 0x3,
    ACTCTX_RUN_LEVEL_NUMBERS = 0x4
}ACTCTX_REQUESTED_RUN_LEVEL, * PACTCTX_REQUESTED_RUN_LEVEL;

typedef struct _ACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA
{
    PVOID lpInformation;
    PVOID lpSectionBase;
    DWORD ulSectionLength;
    PVOID lpSectionGlobalDataBase;
    DWORD ulSectionGlobalDataLength;
}ACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA, * PACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA;

typedef struct _ACTCTX_SECTION_KEYED_DATA
{
    DWORD cbSize;
    DWORD ulDataFormatVersion;
    PVOID lpData;
    DWORD ulLength;
    PVOID lpSectionGlobalData;
    DWORD ulSectionGlobalDataLength;
    PVOID lpSectionBase;
    DWORD ulSectionTotalLength;
    HANDLE hActCtx;
    DWORD ulAssemblyRosterIndex;
    DWORD ulFlags;
    ACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA AssemblyMetadata;
}ACTCTX_SECTION_KEYED_DATA, * PACTCTX_SECTION_KEYED_DATA;

typedef struct _SOCKADDR
{
    WORD sa_family;
    CHAR sa_data[0xe];
}SOCKADDR, * PSOCKADDR;

typedef struct _ADDRINFOA
{
    LONG ai_flags;
    LONG ai_family;
    LONG ai_socktype;
    LONG ai_protocol;
    QWORD* ai_addrlen;// uint64_t*
    PSTR ai_canonname;
    SOCKADDR* ai_addr;
    struct ADDRINFOA* ai_next;
}ADDRINFOA, * PADDRINFOA;

typedef struct _ADDRINFOW
{
    LONG ai_flags;
    LONG ai_family;
    LONG ai_socktype;
    LONG ai_protocol;
    QWORD* ai_addrlen;//uint64_t
    PWSTR ai_canonname;
    SOCKADDR* ai_addr;
    struct ADDRINFOW* ai_next;
}ADDRINFOW, * PADDRINFOW;

typedef union __u_e__Union
{
    UCHAR Byte[0x10];//uint8_t
    WORD Word[0x8];
}_u_e__Union, * P_u_e__Union;

typedef struct __S_un_b_e__Struct
{
    UCHAR s_b1;
    UCHAR s_b2;
    UCHAR s_b3;
    UCHAR s_b4;
}_S_un_b_e__Struct, * P_S_un_b_e__Struct;

typedef struct __S_un_w_e__Struct
{
    WORD s_w1;
    WORD s_w2;
}_S_un_w_e__Struct, * P_S_un_w_e__Struct;

typedef union __S_un_e__Union
{
    _S_un_b_e__Struct S_un_b;
    _S_un_w_e__Struct S_un_w;
    DWORD S_addr;
}_S_un_e__Union, * P_S_un_e__Union;

typedef struct _IN6_ADDR
{
    _u_e__Union u;
}IN6_ADDR, * PIN6_ADDR;

typedef struct _IN_ADDR
{
    _S_un_e__Union S_un;
}IN_ADDR, * PIN_ADDR;

typedef struct _SOCKADDR_IN
{
    WORD sin_family;
    WORD sin_port;
    IN_ADDR sin_addr;
    CHAR sin_zero[0x8];
}SOCKADDR_IN, * PSOCKADDR_IN;

typedef struct _SCOPE_ID
{
    union
    {
        struct
        {
            DWORD _bitfield;
        };
        DWORD Value;
    };
}SCOPE_ID, * PSCOPE_ID;

typedef struct _SOCKADDR_IN6
{
    WORD sin6_family;
    WORD sin6_port;
    DWORD sin6_flowinfo;
    IN6_ADDR sin6_addr;
    union
    {
        DWORD sin6_scope_id;
        SCOPE_ID sin6_scope_struct;
    };
}SOCKADDR_IN6, * PSOCKADDR_IN6;

typedef union _SOCKADDR_INET
{
    SOCKADDR_IN Ipv4;
    SOCKADDR_IN6 Ipv6;
    WORD si_family;
}SOCKADDR_INET, * PSOCKADDR_INET;

typedef struct _IP_ADDRESS_PREFIX
{
    SOCKADDR_INET Prefix;
    UCHAR PrefixLength;
}IP_ADDRESS_PREFIX, * PIP_ADDRESS_PREFIX;

typedef struct _MIB_IPADDRROW_XP
{
    DWORD dwAddr;
    DWORD dwIndex;
    DWORD dwMask;
    DWORD dwBCastAddr;
    DWORD dwReasmSize;
    WORD unused1;
    WORD wType;
}MIB_IPADDRROW_XP, * PMIB_IPADDRROW_XP;

typedef struct _MIB_IPADDRTABLE
{
    DWORD dwNumEntries;
    struct MIB_IPADDRROW_XP* table;
}MIB_IPADDRTABLE, * PMIB_IPADDRTABLE;

typedef enum _NL_DAD_STATE //: uint32_t
{
    NldsInvalid = 0x0,
    NldsTentative = 0x1,
    NldsDuplicate = 0x2,
    NldsDeprecated = 0x3,
    NldsPreferred = 0x4,
    IpDadStateInvalid = 0x0,
    IpDadStateTentative = 0x1,
    IpDadStateDuplicate = 0x2,
    IpDadStateDeprecated = 0x3,
    IpDadStatePreferred = 0x4
}NL_DAD_STATE, * PNL_DAD_STATE;

typedef enum _NL_PREFIX_ORIGIN //: uint32_t
{
    IpPrefixOriginOther = 0x0,
    IpPrefixOriginManual = 0x1,
    IpPrefixOriginWellKnown = 0x2,
    IpPrefixOriginDhcp = 0x3,
    IpPrefixOriginRouterAdvertisement = 0x4,
    IpPrefixOriginUnchanged = 0x10
}NL_PREFIX_ORIGIN, * PNL_PREFIX_ORIGIN;

typedef enum _NL_ROUTE_ORIGIN //: uint32_t
{
    NlroManual = 0x0,
    NlroWellKnown = 0x1,
    NlroDHCP = 0x2,
    NlroRouterAdvertisement = 0x3,
    Nlro6to4 = 0x4
}NL_ROUTE_ORIGIN, * PNL_ROUTE_ORIGIN;

typedef enum _NL_ROUTE_PROTOCOL //: uint32_t
{
    RouteProtocolOther = 0x1,
    RouteProtocolLocal = 0x2,
    RouteProtocolNetMgmt = 0x3,
    RouteProtocolIcmp = 0x4,
    RouteProtocolEgp = 0x5,
    RouteProtocolGgp = 0x6,
    RouteProtocolHello = 0x7,
    RouteProtocolRip = 0x8,
    RouteProtocolIsIs = 0x9,
    RouteProtocolEsIs = 0xa,
    RouteProtocolCisco = 0xb,
    RouteProtocolBbn = 0xc,
    RouteProtocolOspf = 0xd,
    RouteProtocolBgp = 0xe,
    RouteProtocolIdpr = 0xf,
    RouteProtocolEigrp = 0x10,
    RouteProtocolDvmrp = 0x11,
    RouteProtocolRpl = 0x12,
    RouteProtocolDhcp = 0x13,
    MIB_IPPROTO_OTHER = 0x1,
    PROTO_IP_OTHER = 0x1,
    MIB_IPPROTO_LOCAL = 0x2,
    PROTO_IP_LOCAL = 0x2,
    MIB_IPPROTO_NETMGMT = 0x3,
    PROTO_IP_NETMGMT = 0x3,
    MIB_IPPROTO_ICMP = 0x4,
    PROTO_IP_ICMP = 0x4,
    MIB_IPPROTO_EGP = 0x5,
    PROTO_IP_EGP = 0x5,
    MIB_IPPROTO_GGP = 0x6,
    PROTO_IP_GGP = 0x6,
    MIB_IPPROTO_HELLO = 0x7,
    PROTO_IP_HELLO = 0x7,
    MIB_IPPROTO_RIP = 0x8,
    PROTO_IP_RIP = 0x8,
    MIB_IPPROTO_IS_IS = 0x9,
    PROTO_IP_IS_IS = 0x9,
    MIB_IPPROTO_ES_IS = 0xa,
    PROTO_IP_ES_IS = 0xa,
    MIB_IPPROTO_CISCO = 0xb,
    PROTO_IP_CISCO = 0xb,
    MIB_IPPROTO_BBN = 0xc,
    PROTO_IP_BBN = 0xc,
    MIB_IPPROTO_OSPF = 0xd,
    PROTO_IP_OSPF = 0xd,
    MIB_IPPROTO_BGP = 0xe,
    PROTO_IP_BGP = 0xe,
    MIB_IPPROTO_IDPR = 0xf,
    PROTO_IP_IDPR = 0xf,
    MIB_IPPROTO_EIGRP = 0x10,
    PROTO_IP_EIGRP = 0x10,
    MIB_IPPROTO_DVMRP = 0x11,
    PROTO_IP_DVMRP = 0x11,
    MIB_IPPROTO_RPL = 0x12,
    PROTO_IP_RPL = 0x12,
    MIB_IPPROTO_DHCP = 0x13,
    PROTO_IP_DHCP = 0x13,
    MIB_IPPROTO_NT_AUTOSTATIC = 0x2712,
    PROTO_IP_NT_AUTOSTATIC = 0x2712,
    MIB_IPPROTO_NT_STATIC = 0x2716,
    PROTO_IP_NT_STATIC = 0x2716,
    MIB_IPPROTO_NT_STATIC_NON_DOD = 0x2717,
    PROTO_IP_NT_STATIC_NON_DOD = 0x2717
}NL_ROUTE_PROTOCOL, * PNL_ROUTE_PROTOCOL;

typedef enum _NL_SUFFIX_ORIGIN //: uint32_t
{
    NlsoOther = 0x0,
    NlsoManual = 0x1,
    NlsoWellKnown = 0x2,
    NlsoDhcp = 0x3,
    NlsoLinkLayerAddress = 0x4,
    NlsoRandom = 0x5,
    IpSuffixOriginOther = 0x0,
    IpSuffixOriginManual = 0x1,
    IpSuffixOriginWellKnown = 0x2,
    IpSuffixOriginDhcp = 0x3,
    IpSuffixOriginLinkLayerAddress = 0x4,
    IpSuffixOriginRandom = 0x5,
    IpSuffixOriginUnchanged = 0x10
}NL_SUFFIX_ORIGIN, * PNL_SUFFIX_ORIGIN;

typedef struct __Info_e__Struct
{
    QWORD _bitfield;
}_Info_e__Struct, * P_Info_e__Struct;

typedef union _NET_LUID_LH
{
    QWORD Value;
    _Info_e__Struct Info;
}NET_LUID_LH, * PNET_LUID_LH;

typedef struct _MIB_IPFORWARD_ROW2
{
    NET_LUID_LH InterfaceLuid;
    DWORD InterfaceIndex;
    IP_ADDRESS_PREFIX DestinationPrefix;
    SOCKADDR_INET NextHop;
    UCHAR SitePrefixLength;
    DWORD ValidLifetime;
    DWORD PreferredLifetime;
    DWORD Metric;
    NL_ROUTE_PROTOCOL Protocol;
    BOOLEAN Loopback;
    BOOLEAN AutoconfigureAddress;
    BOOLEAN Publish;
    BOOLEAN Immortal;
    DWORD Age;
    NL_ROUTE_ORIGIN Origin;
}MIB_IPFORWARD_ROW2, * PMIB_IPFORWARD_ROW2;

typedef struct _MIB_UNICASTIPADDRESS_ROW
{
    SOCKADDR_INET Address;
    NET_LUID_LH InterfaceLuid;
    DWORD InterfaceIndex;
    NL_PREFIX_ORIGIN PrefixOrigin;
    NL_SUFFIX_ORIGIN SuffixOrigin;
    DWORD ValidLifetime;
    DWORD PreferredLifetime;
    UCHAR OnLinkPrefixLength;
    BOOLEAN SkipAsSource;
    NL_DAD_STATE DadState;
    SCOPE_ID ScopeId;
    LARGE_INTEGER CreationTimeStamp;
}MIB_UNICASTIPADDRESS_ROW, * PMIB_UNICASTIPADDRESS_ROW;

typedef struct _MIB_UNICASTIPADDRESS_TABLE
{
    DWORD NumEntries;
    struct MIB_UNICASTIPADDRESS_ROW* Table;
}MIB_UNICASTIPADDRESS_TABLE, * PMIB_UNICASTIPADDRESS_TABLE;

typedef struct _WSABUF
{
    DWORD len;
    PSTR buf;
}WSABUF, * PWSABUF;

typedef struct _WSAPROTOCOLCHAIN
{
    LONG ChainLen;
    DWORD ChainEntries[0x7];
}WSAPROTOCOLCHAIN, * PWSAPROTOCOLCHAIN;

typedef struct _WSAPROTOCOL_INFOW
{
    DWORD dwServiceFlags1;
    DWORD dwServiceFlags2;
    DWORD dwServiceFlags3;
    DWORD dwServiceFlags4;
    DWORD dwProviderFlags;
    GUID ProviderId;
    DWORD dwCatalogEntryId;
    WSAPROTOCOLCHAIN ProtocolChain;
    LONG iVersion;
    LONG iAddressFamily;
    LONG iMaxSockAddr;
    LONG iMinSockAddr;
    LONG iSocketType;
    LONG iProtocol;
    LONG iProtocolMaxOffset;
    LONG iNetworkByteOrder;
    LONG iSecurityScheme;
    DWORD dwMessageSize;
    DWORD dwProviderReserved;
    char szProtocol[0x100];
}WSAPROTOCOL_INFOW, * PWSAPROTOCOL_INFOW;

typedef enum _CLSCTX // uint32_t
{
    CLSCTX_INPROC_SERVER = 0x1,
    CLSCTX_INPROC_HANDLER = 0x2,
    CLSCTX_LOCAL_SERVER = 0x4,
    CLSCTX_INPROC_SERVER16 = 0x8,
    CLSCTX_REMOTE_SERVER = 0x10,
    CLSCTX_INPROC_HANDLER16 = 0x20,
    CLSCTX_RESERVED1 = 0x40,
    CLSCTX_RESERVED2 = 0x80,
    CLSCTX_RESERVED3 = 0x100,
    CLSCTX_RESERVED4 = 0x200,
    CLSCTX_NO_CODE_DOWNLOAD = 0x400,
    CLSCTX_RESERVED5 = 0x800,
    CLSCTX_NO_CUSTOM_MARSHAL = 0x1000,
    CLSCTX_ENABLE_CODE_DOWNLOAD = 0x2000,
    CLSCTX_NO_FAILURE_LOG = 0x4000,
    CLSCTX_DISABLE_AAA = 0x8000,
    CLSCTX_ENABLE_AAA = 0x10000,
    CLSCTX_FROM_DEFAULT_CONTEXT = 0x20000,
    CLSCTX_ACTIVATE_X86_SERVER = 0x40000,
    CLSCTX_ACTIVATE_32_BIT_SERVER = 0x40000,
    CLSCTX_ACTIVATE_64_BIT_SERVER = 0x80000,
    CLSCTX_ENABLE_CLOAKING = 0x100000,
    CLSCTX_APPCONTAINER = 0x400000,
    CLSCTX_ACTIVATE_AAA_AS_IU = 0x800000,
    CLSCTX_RESERVED6 = 0x1000000,
    CLSCTX_ACTIVATE_ARM32_SERVER = 0x2000000,
    CLSCTX_PS_DLL = 0x80000000,
    CLSCTX_ALL = 0x17,
    CLSCTX_SERVER = 0x15
}CLSCTX, * PCLSCTX;

typedef enum _COINIT // uint32_t
{
    COINIT_APARTMENTTHREADED = 0x2,
    COINIT_MULTITHREADED = 0x0,
    COINIT_DISABLE_OLE1DDE = 0x4,
    COINIT_SPEED_OVER_MEMORY = 0x8
}COINIT, * PCOINIT;

typedef __int64 _HRESULT;

typedef struct _IUNKNOWN
{
    HRESULT(*QueryInterface)(GUID* riid, void** ppvObject);
    DWORD(*AddRef)();
    DWORD(*Release)();
}IUNKNOWN, * PIUNKNOWN;

typedef enum _STREAM_SEEK // uint32_t
{
    STREAM_SEEK_SET = 0x0,
    STREAM_SEEK_CUR = 0x1,
    STREAM_SEEK_END = 0x2
}STREAM_SEEK, * PSTREAM_SEEK;

typedef enum _STGC // uint32_t
{
    STGC_DEFAULT = 0x0,
    STGC_OVERWRITE = 0x1,
    STGC_ONLYIFCURRENT = 0x2,
    STGC_DANGEROUSLYCOMMITMERELYTODISKCACHE = 0x4,
    STGC_CONSOLIDATE = 0x8
}STGC, * PSTGC;

typedef struct _STATSTG
{
    PWSTR pwcsName;
    DWORD type;
    ULARGE_INTEGER cbSize;
    FILETIME mtime;
    FILETIME ctime;
    FILETIME atime;
    DWORD grfMode;
    DWORD grfLocksSupported;
    GUID clsid;
    DWORD grfStateBits;
    DWORD reserved;
}STATSTG, * PSTATSTG;

typedef enum _STGM // uint32_t
{
    STGM_DIRECT = 0x0,
    STGM_TRANSACTED = 0x10000,
    STGM_SIMPLE = 0x8000000,
    STGM_READ = 0x0,
    STGM_WRITE = 0x1,
    STGM_READWRITE = 0x2,
    STGM_SHARE_DENY_NONE = 0x40,
    STGM_SHARE_DENY_READ = 0x30,
    STGM_SHARE_DENY_WRITE = 0x20,
    STGM_SHARE_EXCLUSIVE = 0x10,
    STGM_PRIORITY = 0x40000,
    STGM_DELETEONRELEASE = 0x4000000,
    STGM_NOSCRATCH = 0x100000,
    STGM_CREATE = 0x1000,
    STGM_CONVERT = 0x20000,
    STGM_FAILIFTHERE = 0x0,
    STGM_NOSNAPSHOT = 0x200000,
    STGM_DIRECT_SWMR = 0x400000
}STGM, * PSTGM;

typedef enum _STGMOVE // uint32_t
{
    STGMOVE_MOVE = 0x0,
    STGMOVE_COPY = 0x1,
    STGMOVE_SHALLOWCOPY = 0x2
}STGMOVE, * PSTGMOVE;

typedef struct _IENUMSTATSTG
{
    HRESULT(*Next)(DWORD celt, STATSTG* rgelt, DWORD* pceltFetched);
    HRESULT(*Skip)(DWORD celt);
    HRESULT(*Reset)();
    HRESULT(*Clone)(struct IENUMSTATSTG* ppenum);
}IENUMSTATSTG, * PIENUMSTATSTG;

typedef struct _ISTREAM
{
    HRESULT(*Seek)(LARGE_INTEGER dlibMove, STREAM_SEEK dwOrigin, ULARGE_INTEGER* plibNewPosition);
    HRESULT(*SetSize)(ULARGE_INTEGER libNewSize);
    HRESULT(*CopyTo)(struct ISTREAM pstm, ULARGE_INTEGER cb, ULARGE_INTEGER* pcbRead, ULARGE_INTEGER* pcbWritten);
    HRESULT(*Commit)(STGC grfCommitFlags);
    HRESULT(*Revert)();
    HRESULT(*LockRegion)(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType);
    HRESULT(*UnlockRegion)(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType);
    HRESULT(*Stat)(STATSTG* pstatstg, DWORD grfStatFlag);
    HRESULT(*Clone)(struct ISTREAM* ppstm);
}ISTREAM, * PISTREAM;

typedef struct _ISTORAGE
{
    HRESULT(*CreateStream)(PWSTR pwcsName, STGM grfMode, DWORD reserved1, DWORD reserved2, ISTREAM* ppstm);
    HRESULT(*OpenStream)(PWSTR pwcsName, PVOID reserved1, STGM grfMode, DWORD reserved2, ISTREAM* ppstm);
    HRESULT(*CreateStorage)(PWSTR pwcsName, STGM grfMode, DWORD reserved1, DWORD reserved2, struct ISTORAGE* ppstg);
    HRESULT(*OpenStorage)(PWSTR pwcsName, struct ISTORAGE pstgPriority, STGM grfMode, WORD** snbExclude, DWORD reserved, struct ISTORAGE* ppstg);
    HRESULT(*CopyTo)(DWORD ciidExclude, GUID* rgiidExclude, WORD** snbExclude, struct ISTORAGE pstgDest);
    HRESULT(*MoveElementTo)(PWSTR pwcsName, struct ISTORAGE pstgDest, PWSTR pwcsNewName, STGMOVE grfFlags);
    HRESULT(*Commit)(STGC grfCommitFlags);
    HRESULT(*Revert)();
    HRESULT(*EnumElements)(DWORD reserved1, PVOID reserved2, DWORD reserved3, IENUMSTATSTG* ppenum);
    HRESULT(*DestroyElement)(PWSTR pwcsName);
    HRESULT(*RenameElement)(PWSTR pwcsOldName, PWSTR pwcsNewName);
    HRESULT(*SetElementTimes)(PWSTR pwcsName, FILETIME* pctime, FILETIME* patime, FILETIME* pmtime);
    HRESULT(*SetClass)(GUID* clsid);
    HRESULT(*SetStateBits)(DWORD grfStateBits, DWORD grfMask);
    HRESULT(*Stat)(STATSTG* pstatstg, DWORD grfStatFlag);
}ISTORAGE, * PISTORAGE;

typedef struct _STGMEDIUM
{
    DWORD tymed;
    union
    {
        HBITMAP hBitmap;
        void* hMetaFilePict;
        HENHMETAFILE hEnhMetaFile;
        __int64* hGlobal;//  int64_t*
        PWSTR lpszFileName;
        ISTREAM pstm;
        ISTORAGE pstg;
    };
    IUNKNOWN pUnkForRelease;
}STGMEDIUM, * PSTGMEDIUM;

typedef struct _BINDINFO
{
    DWORD cbSize;
    PWSTR szExtraInfo;
    STGMEDIUM stgmedData;
    DWORD grfBindInfoF;
    DWORD dwBindVerb;
    PWSTR szCustomVerb;
    DWORD cbstgmedData;
    DWORD dwOptions;
    DWORD dwOptionsFlags;
    DWORD dwCodePage;
    SECURITY_ATTRIBUTES securityAttributes;
    GUID iid;
    IUNKNOWN pUnk;
    DWORD dwReserved;
}BINDINFO, * PBINDINFO;

typedef struct _BIND_OPTS
{
    DWORD cbStruct;
    DWORD grfFlags;
    DWORD grfMode;
    DWORD dwTickCountDeadline;
}BIND_OPTS, * PBIND_OPTS;

typedef enum _DNS_CONFIG_TYPE // uint32_t
{
    DnsConfigPrimaryDomainName_W = 0x0,
    DnsConfigPrimaryDomainName_A = 0x1,
    DnsConfigPrimaryDomainName_UTF8 = 0x2,
    DnsConfigAdapterDomainName_W = 0x3,
    DnsConfigAdapterDomainName_A = 0x4,
    DnsConfigAdapterDomainName_UTF8 = 0x5,
    DnsConfigDnsServerList = 0x6,
    DnsConfigSearchList = 0x7,
    DnsConfigAdapterInfo = 0x8,
    DnsConfigPrimaryHostNameRegistrationEnabled = 0x9,
    DnsConfigAdapterHostNameRegistrationEnabled = 0xa,
    DnsConfigAddressRegistrationMaxCount = 0xb,
    DnsConfigHostName_W = 0xc,
    DnsConfigHostName_A = 0xd,
    DnsConfigHostName_UTF8 = 0xe,
    DnsConfigFullHostName_W = 0xf,
    DnsConfigFullHostName_A = 0x10,
    DnsConfigFullHostName_UTF8 = 0x11,
    DnsConfigNameServer = 0x12
}DNS_CONFIG_TYPE, * PDNS_CONFIG_TYPE;

typedef enum _DNS_NAME_FORMAT // uint32_t
{
    DnsNameDomain = 0x0,
    DnsNameDomainLabel = 0x1,
    DnsNameHostnameFull = 0x2,
    DnsNameHostnameLabel = 0x3,
    DnsNameWildcard = 0x4,
    DnsNameSrvRecord = 0x5,
    DnsNameValidateTld = 0x6
}DNS_NAME_FORMAT, * PDNS_NAME_FORMAT;

typedef enum _NAMED_PIPE_MODE // uint32_t
{
    PIPE_WAIT = 0x0,
    PIPE_NOWAIT = 0x1,
    PIPE_READMODE_BYTE = 0x0,
    PIPE_READMODE_MESSAGE = 0x2,
    PIPE_CLIENT_END = 0x0,
    PIPE_SERVER_END = 0x1,
    PIPE_TYPE_BYTE = 0x0,
    PIPE_TYPE_MESSAGE = 0x4,
    PIPE_ACCEPT_REMOTE_CLIENTS = 0x0,
    PIPE_REJECT_REMOTE_CLIENTS = 0x8
}NAMED_PIPE_MODE, * PNAMED_PIPE_MODE;

typedef enum _ACTIVATE_KEYBOARD_LAYOUT_FLAGS // uint32_t
{
    KLF_REORDER = 0x8,
    KLF_RESET = 0x40000000,
    KLF_SETFORPROCESS = 0x100,
    KLF_SHIFTLOCK = 0x10000,
    KLF_ACTIVATE = 0x1,
    KLF_NOTELLSHELL = 0x80,
    KLF_REPLACELANG = 0x10,
    KLF_SUBSTITUTE_OK = 0x2
}ACTIVATE_KEYBOARD_LAYOUT_FLAGS, * PACTIVATE_KEYBOARD_LAYOUT_FLAGS;

typedef enum _BROADCAST_SYSTEM_MESSAGE_FLAGS // uint32_t
{
    BSF_ALLOWSFW = 0x80,
    BSF_FLUSHDISK = 0x4,
    BSF_FORCEIFHUNG = 0x20,
    BSF_IGNORECURRENTTASK = 0x2,
    BSF_NOHANG = 0x8,
    BSF_NOTIMEOUTIFNOTHUNG = 0x40,
    BSF_POSTMESSAGE = 0x10,
    BSF_QUERY = 0x1,
    BSF_SENDNOTIFYMESSAGE = 0x100,
    BSF_LUID = 0x400,
    BSF_RETURNHDESK = 0x200
}BROADCAST_SYSTEM_MESSAGE_FLAGS, * PBROADCAST_SYSTEM_MESSAGE_FLAGS;

typedef enum _BROADCAST_SYSTEM_MESSAGE_INFO // uint32_t
{
    BSM_ALLCOMPONENTS = 0x0,
    BSM_ALLDESKTOPS = 0x10,
    BSM_APPLICATIONS = 0x8
}BROADCAST_SYSTEM_MESSAGE_INFO, * PBROADCAST_SYSTEM_MESSAGE_INFO;

typedef enum _CALLCONV // uint32_t
{
    CC_FASTCALL = 0x0,
    CC_CDECL = 0x1,
    CC_MSCPASCAL = 0x2,
    CC_PASCAL = 0x2,
    CC_MACPASCAL = 0x3,
    CC_STDCALL = 0x4,
    CC_FPFASTCALL = 0x5,
    CC_SYSCALL = 0x6,
    CC_MPWCDECL = 0x7,
    CC_MPWPASCAL = 0x8,
    CC_MAX = 0x9
}CALLCONV, * PCALLCONV;

typedef enum _NT_PRODUCT_TYPE // int32_t
{
    NtProductWinNt = 0x1,
    NtProductLanManNt = 0x2,
    NtProductServer = 0x3
}NT_PRODUCT_TYPE, * PNT_PRODUCT_TYPE;

typedef enum _OS_PRODUCT_TYPE // uint32_t
{
    PRODUCT_BUSINESS = 0x6,
    PRODUCT_BUSINESS_N = 0x10,
    PRODUCT_CLUSTER_SERVER = 0x12,
    PRODUCT_CLUSTER_SERVER_V = 0x40,
    PRODUCT_CORE = 0x65,
    PRODUCT_CORE_COUNTRYSPECIFIC = 0x63,
    PRODUCT_CORE_N = 0x62,
    PRODUCT_CORE_SINGLELANGUAGE = 0x64,
    PRODUCT_DATACENTER_EVALUATION_SERVER = 0x50,
    PRODUCT_DATACENTER_A_SERVER_CORE = 0x91,
    PRODUCT_STANDARD_A_SERVER_CORE = 0x92,
    PRODUCT_DATACENTER_SERVER = 0x8,
    PRODUCT_DATACENTER_SERVER_CORE = 0xc,
    PRODUCT_DATACENTER_SERVER_CORE_V = 0x27,
    PRODUCT_DATACENTER_SERVER_V = 0x25,
    PRODUCT_EDUCATION = 0x79,
    PRODUCT_EDUCATION_N = 0x7a,
    PRODUCT_ENTERPRISE = 0x4,
    PRODUCT_ENTERPRISE_E = 0x46,
    PRODUCT_ENTERPRISE_EVALUATION = 0x48,
    PRODUCT_ENTERPRISE_N = 0x1b,
    PRODUCT_ENTERPRISE_N_EVALUATION = 0x54,
    PRODUCT_ENTERPRISE_S = 0x7d,
    PRODUCT_ENTERPRISE_S_EVALUATION = 0x81,
    PRODUCT_ENTERPRISE_S_N = 0x7e,
    PRODUCT_ENTERPRISE_S_N_EVALUATION = 0x82,
    PRODUCT_ENTERPRISE_SERVER = 0xa,
    PRODUCT_ENTERPRISE_SERVER_CORE = 0xe,
    PRODUCT_ENTERPRISE_SERVER_CORE_V = 0x29,
    PRODUCT_ENTERPRISE_SERVER_IA64 = 0xf,
    PRODUCT_ENTERPRISE_SERVER_V = 0x26,
    PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL = 0x3c,
    PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC = 0x3e,
    PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT = 0x3b,
    PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC = 0x3d,
    PRODUCT_HOME_BASIC = 0x2,
    PRODUCT_HOME_BASIC_E = 0x43,
    PRODUCT_HOME_BASIC_N = 0x5,
    PRODUCT_HOME_PREMIUM = 0x3,
    PRODUCT_HOME_PREMIUM_E = 0x44,
    PRODUCT_HOME_PREMIUM_N = 0x1a,
    PRODUCT_HOME_PREMIUM_SERVER = 0x22,
    PRODUCT_HOME_SERVER = 0x13,
    PRODUCT_HYPERV = 0x2a,
    PRODUCT_IOTUAP = 0x7b,
    PRODUCT_IOTUAPCOMMERCIAL = 0x83,
    PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT = 0x1e,
    PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING = 0x20,
    PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY = 0x1f,
    PRODUCT_MOBILE_CORE = 0x68,
    PRODUCT_MOBILE_ENTERPRISE = 0x85,
    PRODUCT_MULTIPOINT_PREMIUM_SERVER = 0x4d,
    PRODUCT_MULTIPOINT_STANDARD_SERVER = 0x4c,
    PRODUCT_PRO_WORKSTATION = 0xa1,
    PRODUCT_PRO_WORKSTATION_N = 0xa2,
    PRODUCT_PROFESSIONAL = 0x30,
    PRODUCT_PROFESSIONAL_E = 0x45,
    PRODUCT_PROFESSIONAL_N = 0x31,
    PRODUCT_PROFESSIONAL_WMC = 0x67,
    PRODUCT_SB_SOLUTION_SERVER = 0x32,
    PRODUCT_SB_SOLUTION_SERVER_EM = 0x36,
    PRODUCT_SERVER_FOR_SB_SOLUTIONS = 0x33,
    PRODUCT_SERVER_FOR_SB_SOLUTIONS_EM = 0x37,
    PRODUCT_SERVER_FOR_SMALLBUSINESS = 0x18,
    PRODUCT_SERVER_FOR_SMALLBUSINESS_V = 0x23,
    PRODUCT_SERVER_FOUNDATION = 0x21,
    PRODUCT_SMALLBUSINESS_SERVER = 0x9,
    PRODUCT_SMALLBUSINESS_SERVER_PREMIUM = 0x19,
    PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE = 0x3f,
    PRODUCT_SOLUTION_EMBEDDEDSERVER = 0x38,
    PRODUCT_STANDARD_EVALUATION_SERVER = 0x4f,
    PRODUCT_STANDARD_SERVER = 0x7,
    PRODUCT_STANDARD_SERVER_CORE_ = 0xd,
    PRODUCT_STANDARD_SERVER_CORE_V = 0x28,
    PRODUCT_STANDARD_SERVER_V = 0x24,
    PRODUCT_STANDARD_SERVER_SOLUTIONS = 0x34,
    PRODUCT_STANDARD_SERVER_SOLUTIONS_CORE = 0x35,
    PRODUCT_STARTER = 0xb,
    PRODUCT_STARTER_E = 0x42,
    PRODUCT_STARTER_N = 0x2f,
    PRODUCT_STORAGE_ENTERPRISE_SERVER = 0x17,
    PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE = 0x2e,
    PRODUCT_STORAGE_EXPRESS_SERVER = 0x14,
    PRODUCT_STORAGE_EXPRESS_SERVER_CORE = 0x2b,
    PRODUCT_STORAGE_STANDARD_EVALUATION_SERVER = 0x60,
    PRODUCT_STORAGE_STANDARD_SERVER = 0x15,
    PRODUCT_STORAGE_STANDARD_SERVER_CORE = 0x2c,
    PRODUCT_STORAGE_WORKGROUP_EVALUATION_SERVER = 0x5f,
    PRODUCT_STORAGE_WORKGROUP_SERVER = 0x16,
    PRODUCT_STORAGE_WORKGROUP_SERVER_CORE = 0x2d,
    PRODUCT_ULTIMATE = 0x1,
    PRODUCT_ULTIMATE_E = 0x47,
    PRODUCT_ULTIMATE_N = 0x1c,
    PRODUCT_UNDEFINED = 0x0,
    PRODUCT_WEB_SERVER = 0x11,
    PRODUCT_WEB_SERVER_CORE = 0x1d
}OS_PRODUCT_TYPE, * POS_PRODUCT_TYPE;

typedef enum _SUBSYSTEM_INFORMATION_TYPE// int32_t
{
    SubsystemInformationTypeWin32 = 0x0,
    SubsystemInformationTypeWSL = 0x1,
    MaxSubsystemInformationType = 0x2
}SUBSYSTEM_INFORMATION_TYPE, * PSUBSYSTEM_INFORMATION_TYPE;

typedef enum _SUITE_TYPE //int32_t
{
    SmallBusiness = 0x0,
    Enterprise = 0x1,
    BackOffice = 0x2,
    CommunicationServer = 0x3,
    TerminalServer = 0x4,
    SmallBusinessRestricted = 0x5,
    EmbeddedNT = 0x6,
    DataCenter = 0x7,
    SingleUserTS = 0x8,
    Personal = 0x9,
    Blade = 0xa,
    EmbeddedRestricted = 0xb,
    SecurityAppliance = 0xc,
    StorageServer = 0xd,
    ComputeServer = 0xe,
    WHServer = 0xf,
    PhoneNT = 0x10,
    MultiUserTS = 0x11,
    MaxSuiteType = 0x12
}SUITE_TYPE, * PSUITE_TYPE;

typedef enum _CREDUIWIN_FLAGS // uint32_t
{
    CREDUIWIN_GENERIC = 0x1,
    CREDUIWIN_CHECKBOX = 0x2,
    CREDUIWIN_AUTHPACKAGE_ONLY = 0x10,
    CREDUIWIN_IN_CRED_ONLY = 0x20,
    CREDUIWIN_ENUMERATE_ADMINS = 0x100,
    CREDUIWIN_ENUMERATE_CURRENT_USER = 0x200,
    CREDUIWIN_SECURE_PROMPT = 0x1000,
    CREDUIWIN_PREPROMPTING = 0x2000,
    CREDUIWIN_PACK_32_WOW = 0x10000000
}CREDUIWIN_FLAGS, * PCREDUIWIN_FLAGS;

typedef struct _CREDUI_INFOW
{
    DWORD cbSize;
    HWND hwndParent;
    PWSTR pszMessageText;
    PWSTR pszCaptionText;
    HBITMAP hbmBanner;
}CREDUI_INFOW, * PCREDUI_INFOW;

typedef enum _CRED_PACK_FLAGS //uint32_t
{
    CRED_PACK_PROTECTED_CREDENTIALS = 0x1,
    CRED_PACK_WOW_BUFFER = 0x2,
    CRED_PACK_GENERIC_CREDENTIALS = 0x4,
    CRED_PACK_ID_PROVIDER_CREDENTIALS = 0x8
}CRED_PACK_FLAGS, * PCRED_PACK_FLAGS;

typedef enum _APTTYPE // uint32_t
{
    APTTYPE_CURRENT = 0xffffffff,
    APTTYPE_STA = 0x0,
    APTTYPE_MTA = 0x1,
    APTTYPE_NA = 0x2,
    APTTYPE_MAINSTA = 0x3
}APTTYPE, * PAPTTYPE;

typedef enum _APTTYPEQUALIFIER // uint32_t
{
    APTTYPEQUALIFIER_NONE = 0x0,
    APTTYPEQUALIFIER_IMPLICIT_MTA = 0x1,
    APTTYPEQUALIFIER_NA_ON_MTA = 0x2,
    APTTYPEQUALIFIER_NA_ON_STA = 0x3,
    APTTYPEQUALIFIER_NA_ON_IMPLICIT_MTA = 0x4,
    APTTYPEQUALIFIER_NA_ON_MAINSTA = 0x5,
    APTTYPEQUALIFIER_APPLICATION_STA = 0x6,
    APTTYPEQUALIFIER_RESERVED_1 = 0x7
}APTTYPEQUALIFIER, * PAPTTYPEQUALIFIER;

typedef enum _ASSOCKEY // uint32_t
{
    ASSOCKEY_SHELLEXECCLASS = 0x1,
    ASSOCKEY_APP = 0x2,
    ASSOCKEY_CLASS = 0x3,
    ASSOCKEY_BASECLASS = 0x4,
    ASSOCKEY_MAX = 0x5
}ASSOCKEY, * PASSOCKEY;

typedef enum _ASSOCSTR // uint32_t
{
    ASSOCSTR_COMMAND = 0x1,
    ASSOCSTR_EXECUTABLE = 0x2,
    ASSOCSTR_FRIENDLYDOCNAME = 0x3,
    ASSOCSTR_FRIENDLYAPPNAME = 0x4,
    ASSOCSTR_NOOPEN = 0x5,
    ASSOCSTR_SHELLNEWVALUE = 0x6,
    ASSOCSTR_DDECOMMAND = 0x7,
    ASSOCSTR_DDEIFEXEC = 0x8,
    ASSOCSTR_DDEAPPLICATION = 0x9,
    ASSOCSTR_DDETOPIC = 0xa,
    ASSOCSTR_INFOTIP = 0xb,
    ASSOCSTR_QUICKTIP = 0xc,
    ASSOCSTR_TILEINFO = 0xd,
    ASSOCSTR_CONTENTTYPE = 0xe,
    ASSOCSTR_DEFAULTICON = 0xf,
    ASSOCSTR_SHELLEXTENSION = 0x10,
    ASSOCSTR_DROPTARGET = 0x11,
    ASSOCSTR_DELEGATEEXECUTE = 0x12,
    ASSOCSTR_SUPPORTED_URI_PROTOCOLS = 0x13,
    ASSOCSTR_PROGID = 0x14,
    ASSOCSTR_APPID = 0x15,
    ASSOCSTR_APPPUBLISHER = 0x16,
    ASSOCSTR_APPICONREFERENCE = 0x17,
    ASSOCSTR_MAX = 0x18
}ASSOCSTR, * PASSOCSTR;

typedef enum __ATTACH_VIRTUAL_DISK_FLAG // uint32_t
{
    ATTACH_VIRTUAL_DISK_FLAG_NONE = 0x0,
    ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY = 0x1,
    ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER = 0x2,
    ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME = 0x4,
    ATTACH_VIRTUAL_DISK_FLAG_NO_LOCAL_HOST = 0x8,
    ATTACH_VIRTUAL_DISK_FLAG_NO_SECURITY_DESCRIPTOR = 0x10,
    ATTACH_VIRTUAL_DISK_FLAG_BYPASS_DEFAULT_ENCRYPTION_POLICY = 0x20,
    ATTACH_VIRTUAL_DISK_FLAG_NON_PNP = 0x40,
    ATTACH_VIRTUAL_DISK_FLAG_RESTRICTED_RANGE = 0x80,
    ATTACH_VIRTUAL_DISK_FLAG_SINGLE_PARTITION = 0x100,
    ATTACH_VIRTUAL_DISK_FLAG_REGISTER_VOLUME = 0x200
}ATTACH_VIRTUAL_DISK_FLAG, * PATTACH_VIRTUAL_DISK_FLAG;

typedef enum _DETACH_VIRTUAL_DISK_FLAG // uint32_t
{
    DETACH_VIRTUAL_DISK_FLAG_NONE = 0x0
}DETACH_VIRTUAL_DISK_FLAG, * PDETACH_VIRTUAL_DISK_FLAG;

typedef enum _DEFINE_DOS_DEVICE_FLAGS// uint32_t
{
    DDD_RAW_TARGET_PATH = 0x1,
    DDD_REMOVE_DEFINITION = 0x2,
    DDD_EXACT_MATCH_ON_REMOVE = 0x4,
    DDD_NO_BROADCAST_SYSTEM = 0x8,
    DDD_LUID_BROADCAST_DRIVE = 0x10
}DEFINE_DOS_DEVICE_FLAGS, * PDEFINE_DOS_DEVICE_FLAGS;

typedef enum _DEPENDENT_DISK_FLAG // uint32_t
{
    DEPENDENT_DISK_FLAG_NONE = 0x0,
    DEPENDENT_DISK_FLAG_MULT_BACKING_FILES = 0x1,
    DEPENDENT_DISK_FLAG_FULLY_ALLOCATED = 0x2,
    DEPENDENT_DISK_FLAG_READ_ONLY = 0x4,
    DEPENDENT_DISK_FLAG_REMOTE = 0x8,
    DEPENDENT_DISK_FLAG_SYSTEM_VOLUME = 0x10,
    DEPENDENT_DISK_FLAG_SYSTEM_VOLUME_PARENT = 0x20,
    DEPENDENT_DISK_FLAG_REMOVABLE = 0x40,
    DEPENDENT_DISK_FLAG_NO_DRIVE_LETTER = 0x80,
    DEPENDENT_DISK_FLAG_PARENT = 0x100,
    DEPENDENT_DISK_FLAG_NO_HOST_DISK = 0x200,
    DEPENDENT_DISK_FLAG_PERMANENT_LIFETIME = 0x400,
    DEPENDENT_DISK_FLAG_SUPPORT_COMPRESSED_VOLUMES = 0x800,
    DEPENDENT_DISK_FLAG_ALWAYS_ALLOW_SPARSE = 0x1000,
    DEPENDENT_DISK_FLAG_SUPPORT_ENCRYPTED_FILES = 0x2000
}DEPENDENT_DISK_FLAG, * PDEPENDENT_DISK_FLAG;

typedef enum _DEVICEFAMILYDEVICEFORM // uint32_t
{
    DEVICEFAMILYDEVICEFORM_UNKNOWN = 0x0,
    DEVICEFAMILYDEVICEFORM_PHONE = 0x1,
    DEVICEFAMILYDEVICEFORM_TABLET = 0x2,
    DEVICEFAMILYDEVICEFORM_DESKTOP = 0x3,
    DEVICEFAMILYDEVICEFORM_NOTEBOOK = 0x4,
    DEVICEFAMILYDEVICEFORM_CONVERTIBLE = 0x5,
    DEVICEFAMILYDEVICEFORM_DETACHABLE = 0x6,
    DEVICEFAMILYDEVICEFORM_ALLINONE = 0x7,
    DEVICEFAMILYDEVICEFORM_STICKPC = 0x8,
    DEVICEFAMILYDEVICEFORM_PUCK = 0x9,
    DEVICEFAMILYDEVICEFORM_LARGESCREEN = 0xa,
    DEVICEFAMILYDEVICEFORM_HMD = 0xb,
    DEVICEFAMILYDEVICEFORM_INDUSTRY_HANDHELD = 0xc,
    DEVICEFAMILYDEVICEFORM_INDUSTRY_TABLET = 0xd,
    DEVICEFAMILYDEVICEFORM_BANKING = 0xe,
    DEVICEFAMILYDEVICEFORM_BUILDING_AUTOMATION = 0xf,
    DEVICEFAMILYDEVICEFORM_DIGITAL_SIGNAGE = 0x10,
    DEVICEFAMILYDEVICEFORM_GAMING = 0x11,
    DEVICEFAMILYDEVICEFORM_HOME_AUTOMATION = 0x12,
    DEVICEFAMILYDEVICEFORM_INDUSTRIAL_AUTOMATION = 0x13,
    DEVICEFAMILYDEVICEFORM_KIOSK = 0x14,
    DEVICEFAMILYDEVICEFORM_MAKER_BOARD = 0x15,
    DEVICEFAMILYDEVICEFORM_MEDICAL = 0x16,
    DEVICEFAMILYDEVICEFORM_NETWORKING = 0x17,
    DEVICEFAMILYDEVICEFORM_POINT_OF_SERVICE = 0x18,
    DEVICEFAMILYDEVICEFORM_PRINTING = 0x19,
    DEVICEFAMILYDEVICEFORM_THIN_CLIENT = 0x1a,
    DEVICEFAMILYDEVICEFORM_TOY = 0x1b,
    DEVICEFAMILYDEVICEFORM_VENDING = 0x1c,
    DEVICEFAMILYDEVICEFORM_INDUSTRY_OTHER = 0x1d,
    DEVICEFAMILYDEVICEFORM_XBOX_ONE = 0x1e,
    DEVICEFAMILYDEVICEFORM_XBOX_ONE_S = 0x1f,
    DEVICEFAMILYDEVICEFORM_XBOX_ONE_X = 0x20,
    DEVICEFAMILYDEVICEFORM_XBOX_ONE_X_DEVKIT = 0x21,
    DEVICEFAMILYDEVICEFORM_XBOX_SERIES_X = 0x22,
    DEVICEFAMILYDEVICEFORM_XBOX_SERIES_X_DEVKIT = 0x23,
    DEVICEFAMILYDEVICEFORM_XBOX_RESERVED_00 = 0x24,
    DEVICEFAMILYDEVICEFORM_XBOX_RESERVED_01 = 0x25,
    DEVICEFAMILYDEVICEFORM_XBOX_RESERVED_02 = 0x26,
    DEVICEFAMILYDEVICEFORM_XBOX_RESERVED_03 = 0x27,
    DEVICEFAMILYDEVICEFORM_XBOX_RESERVED_04 = 0x28,
    DEVICEFAMILYDEVICEFORM_XBOX_RESERVED_05 = 0x29,
    DEVICEFAMILYDEVICEFORM_XBOX_RESERVED_06 = 0x2a,
    DEVICEFAMILYDEVICEFORM_XBOX_RESERVED_07 = 0x2b,
    DEVICEFAMILYDEVICEFORM_XBOX_RESERVED_08 = 0x2c,
    DEVICEFAMILYDEVICEFORM_XBOX_RESERVED_09 = 0x2d,
    DEVICEFAMILYDEVICEFORM_MAX = 0x2d
}DEVICEFAMILYDEVICEFORM, * PDEVICEFAMILYDEVICEFORM;

typedef enum _DEVICEFAMILYINFOENUM // uint32_t
{
    DEVICEFAMILYINFOENUM_UAP = 0x0,
    DEVICEFAMILYINFOENUM_WINDOWS_8X = 0x1,
    DEVICEFAMILYINFOENUM_WINDOWS_PHONE_8X = 0x2,
    DEVICEFAMILYINFOENUM_DESKTOP = 0x3,
    DEVICEFAMILYINFOENUM_MOBILE = 0x4,
    DEVICEFAMILYINFOENUM_XBOX = 0x5,
    DEVICEFAMILYINFOENUM_TEAM = 0x6,
    DEVICEFAMILYINFOENUM_IOT = 0x7,
    DEVICEFAMILYINFOENUM_IOT_HEADLESS = 0x8,
    DEVICEFAMILYINFOENUM_SERVER = 0x9,
    DEVICEFAMILYINFOENUM_HOLOGRAPHIC = 0xa,
    DEVICEFAMILYINFOENUM_XBOXSRA = 0xb,
    DEVICEFAMILYINFOENUM_XBOXERA = 0xc,
    DEVICEFAMILYINFOENUM_SERVER_NANO = 0xd,
    DEVICEFAMILYINFOENUM_8828080 = 0xe,
    DEVICEFAMILYINFOENUM_7067329 = 0xf,
    DEVICEFAMILYINFOENUM_WINDOWS_CORE = 0x10,
    DEVICEFAMILYINFOENUM_WINDOWS_CORE_HEADLESS = 0x11,
    DEVICEFAMILYINFOENUM_MAX = 0x11
}DEVICEFAMILYINFOENUM, * PDEVICEFAMILYINFOENUM;

typedef struct _DEVPROPKEY
{
    GUID fmtid;
    DWORD pid;
}DEVPROPKEY, * PDEVPROPKEY;

typedef enum _DEVPROPSTORE // uint32_t
{
    DEVPROP_STORE_SYSTEM = 0x0,
    DEVPROP_STORE_USER = 0x1
}DEVPROPSTORE, * PDEVPROPSTORE;

typedef struct _DEVPROPCOMPKEY
{
    DEVPROPKEY Key;
    DEVPROPSTORE Store;
    PWSTR LocaleName;
}DEVPROPCOMPKEY, * PDEVPROPCOMPKEY;

typedef struct _DEVPROPERTY
{
    DEVPROPCOMPKEY CompKey;
    DWORD Type;
    DWORD BufferSize;
    PVOID Buffer;
}DEVPROPERTY, * PDEVPROPERTY;

typedef enum _DEVPROP_OPERATOR // uint32_t
{
    DEVPROP_OPERATOR_MODIFIER_NOT = 0x10000,
    DEVPROP_OPERATOR_MODIFIER_IGNORE_CASE = 0x20000,
    DEVPROP_OPERATOR_NONE = 0x0,
    DEVPROP_OPERATOR_EXISTS = 0x1,
    DEVPROP_OPERATOR_NOT_EXISTS = 0x10001,
    DEVPROP_OPERATOR_EQUALS = 0x2,
    DEVPROP_OPERATOR_NOT_EQUALS = 0x10002,
    DEVPROP_OPERATOR_GREATER_THAN = 0x3,
    DEVPROP_OPERATOR_LESS_THAN = 0x4,
    DEVPROP_OPERATOR_GREATER_THAN_EQUALS = 0x5,
    DEVPROP_OPERATOR_LESS_THAN_EQUALS = 0x6,
    DEVPROP_OPERATOR_EQUALS_IGNORE_CASE = 0x20002,
    DEVPROP_OPERATOR_NOT_EQUALS_IGNORE_CASE = 0x30002,
    DEVPROP_OPERATOR_BITWISE_AND = 0x7,
    DEVPROP_OPERATOR_BITWISE_OR = 0x8,
    DEVPROP_OPERATOR_BEGINS_WITH = 0x9,
    DEVPROP_OPERATOR_ENDS_WITH = 0xa,
    DEVPROP_OPERATOR_CONTAINS = 0xb,
    DEVPROP_OPERATOR_BEGINS_WITH_IGNORE_CASE = 0x20009,
    DEVPROP_OPERATOR_ENDS_WITH_IGNORE_CASE = 0x2000a,
    DEVPROP_OPERATOR_CONTAINS_IGNORE_CASE = 0x2000b,
    DEVPROP_OPERATOR_LIST_CONTAINS = 0x1000,
    DEVPROP_OPERATOR_LIST_ELEMENT_BEGINS_WITH = 0x2000,
    DEVPROP_OPERATOR_LIST_ELEMENT_ENDS_WITH = 0x3000,
    DEVPROP_OPERATOR_LIST_ELEMENT_CONTAINS = 0x4000,
    DEVPROP_OPERATOR_LIST_CONTAINS_IGNORE_CASE = 0x21000,
    DEVPROP_OPERATOR_LIST_ELEMENT_BEGINS_WITH_IGNORE_CASE = 0x22000,
    DEVPROP_OPERATOR_LIST_ELEMENT_ENDS_WITH_IGNORE_CASE = 0x23000,
    DEVPROP_OPERATOR_LIST_ELEMENT_CONTAINS_IGNORE_CASE = 0x24000,
    DEVPROP_OPERATOR_AND_OPEN = 0x100000,
    DEVPROP_OPERATOR_AND_CLOSE = 0x200000,
    DEVPROP_OPERATOR_OR_OPEN = 0x300000,
    DEVPROP_OPERATOR_OR_CLOSE = 0x400000,
    DEVPROP_OPERATOR_NOT_OPEN = 0x500000,
    DEVPROP_OPERATOR_NOT_CLOSE = 0x600000,
    DEVPROP_OPERATOR_ARRAY_CONTAINS = 0x10000000,
    DEVPROP_OPERATOR_MASK_EVAL = 0xfff,
    DEVPROP_OPERATOR_MASK_LIST = 0xf000,
    DEVPROP_OPERATOR_MASK_MODIFIER = 0xf0000,
    DEVPROP_OPERATOR_MASK_NOT_LOGICAL = 0xf00fffff,
    DEVPROP_OPERATOR_MASK_LOGICAL = 0xff00000,
    DEVPROP_OPERATOR_MASK_ARRAY = 0xf0000000
}DEVPROP_OPERATOR, * PDEVPROP_OPERATOR;

typedef struct _DEVPROP_FILTER_EXPRESSION
{
    DEVPROP_OPERATOR Operator;
    DEVPROPERTY Property;
}DEVPROP_FILTER_EXPRESSION, * PDEVPROP_FILTER_EXPRESSION;

typedef enum _DEV_OBJECT_TYPE //uint32_t
{
    DevObjectTypeUnknown = 0x0,
    DevObjectTypeDeviceInterface = 0x1,
    DevObjectTypeDeviceContainer = 0x2,
    DevObjectTypeDevice = 0x3,
    DevObjectTypeDeviceInterfaceClass = 0x4,
    DevObjectTypeAEP = 0x5,
    DevObjectTypeAEPContainer = 0x6,
    DevObjectTypeDeviceInstallerClass = 0x7,
    DevObjectTypeDeviceInterfaceDisplay = 0x8,
    DevObjectTypeDeviceContainerDisplay = 0x9,
    DevObjectTypeAEPService = 0xa,
    DevObjectTypeDevicePanel = 0xb
}DEV_OBJECT_TYPE, * PDEV_OBJECT_TYPE;

typedef struct _DEV_OBJECT
{
    DEV_OBJECT_TYPE ObjectType;
    PWSTR pszObjectId;
    DWORD cPropertyCount;
    DEVPROPERTY* pProperties;
}DEV_OBJECT, * PDEV_OBJECT;

typedef enum _DEV_QUERY_RESULT_ACTION // uint32_t
{
    DevQueryResultStateChange = 0x0,
    DevQueryResultAdd = 0x1,
    DevQueryResultUpdate = 0x2,
    DevQueryResultRemove = 0x3
}DEV_QUERY_RESULT_ACTION, * PDEV_QUERY_RESULT_ACTION;

typedef enum _DEV_QUERY_STATE // uint32_t
{
    DevQueryStateInitialized = 0x0,
    DevQueryStateEnumCompleted = 0x1,
    DevQueryStateAborted = 0x2,
    DevQueryStateClosed = 0x3
}DEV_QUERY_STATE, * PDEV_QUERY_STATE;

typedef union _DEV_QUERY_RESULT_UPDATE_PAYLOAD
{
    DEV_QUERY_STATE State;
    DEV_OBJECT DeviceObject;
}DEV_QUERY_RESULT_UPDATE_PAYLOAD, * PDEV_QUERY_RESULT_UPDATE_PAYLOAD;

typedef struct _DEV_QUERY_RESULT_ACTION_DATA
{
    DEV_QUERY_RESULT_ACTION Action;
    DEV_QUERY_RESULT_UPDATE_PAYLOAD Data;
}DEV_QUERY_RESULT_ACTION_DATA, * PDEV_QUERY_RESULT_ACTION_DATA;

typedef struct __Version1_e__Struct
{
    PWSTR ForkedVirtualDiskPath;
}_Version1_e__Struct, * P_Version1_e__Struct;

typedef struct __Version2_e__Struct
{
    DWORD MergeSourceDepth;
    DWORD MergeTargetDepth;
}_Version2_e__Struct, * P_Version2_e__Struct;

typedef struct _ATTACH_VIRTUAL_DISK_PARAMETERS
{
    enum ATTACH_VIRTUAL_DISK_VERSION Version;
    union
    {
        _Version1_e__Struct Version1;
        _Version2_e__Struct Version2;
    };
}ATTACH_VIRTUAL_DISK_PARAMETERS, * PATTACH_VIRTUAL_DISK_PARAMETERS;

typedef enum _ATTACH_VIRTUAL_DISK_VERSION // uint32_t
{
    ATTACH_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0x0,
    ATTACH_VIRTUAL_DISK_VERSION_1 = 0x1,
    ATTACH_VIRTUAL_DISK_VERSION_2 = 0x2
}ATTACH_VIRTUAL_DISK_VERSION, * PATTACH_VIRTUAL_DISK_VERSION;

typedef enum _BACKGROUND_MODE // uint32_t
{
    OPAQUE = 0x2,
    TRANSPARENT = 0x1
}BACKGROUND_MODE, * PBACKGROUND_MODE;

typedef struct _RTL_USER_PROCESS_EXTENDED_PARAMETERS
{
    USHORT Version;
    USHORT NodeNumber;
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor;
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor;
    HANDLE ParentProcess;
    HANDLE DebugPort;
    HANDLE TokenHandle;
    HANDLE JobHandle;
} RTL_USER_PROCESS_EXTENDED_PARAMETERS, * PRTL_USER_PROCESS_EXTENDED_PARAMETERS;

typedef struct _SECTION_IMAGE_INFORMATION
{
    PVOID TransferAddress;
    ULONG ZeroBits;
    SIZE_T MaximumStackSize;
    SIZE_T CommittedStackSize;
    ULONG SubSystemType;
    union
    {
        struct
        {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    ULONG GpValue;
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    union
    {
        UCHAR ImageFlags;
        struct
        {
            UCHAR ComPlusNativeReady : 1;
            UCHAR ComPlusILOnly : 1;
            UCHAR ImageDynamicallyRelocated : 1;
            UCHAR ImageMappedFlat : 1;
            UCHAR BaseBelow4gb;
            UCHAR ComPlusPrefer32bit;
            UCHAR Reserved;
        };
    }__inner11;
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

typedef struct _SECTION_IMAGE_INFORMATION32
{
    DWORD TransferAddress;
    DWORD ZeroBits;
    DWORD MaximumStackSize;
    DWORD CommittedStackSize;
    DWORD SubSystemType;
    union
    {
        struct
        {
            WORD SubSystemMinorVersion;
            WORD SubSystemMajorVersion;
        } __inner0;
        DWORD SubSystemVersion;
    } __inner5;
    union
    {
        struct
        {
            WORD MajorOperatingSystemVersion;
            WORD MinorOperatingSystemVersion;
        } __inner0;
        DWORD OperatingSystemVersion;
    } __inner6;
    WORD ImageCharacteristics;
    WORD DllCharacteristics;
    WORD Machine;
    UCHAR ImageContainsCode;
    union
    {
        UCHAR ImageFlags;
        union
        {
            UCHAR ComPlus;
            UCHAR ImageDynamicallyRelocated;
            UCHAR Reserved;
        } __bitfield35;
    } __inner11;
    DWORD LoaderFlags;
    DWORD ImageFileSize;
    DWORD CheckSum;
}SECTION_IMAGE_INFORMATION32, * PSECTION_IMAGE_INFORMATION32;

typedef struct _SECTION_IMAGE_INFORMATION64
{
    QWORD TransferAddress;
    DWORD ZeroBits;
    QWORD MaximumStackSize;
    QWORD CommittedStackSize;
    DWORD SubSystemType;
    union
    {
        struct
        {
            WORD SubSystemMinorVersion;
            WORD SubSystemMajorVersion;
        } __inner0;
        DWORD SubSystemVersion;
    } __inner5;
    union
    {
        struct
        {
            WORD MajorOperatingSystemVersion;
            WORD MinorOperatingSystemVersion;
        } __inner0;
        DWORD OperatingSystemVersion;
    } __inner6;
    WORD ImageCharacteristics;
    WORD DllCharacteristics;
    WORD Machine;
    UCHAR ImageContainsCode;
    union
    {
        UCHAR ImageFlags;
        union
        {
            UCHAR ComPlus;
            UCHAR ImageDynamicallyRelocated;
            UCHAR Reserved;
        } __bitfield51;
    } __inner11;
    DWORD LoaderFlags;
    DWORD ImageFileSize;
    DWORD CheckSum;
}SECTION_IMAGE_INFORMATION64, * PSECTION_IMAGE_INFORMATION64;

enum _SECTION_INFORMATION_CLASS // int32_t
{
    SectionBasicInformation = 0x0,
    SectionImageInformation = 0x1,
    SectionRelocationInformation = 0x2,
    SectionOriginalBaseInformation = 0x3,
    SectionInternalImageInformation = 0x4,
    MaxSectionInfoClass = 0x5
};

typedef enum _SECTION_INHERIT// int32_t
{
    ViewShare = 0x1,
    ViewUnmap = 0x2
}SECTION_INHERIT, * PSECTION_INHERIT;

typedef struct _SECTION_INTERNAL_IMAGE_INFORMATION
{
    SECTION_IMAGE_INFORMATION SectionInformation;
    union
    {
        DWORD ExtendedFlags;
        union
        {
            DWORD ImageExportSuppressionEnabled;
            DWORD ImageCetShadowStacksReady;
            DWORD ImageXfgEnabled;
            DWORD ImageCetShadowStacksStrictMode;
            DWORD ImageCetSetContextIpValidationRelaxedMode;
            DWORD ImageCetDynamicApisAllowInProc;
            DWORD ImageCetDowngradeReserved1;
            DWORD ImageCetDowngradeReserved2;
            DWORD Reserved;
        } __bitfield64;
    } __inner1;
}SECTION_INTERNAL_IMAGE_INFORMATION, * PSECTION_INTERNAL_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION
{
    ULONG Length;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;
//-------------------

typedef struct _PORT_MESSAGE
{
    union
    {
        struct
        {
            SHORT DataLength;
            SHORT TotalLength;
        } s1;
        DWORD Length;
    } u1;
    union
    {
        struct
        {
            SHORT Type;
            SHORT DataInfoOffset;
        } s2;
        DWORD ZeroInit;
    } u2;
    union
    {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    } __inner2;
    DWORD MessageId;

    union
    {
        QWORD ClientViewSize;
        DWORD CallbackId;
    } __inner4;
}PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _HARDERROR_MSG
{
    PORT_MESSAGE h;
    LONG Status;
    LARGE_INTEGER ErrorTime;
    DWORD ValidResponseOptions;
    DWORD Response;
    DWORD NumberOfParameters;
    DWORD UnicodeStringParameterMask;
    QWORD Parameters[0x5];
}HARDERROR_MSG, * PHARDERROR_MSG;

typedef enum _HARDERROR_RESPONSE // int32_t
{
    ResponseReturnToCaller = 0x0,
    ResponseNotHandled = 0x1,
    ResponseAbort = 0x2,
    ResponseCancel = 0x3,
    ResponseIgnore = 0x4,
    ResponseNo = 0x5,
    ResponseOk = 0x6,
    ResponseRetry = 0x7,
    ResponseYes = 0x8,
    ResponseTryAgain = 0x9,
    ResponseContinue = 0xa
}HARDERROR_RESPONSE, * PHARDERROR_RESPONSE;

typedef enum _HARDERROR_RESPONSE_OPTION // int32_t
{
    OptionAbortRetryIgnore = 0x0,
    OptionOk = 0x1,
    OptionOkCancel = 0x2,
    OptionRetryCancel = 0x3,
    OptionYesNo = 0x4,
    OptionYesNoCancel = 0x5,
    OptionShutdownSystem = 0x6,
    OptionOkNoWait = 0x7,
    OptionCancelTryContinue = 0x8
}HARDERROR_RESPONSE_OPTION, * PHARDERROR_RESPONSE_OPTION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,                 // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation,             // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation,           // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation,             // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation,                  // not implemented
    SystemProcessInformation,               // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation,             // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation,                // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation,  // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation,                 // q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation,              // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
    SystemModuleInformation,                // q: RTL_PROCESS_MODULES
    SystemLocksInformation,                 // q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation,            // q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation,             // not implemented
    SystemNonPagedPoolInformation,          // not implemented
    SystemHandleInformation,                // q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation,                // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation,              // q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation,           // q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation,                // not implemented // 20
    SystemFileCacheInformation,             // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation,               // q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation,             // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemDpcBehaviorInformation,           // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation,            // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemLoadGdiDriverInformation,         // s (kernel-mode only)
    SystemUnloadGdiDriverInformation,       // s (kernel-mode only)
    SystemTimeAdjustmentInformation,        // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation,         // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemMirrorMemoryInformation,          // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation,      // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0,                        // not implemented
    SystemExceptionInformation,             // q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation,        // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation,        // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation,         // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation,         // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation,    // s (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeperation,               // s (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation,     // s (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation,  // s (requires SeDebugPrivilege)
    SystemProcessorIdleInformation,         // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemLegacyDriverInformation,          // q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation,       // q; s: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation,             // q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification,             // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate,                    // not implemented
    SystemSessionDetach,                    // not implemented
    SystemSessionInformation,               // not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation,            // q: SYSTEM_RANGE_START_INFORMATION // 50
    SystemVerifierInformation,              // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend,              // s (kernel-mode only)
    SystemSessionProcessInformation,        // q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace,       // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap,                 // q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation,            // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation,       // q: SYSTEM_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment,   // q: ULONG // KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage,                   // q; s: ULONG
    SystemNumaAvailableMemory,              // q: SYSTEM_NUMA_INFORMATION // 60
    SystemProcessorPowerInformation,        // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemEmulationBasicInformation,        // q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation,    // q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation,        // q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation,      // q: ULONG
    SystemBigPoolInformation,               // q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation,        // q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation,     // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation,              // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode,               // q: ULONG // 70
    SystemWatchdogTimerHandler,             // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
    SystemWatchdogTimerInformation,         // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
    SystemLogicalProcessorInformation,      // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemWow64SharedInformationObsolete,   // not implemented
    SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
    SystemFirmwareTableInformation,         // SYSTEM_FIRMWARE_TABLE_INFORMATION
    SystemModuleInformationEx,              // q: RTL_PROCESS_MODULE_INFORMATION_EX
    SystemVerifierTriageInformation,        // not implemented
    SystemSuperfetchInformation,            // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation,            // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx,           // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
    SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx, // not implemented
    SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
    SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation, // s (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // 100
    SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
    SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
    SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
    SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber)
    SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
    SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation,
    SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
    SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation, // q; s: SYSTEM_CONSOLE_INFORMATION
    SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION
    SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
    SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // since WINBLUE
    SystemCriticalProcessErrorLogInformation,
    SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation,
    SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation, // 150
    SystemSoftRebootInformation, // q: ULONG
    SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // 160
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
    SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation,
    SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
    SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
    SystemInterruptSteeringInformation, // SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT // 180
    SystemSupportedProcessorArchitectures, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
    SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
    SystemControlFlowTransition,
    SystemKernelDebuggingAllowed, // s: ULONG
    SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation,
    SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
    SystemIntegrityQuotaInformation,
    SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
    SystemSecureDumpEncryptionInformation,
    SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
    SystemFirmwareBootPerformanceInformation,
    SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
    SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation,
    SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
    SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
    SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
    SystemCodeIntegritySyntheticCacheInformation,
    SystemFeatureConfigurationInformation, // SYSTEM_FEATURE_CONFIGURATION_INFORMATION // since 20H1 // 210
    SystemFeatureConfigurationSectionInformation, // SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
    SystemFeatureUsageSubscriptionInformation, // SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
    SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation, // since 20H2
    SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation,
    SystemDifSetRuleClassInformation,
    SystemDifClearRuleClassInformation,
    SystemDifApplyPluginVerificationOnDriver,
    SystemDifRemovePluginVerificationOnDriver, // 220
    SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation, // SYSTEM_BUILD_VERSION_INFORMATION
    SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION
    SystemCodeIntegrityAddDynamicStore,
    SystemCodeIntegrityClearDynamicStores,
    SystemDifPoolTrackingInformation,
    SystemPoolZeroingInformation, // SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation,
    SystemDpcWatchdogInformation2,
    SystemSupportedProcessorArchitectures2, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx  // 230
    SystemSingleProcessorRelationshipInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor)
    SystemXfgCheckFailureInformation,
    SystemIommuStateInformation, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
    SystemHypervisorMinrootInformation, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation, // SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation,
    SystemOriginalImageFeatureInformation,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

typedef enum _FIRMWARE_TYPE // int32_t
{
    FirmwareTypeUnknown = 0x0,
    FirmwareTypeBios = 0x1,
    FirmwareTypeUefi = 0x2,
    FirmwareTypeMax = 0x3
}FIRMWARE_TYPE, * PFIRMWARE_TYPE;

typedef struct _PROCESSOR_POWER_INFORMATION
{
    DWORD Number;
    DWORD MaxMhz;
    DWORD CurrentMhz;
    DWORD MhzLimit;
    DWORD MaxIdleState;
    DWORD CurrentIdleState;
}PROCESSOR_POWER_INFORMATION, * PPROCESSOR_POWER_INFORMATION;

typedef struct _SYSTEM_ACPI_AUDIT_INFORMATION
{
    DWORD RsdpCount;
    union
    {
        DWORD SameRsdt;
        DWORD SlicPresent;
        DWORD SlicDifferent;
    } __bitfield4;
}SYSTEM_ACPI_AUDIT_INFORMATION, * PSYSTEM_ACPI_AUDIT_INFORMATION;

typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION
{
    GUID BootIdentifier;
    FIRMWARE_TYPE FirmwareType;
    union
    {
        QWORD BootFlags;
        union
        {
            QWORD DbgMenuOsSelection;
            QWORD DbgHiberBoot;
            QWORD DbgSoftBoot;
            QWORD DbgMeasuredLaunch;
            QWORD DbgMeasuredLaunchCapable;
            QWORD DbgSystemHiveReplace;
            QWORD DbgMeasuredLaunchSmmProtections;
            QWORD DbgMeasuredLaunchSmmLevel;
        } __bitfield24;
    } __inner2;
}SYSTEM_BOOT_ENVIRONMENT_INFORMATION, * PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    KAFFINITY ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_CALL_COUNT_INFORMATION
{
    ULONG Length;
    ULONG NumberOfTables;
} SYSTEM_CALL_COUNT_INFORMATION, * PSYSTEM_CALL_COUNT_INFORMATION;

typedef struct _SYSTEM_DEVICE_INFORMATION
{
    ULONG NumberOfDisks;
    ULONG NumberOfFloppies;
    ULONG NumberOfCdRoms;
    ULONG NumberOfTapes;
    ULONG NumberOfSerialPorts;
    ULONG NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, * PSYSTEM_DEVICE_INFORMATION;

// private
typedef struct _SYSTEM_CALL_TIME_INFORMATION
{
    ULONG Length;
    ULONG TotalCalls;
    LARGE_INTEGER TimeOfCalls[1];
} SYSTEM_CALL_TIME_INFORMATION, * PSYSTEM_CALL_TIME_INFORMATION;

typedef struct _SYSTEM_FILECACHE_INFORMATION
{
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, * PSYSTEM_FILECACHE_INFORMATION;

// Can be used instead of SYSTEM_FILECACHE_INFORMATION
typedef struct _SYSTEM_BASIC_WORKING_SET_INFORMATION
{
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
} SYSTEM_BASIC_WORKING_SET_INFORMATION, * PSYSTEM_BASIC_WORKING_SET_INFORMATION;

typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION
{
    ULONG Spare;
    ULONG DpcQueueDepth;
    ULONG MinimumDpcRate;
    ULONG AdjustDpcThreshold;
    ULONG IdealDpcRate;
} SYSTEM_DPC_BEHAVIOR_INFORMATION, * PSYSTEM_DPC_BEHAVIOR_INFORMATION;

typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION
{
    ULONG TimeAdjustment;
    ULONG TimeIncrement;
    BOOLEAN Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION, * PSYSTEM_QUERY_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION_PRECISE
{
    ULONGLONG TimeAdjustment;
    ULONGLONG TimeIncrement;
    BOOLEAN Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION_PRECISE, * PSYSTEM_QUERY_TIME_ADJUST_INFORMATION_PRECISE;

typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION
{
    ULONG TimeAdjustment;
    BOOLEAN Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION, * PSYSTEM_SET_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION_PRECISE
{
    ULONGLONG TimeAdjustment;
    BOOLEAN Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION_PRECISE, * PSYSTEM_SET_TIME_ADJUST_INFORMATION_PRECISE;

typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP // int32_t
{
    RelationProcessorCore = 0x0,
    RelationNumaNode = 0x1,
    RelationCache = 0x2,
    RelationProcessorPackage = 0x3,
    RelationGroup = 0x4,
    RelationAll = 0xffff
}LOGICAL_PROCESSOR_RELATIONSHIP, * PLOGICAL_PROCESSOR_RELATIONSHIP;

typedef struct __ProcessorCore_e__Struct
{
    UCHAR Flags;
}_ProcessorCore_e__Struct, * P_ProcessorCore_e__Struct;

typedef struct __NumaNode_e__Struct
{
    DWORD NodeNumber;
}_NumaNode_e__Struct, * P_NumaNode_e__Struct;

typedef enum _PROCESSOR_CACHE_TYPE // int32_t
{
    CacheUnified = 0x0,
    CacheInstruction = 0x1,
    CacheData = 0x2,
    CacheTrace = 0x3
}PROCESSOR_CACHE_TYPE, * PPROCESSOR_CACHE_TYPE;

typedef struct _CACHE_DESCRIPTOR
{
    UCHAR Level;
    UCHAR Associativity;
    DWORD LineSize;
    DWORD Size;
    PROCESSOR_CACHE_TYPE Type;
}CACHE_DESCRIPTOR, * PCACHE_DESCRIPTOR;

typedef struct _PROCESSOR_RELATIONSHIP
{
    UCHAR Flags;
    UCHAR EfficiencyClass;
    UCHAR Reserved[0x14];
    WORD GroupCount;
    GROUP_AFFINITY GroupMask[0x1];
}PROCESSOR_RELATIONSHIP, * PPROCESSOR_RELATIONSHIP;

typedef struct _NUMA_NODE_RELATIONSHIP
{
    DWORD NodeNumber;
    UCHAR Reserved[0x12];
    WORD GroupCount;
    union
    {
        GROUP_AFFINITY GroupMask;
        GROUP_AFFINITY* GroupMasks;
    };
}NUMA_NODE_RELATIONSHIP, * PNUMA_NODE_RELATIONSHIP;

typedef struct _CACHE_RELATIONSHIP
{
    UCHAR Level;
    UCHAR Associativity;
    WORD LineSize;
    DWORD CacheSize;
    PROCESSOR_CACHE_TYPE Type;
    UCHAR Reserved[0x14];
    GROUP_AFFINITY GroupMask;
}CACHE_RELATIONSHIP, * PCACHE_RELATIONSHIP;

typedef struct _PROCESSOR_GROUP_INFO
{
    UCHAR MaximumProcessorCount;
    UCHAR ActiveProcessorCount;
    UCHAR Reserved[0x26];
    QWORD ActiveProcessorMask;
}PROCESSOR_GROUP_INFO, * PPROCESSOR_GROUP_INFO;

typedef struct _GROUP_RELATIONSHIP
{
    WORD MaximumGroupCount;
    WORD ActiveGroupCount;
    UCHAR Reserved[0x14];
    PROCESSOR_GROUP_INFO GroupInfo[0x1];
}GROUP_RELATIONSHIP, * PGROUP_RELATIONSHIP;

typedef struct _SYSTEM_POWER_CAPABILITIES
{
    UCHAR PowerButtonPresent;
    UCHAR SleepButtonPresent;
    UCHAR LidPresent;
    UCHAR SystemS1;
    UCHAR SystemS2;
    UCHAR SystemS3;
    UCHAR SystemS4;
    UCHAR SystemS5;
    UCHAR HiberFilePresent;
    UCHAR FullWake;
    UCHAR VideoDimPresent;
    UCHAR ApmPresent;
    UCHAR UpsPresent;
    UCHAR ThermalControl;
    UCHAR ProcessorThrottle;
    UCHAR ProcessorMinThrottle;
    UCHAR ProcessorMaxThrottle;
    UCHAR FastSystemS4;
    UCHAR Hiberboot;
    UCHAR WakeAlarmPresent;
    UCHAR AoAc;
    UCHAR DiskSpinDown;
    UCHAR HiberFileType;
    UCHAR AoAcConnectivitySupported;
    UCHAR spare3[0x6];
    UCHAR SystemBatteriesPresent;
    UCHAR BatteriesAreShortTerm;
    BATTERY_REPORTING_SCALE BatteryScale[0x3];
    SYSTEM_POWER_STATE AcOnLineWake;
    SYSTEM_POWER_STATE SoftLidWake;
    SYSTEM_POWER_STATE RtcWake;
    SYSTEM_POWER_STATE MinDeviceWakeState;
    SYSTEM_POWER_STATE DefaultLowLatencyWake;
}SYSTEM_POWER_CAPABILITIES, * PSYSTEM_POWER_CAPABILITIES;

typedef struct _RTL_TIME_ZONE_INFORMATION
{
    LONG Bias;
    unsigned short StandardName[0x20];
    TIME_FIELDS StandardStart;
    LONG StandardBias;
    unsigned short DaylightName[0x20];
    TIME_FIELDS DaylightStart;
    LONG DaylightBias;
}RTL_TIME_ZONE_INFORMATION, * PRTL_TIME_ZONE_INFORMATION;

typedef struct _RTL_DYNAMIC_TIME_ZONE_INFORMATION
{
    RTL_TIME_ZONE_INFORMATION tzi;
    unsigned short TimeZoneKeyName[0x80];//wchar16
    UCHAR DynamicDaylightTimeDisabled;

}RTL_DYNAMIC_TIME_ZONE_INFORMATION, * PRTL_DYNAMIC_TIME_ZONE_INFORMATION;

typedef enum _RTL_FEATURE_CONFIGURATION_PRIORITY // int32_t
{
    FeatureConfigurationPriorityImageDefault = 0x0,
    FeatureConfigurationPriorityService = 0x4,
    FeatureConfigurationPriorityUser = 0x8,
    FeatureConfigurationPriorityUserPolicy = 0xa,
    FeatureConfigurationPriorityTest = 0xc,
    FeatureConfigurationPriorityImageOverride = 0xf,
    FeatureConfigurationPriorityMax = 0xf
}RTL_FEATURE_CONFIGURATION_PRIORITY, * PRTL_FEATURE_CONFIGURATION_PRIORITY;

typedef union _CPU_INFORMATION
{
    struct
    {
        DWORD VendorId[0x3];
        DWORD VersionInformation;
        DWORD FeatureInformation;
        DWORD AMDExtendedCpuFeatures;
    } X86CpuInfo;
    struct
    {
        QWORD ProcessorFeatures[0x2];
    } OtherCpuInfo;
}CPU_INFORMATION, * PCPU_INFORMATION;

typedef enum _CPU_SET_INFORMATION_TYPE // int32_t
{
    CpuSetInformation = 0x0
}CPU_SET_INFORMATION_TYPE, * PCPU_SET_INFORMATION_TYPE;

typedef enum _SYSTEM_PIXEL_FORMAT // int32_t
{
    SystemPixelFormatUnknown = 0x0,
    SystemPixelFormatR8G8B8 = 0x1,
    SystemPixelFormatR8G8B8X8 = 0x2,
    SystemPixelFormatB8G8R8 = 0x3,
    SystemPixelFormatB8G8R8X8 = 0x4
}SYSTEM_PIXEL_FORMAT, * PSYSTEM_PIXEL_FORMAT;

typedef struct _SYSTEM_BOOT_GRAPHICS_INFORMATION
{
    LARGE_INTEGER FrameBuffer;
    DWORD Width;
    DWORD Height;
    DWORD PixelStride;
    DWORD Flags;
    SYSTEM_PIXEL_FORMAT Format;
    DWORD DisplayRotation;
}SYSTEM_BOOT_GRAPHICS_INFORMATION, * PSYSTEM_BOOT_GRAPHICS_INFORMATION;

typedef struct _SYSTEM_BOOT_LOGO_INFORMATION
{
    DWORD Flags;
    DWORD BitmapOffset;
}SYSTEM_BOOT_LOGO_INFORMATION, * PSYSTEM_BOOT_LOGO_INFORMATION;


typedef struct _SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
{
    DWORD Options;
    DWORD HVCIOptions;
    QWORD Version;
    GUID PolicyGuid;
}SYSTEM_CODEINTEGRITYPOLICY_INFORMATION, * PSYSTEM_CODEINTEGRITYPOLICY_INFORMATION;

typedef struct _SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
{
    PVOID FileHandle;
    DWORD ImageSize;
    PVOID Image;
}SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION, * PSYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION;

typedef struct _SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
{
    PVOID ImageFile;
    DWORD Type;
}SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION, * PSYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION;

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
{
    DWORD Length;
    DWORD CodeIntegrityOptions;
}SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef struct _SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD Locked;
            DWORD UnlockApplied;
            DWORD UnlockIdValid;
            DWORD Reserved;
        } __bitfield0;
    } __inner0;
    UCHAR UnlockId[0x20];
}YSTEM_CODEINTEGRITY_UNLOCK_INFORMATION, * PYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION;

typedef struct _SYSTEM_CONSOLE_INFORMATION
{
    union
    {
        DWORD DriverLoaded;
        DWORD Spare;
    } __bitfield0;
}SYSTEM_CONSOLE_INFORMATION, * PSYSTEM_CONSOLE_INFORMATION;

typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION
{
    DWORD ContextSwitches;
    DWORD FindAny;
    DWORD FindLast;
    DWORD FindIdeal;
    DWORD IdleAny;
    DWORD IdleCurrent;
    DWORD IdleLast;
    DWORD IdleIdeal;
    DWORD PreemptAny;
    DWORD PreemptCurrent;
    DWORD PreemptLast;
    DWORD SwitchToIdle;
}SYSTEM_CONTEXT_SWITCH_INFORMATION, * PSYSTEM_CONTEXT_SWITCH_INFORMATION;

typedef struct _SYSTEM_CPU_SET_INFORMATION
{
    DWORD Size;
    CPU_SET_INFORMATION_TYPE Type;
    struct
    {
        DWORD Id;
        WORD Group;
        UCHAR LogicalProcessorIndex;
        UCHAR CoreIndex;
        UCHAR LastLevelCacheIndex;
        UCHAR NumaNodeIndex;
        UCHAR EfficiencyClass;
        union
        {
            UCHAR AllFlags;
            union
            {
                UCHAR Parked;
                UCHAR Allocated;
                UCHAR AllocatedToTargetProcess;
                UCHAR RealTime;
                UCHAR ReservedFlags;
            } __bitfield11;
        } __inner7;
        union
        {
            DWORD Reserved;
            UCHAR SchedulingClass;
        } __inner8;
        QWORD AllocationTag;
    } CpuSet;
}SYSTEM_CPU_SET_INFORMATION, * PSYSTEM_CPU_SET_INFORMATION;

typedef struct _SYSTEM_CPU_SET_TAG_INFORMATION
{
    QWORD Tag;
    QWORD CpuSets[0x1];
}SYSTEM_CPU_SET_TAG_INFORMATION, * PSYSTEM_CPU_SET_TAG_INFORMATION;

typedef enum _SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS// int32_t
{
    SystemCrashDumpDisable = 0x0,
    SystemCrashDumpReconfigure = 0x1,
    SystemCrashDumpInitializationComplete = 0x2
}SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS, * PSYSTEM_CRASH_DUMP_CONFIGURATION_CLASS;

typedef struct _SYSTEM_CRASH_DUMP_STATE_INFORMATION
{
    SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS CrashDumpConfigurationClass;
}SYSTEM_CRASH_DUMP_STATE_INFORMATION, * PSYSTEM_CRASH_DUMP_STATE_INFORMATION;

typedef struct _SYSTEM_DEVICE_DATA_INFORMATION
{
    UNICODE_STRING DeviceId;
    UNICODE_STRING DataName;
    DWORD DataType;
    DWORD DataBufferLength;
    PVOID DataBuffer;
}SYSTEM_DEVICE_DATA_INFORMATION, * PSYSTEM_DEVICE_DATA_INFORMATION;

typedef struct _SYSTEM_DMA_GUARD_POLICY_INFORMATION
{
    UCHAR DmaGuardPolicyEnabled;
}SYSTEM_DMA_GUARD_POLICY_INFORMATION, * PSYSTEM_DMA_GUARD_POLICY_INFORMATION;

typedef struct _SYSTEM_ELAM_CERTIFICATE_INFORMATION
{
    PVOID ElamDriverFile;
}SYSTEM_ELAM_CERTIFICATE_INFORMATION, * PSYSTEM_ELAM_CERTIFICATE_INFORMATION;

typedef struct _SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
{
    UCHAR EnclaveLaunchSigner[0x20];
}SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION, * PSYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION;

typedef struct _SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
{
    UCHAR Enabled;
}SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION, * PSYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION;

typedef struct _SYSTEM_ENTROPY_TIMING_INFORMATION
{
    void (*EntropyRoutine)(PVOID, DWORD);
    void (*InitializationRoutine)(PVOID, DWORD, PVOID);
    PVOID InitializationContext;
}SYSTEM_ENTROPY_TIMING_INFORMATION, * PSYSTEM_ENTROPY_TIMING_INFORMATION;

typedef struct _SYSTEM_ERROR_PORT_TIMEOUTS
{
    DWORD StartTimeout;
    DWORD CommTimeout;
}SYSTEM_ERROR_PORT_TIMEOUTS, * PSYSTEM_ERROR_PORT_TIMEOUTS;

typedef struct _SYSTEM_EXCEPTION_INFORMATION
{
    DWORD AlignmentFixupCount;
    DWORD ExceptionDispatchCount;
    DWORD FloatingEmulationCount;
    DWORD ByteWordEmulationCount;
}SYSTEM_EXCEPTION_INFORMATION, * PSYSTEM_EXCEPTION_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
    ULONG ContextSwitches;
    KTHREAD_STATE ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
    SYSTEM_THREAD_INFORMATION ThreadInfo;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID Win32StartAddress;
    PVOID TebBase;
    QWORD Reserved2;
    QWORD Reserved3;
    QWORD Reserved4;
}SYSTEM_EXTENDED_THREAD_INFORMATION, * PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _RTL_FEATURE_CONFIGURATION
{
    DWORD FeatureId;
    union
    {
        DWORD Priority;
        DWORD EnabledState;
        DWORD IsWexpConfiguration;
        DWORD HasSubscriptions;
        DWORD Variant;
        DWORD VariantPayloadKind;
    } __bitfield4;
    DWORD VariantPayload;
}RTL_FEATURE_CONFIGURATION, * PRTL_FEATURE_CONFIGURATION;

typedef struct _SYSTEM_FEATURE_CONFIGURATION_INFORMATION
{
    QWORD ChangeStamp;
    RTL_FEATURE_CONFIGURATION Configuration;

}SYSTEM_FEATURE_CONFIGURATION_INFORMATION, * PSYSTEM_FEATURE_CONFIGURATION_INFORMATION;

typedef enum _RTL_FEATURE_CONFIGURATION_TYPE //int32_t
{
    RtlFeatureConfigurationBoot = 0x0,
    RtlFeatureConfigurationRuntime = 0x1,
    RtlFeatureConfigurationCount = 0x2
}RTL_FEATURE_CONFIGURATION_TYPE, * PRTL_FEATURE_CONFIGURATION_TYPE;

typedef struct _SYSTEM_FEATURE_CONFIGURATION_QUERY
{
    RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType;
    DWORD FeatureId;
}SYSTEM_FEATURE_CONFIGURATION_QUERY, * PSYSTEM_FEATURE_CONFIGURATION_QUERY;

typedef struct _SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY
{
    QWORD ChangeStamp;
    PVOID Section;
    QWORD Size;
}SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY, * PSYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY;

typedef struct _SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
{
    QWORD OverallChangeStamp;
    SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY Descriptors[0x3];
}SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION, ** PSYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION;

typedef struct _SYSTEM_FIRMWARE_PARTITION_INFORMATION
{
    UNICODE_STRING FirmwarePartition;
}SYSTEM_FIRMWARE_PARTITION_INFORMATION, * PSYSTEM_FIRMWARE_PARTITION_INFORMATION;

typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION // int32_t
{
    SystemFirmwareTable_Enumerate = 0x0,
    SystemFirmwareTable_Get = 0x1
}SYSTEM_FIRMWARE_TABLE_ACTION, * PSYSTEM_FIRMWARE_TABLE_ACTION;

typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION
{
    DWORD ProviderSignature;
    SYSTEM_FIRMWARE_TABLE_ACTION Action;
    DWORD TableID;
    DWORD TableBufferLength;
    UCHAR TableBuffer[0x1];
}SYSTEM_FIRMWARE_TABLE_INFORMATION, * PSYSTEM_FIRMWARE_TABLE_INFORMATION;

typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER
{
    DWORD ProviderSignature;
    UCHAR Register;
    LONG(*FirmwareTableHandler)(SYSTEM_FIRMWARE_TABLE_INFORMATION*);
    PVOID DriverObject;
}SYSTEM_FIRMWARE_TABLE_HANDLER, * PSYSTEM_FIRMWARE_TABLE_HANDLER;

typedef struct _SYSTEM_FLAGS_INFORMATION
{
    DWORD Flags;
}SYSTEM_FLAGS_INFORMATION, * PSYSTEM_FLAGS_INFORMATION;

typedef struct _SYSTEM_FLUSH_INFORMATION
{
    DWORD SupportedFlushMethods;
    DWORD ProcessorCacheFlushSize;
    QWORD SystemFlushCapabilities;
    QWORD Reserved[0x2];
}SYSTEM_FLUSH_INFORMATION, * PSYSTEM_FLUSH_INFORMATION;

typedef struct _SYSTEM_GDI_DRIVER_INFORMATION
{
    UNICODE_STRING DriverName;
    PVOID ImageAddress;
    PVOID SectionPointer;
    PVOID EntryPoint;
    IMAGE_EXPORT_DIRECTORY* ExportSectionPointer;
    DWORD ImageLength;
}SYSTEM_GDI_DRIVER_INFORMATION, * PSYSTEM_GDI_DRIVER_INFORMATION;

typedef enum _RTL_FEATURE_ENABLED_STATE // int32_t
{
    FeatureEnabledStateDefault = 0x0,
    FeatureEnabledStateDisabled = 0x1,
    FeatureEnabledStateEnabled = 0x2
}RTL_FEATURE_ENABLED_STATE, * PRTL_FEATURE_ENABLED_STATE;

typedef enum _RTL_FEATURE_ENABLED_STATE_OPTIONS // int32_t
{
    FeatureEnabledStateOptionsNone = 0x0,
    FeatureEnabledStateOptionsWexpConfig = 0x1
}RTL_FEATURE_ENABLED_STATE_OPTIONS, * PRTL_FEATURE_ENABLED_STATE_OPTIONS;

typedef enum _RTL_FEATURE_VARIANT_PAYLOAD_KIND // int32_t
{
    FeatureVariantPayloadKindNone = 0x0,
    FeatureVariantPayloadKindResident = 0x1,
    FeatureVariantPayloadKindExternal = 0x2
}RTL_FEATURE_VARIANT_PAYLOAD_KIND, * PRTL_FEATURE_VARIANT_PAYLOAD_KIND;

typedef enum _RTL_FEATURE_CONFIGURATION_OPERATION // int32_t
{
    FeatureConfigurationOperationNone = 0x0,
    FeatureConfigurationOperationFeatureState = 0x1,
    FeatureConfigurationOperationVariantState = 0x2,
    FeatureConfigurationOperationResetState = 0x4
}RTL_FEATURE_CONFIGURATION_OPERATION, * PRTL_FEATURE_CONFIGURATION_OPERATION;

typedef struct _RTL_FEATURE_CONFIGURATION_UPDATE
{
    DWORD FeatureId;
    RTL_FEATURE_CONFIGURATION_PRIORITY Priority;
    RTL_FEATURE_ENABLED_STATE EnabledState;
    RTL_FEATURE_ENABLED_STATE_OPTIONS EnabledStateOptions;
    UCHAR Variant;
    UCHAR Reserved[0x3];
    RTL_FEATURE_VARIANT_PAYLOAD_KIND VariantPayloadKind;
    DWORD VariantPayload;
    RTL_FEATURE_CONFIGURATION_OPERATION Operation;
}RTL_FEATURE_CONFIGURATION_UPDATE, * PRTL_FEATURE_CONFIGURATION_UPDATE;

typedef struct _SYSTEM_FEATURE_CONFIGURATION_UPDATE
{
    QWORD PreviousChangeStamp;
    RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType;
    DWORD UpdateCount;
    RTL_FEATURE_CONFIGURATION_UPDATE Updates[0x1];
}SYSTEM_FEATURE_CONFIGURATION_UPDATE, * PSYSTEM_FEATURE_CONFIGURATION_UPDATE;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    WORD UniqueProcessId;
    WORD CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    WORD HandleValue;
    PVOID Object;
    DWORD GrantedAccess;
}SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    QWORD UniqueProcessId;
    QWORD HandleValue;
    DWORD GrantedAccess;
    WORD CreatorBackTraceIndex;
    WORD ObjectTypeIndex;
    DWORD HandleAttributes;
    DWORD Reserved;
}SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    DWORD NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[0x1];
}SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    QWORD NumberOfHandles;
    QWORD Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[0x1];
}SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _SYSTEM_HIBERFILE_INFORMATION
{
    DWORD NumberOfMcbPairs;
    LARGE_INTEGER Mcb[0x1];
}SYSTEM_HIBERFILE_INFORMATION, * PSYSTEM_HIBERFILE_INFORMATION;

typedef struct _HV_DETAILS
{
    DWORD Data[0x4];
}HV_DETAILS, * PHV_DETAILS;

typedef struct _SYSTEM_INTERRUPT_CPU_SET_INFORMATION
{
    DWORD Gsiv;
    WORD Group;
    QWORD CpuSets;
}SYSTEM_INTERRUPT_CPU_SET_INFORMATION, * PSYSTEM_INTERRUPT_CPU_SET_INFORMATION;

typedef struct _SYSTEM_INTERRUPT_INFORMATION
{
    DWORD ContextSwitches;
    DWORD DpcCount;
    DWORD DpcRate;
    DWORD TimeIncrement;
    DWORD DpcBypassCount;
    DWORD ApcBypassCount;
}SYSTEM_INTERRUPT_INFORMATION, * PSYSTEM_INTERRUPT_INFORMATION;

typedef struct _SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT
{
    DWORD Gsiv;
    UCHAR ControllerInterrupt;
    UCHAR EdgeInterrupt;
    UCHAR IsPrimaryInterrupt;
    GROUP_AFFINITY TargetAffinity;
}SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, * PSYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT;

typedef struct _SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT
{
    union
    {
        union
        {
            DWORD Enabled;
            DWORD Reserved;
        } __bitfield0;
        DWORD AsULONG;
    } __inner0;
}SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT, * PSYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT;

typedef struct _SYSTEM_ISOLATED_USER_MODE_INFORMATION
{
    union
    {
        UCHAR SecureKernelRunning;
        UCHAR HvciEnabled;
        UCHAR HvciStrictMode;
        UCHAR DebugEnabled;
        UCHAR FirmwarePageProtection;
        UCHAR EncryptionKeyAvailable;
        UCHAR SpareFlags;
    } __bitfield0;
    union
    {
        UCHAR TrustletRunning;
        UCHAR HvciDisableAllowed;
        UCHAR SpareFlags2;
    } __bitfield1;
    UCHAR Spare0[0x6];
    QWORD Spare1;
}SYSTEM_ISOLATED_USER_MODE_INFORMATION, * PSYSTEM_ISOLATED_USER_MODE_INFORMATION;

typedef struct _SYSTEM_KERNEL_DEBUGGER_FLAGS
{
    UCHAR KernelDebuggerIgnoreUmExceptions;
}SYSTEM_KERNEL_DEBUGGER_FLAGS, * PSYSTEM_KERNEL_DEBUGGER_FLAGS;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    UCHAR KernelDebuggerEnabled;
    UCHAR KernelDebuggerNotPresent;
}SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
{
    UCHAR DebuggerAllowed;
    UCHAR DebuggerEnabled;
    UCHAR DebuggerPresent;
}SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX;

typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION
{
    struct
    {
        union
        {
            DWORD KvaShadowEnabled;
            DWORD KvaShadowUserGlobal;
            DWORD KvaShadowPcid;
            DWORD KvaShadowInvpcid;
            DWORD KvaShadowRequired;
            DWORD KvaShadowRequiredAvailable;
            DWORD InvalidPteBit;
            DWORD L1DataCacheFlushSupported;
            DWORD L1TerminalFaultMitigationPresent;
            DWORD Reserved;
        } __bitfield0;
    } KvaShadowFlags;
}SYSTEM_KERNEL_VA_SHADOW_INFORMATION, * PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;

typedef struct _SYSTEM_LEAP_SECOND_INFORMATION
{
    UCHAR Enabled;
    DWORD Flags;
}SYSTEM_LEAP_SECOND_INFORMATION, * PSYSTEM_LEAP_SECOND_INFORMATION;

typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION
{
    DWORD VetoType;
    UNICODE_STRING VetoList;
}SYSTEM_LEGACY_DRIVER_INFORMATION, * PSYSTEM_LEGACY_DRIVER_INFORMATION;

typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION
{
    QWORD ProcessorMask;
    LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
    union
    {
        struct
        {
            UCHAR Flags;
        } ProcessorCore;
        struct
        {
            DWORD NodeNumber;
        } NumaNode;
        CACHE_DESCRIPTOR Cache;
        QWORD Reserved[0x2];
    } __inner2;
}SYSTEM_LOGICAL_PROCESSOR_INFORMATION, * PSYSTEM_LOGICAL_PROCESSOR_INFORMATION;

typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
{
    LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
    DWORD Size;
    union
    {
        struct _PROCESSOR_RELATIONSHIP Processor;
        struct _NUMA_NODE_RELATIONSHIP NumaNode;
        struct _CACHE_RELATIONSHIP Cache;
        struct _GROUP_RELATIONSHIP Group;
    } __inner2;
}SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, * PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;

typedef struct _SYSTEM_HYPERVISOR_DETAIL_INFORMATION
{
    HV_DETAILS HvVendorAndMaxFunction;
    HV_DETAILS HypervisorInterface;
    HV_DETAILS HypervisorVersion;
    HV_DETAILS HvFeatures;
    HV_DETAILS HwFeatures;
    HV_DETAILS EnlightenmentInfo;
    HV_DETAILS ImplementationLimits;
}SYSTEM_HYPERVISOR_DETAIL_INFORMATION, * PSYSTEM_HYPERVISOR_DETAIL_INFORMATION;

typedef struct _SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
{
    DWORD NumberOfLogicalProcessors;
    DWORD NumberOfCores;
}SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION, * PSYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION;

typedef struct _SYSTEM_HYPERVISOR_QUERY_INFORMATION
{
    UCHAR HypervisorConnected;
    UCHAR HypervisorDebuggingEnabled;
    UCHAR HypervisorPresent;
    UCHAR HypervisorSchedulerType;
    UCHAR Spare0[0x4];
    QWORD EnabledEnlightenments;
}SYSTEM_HYPERVISOR_QUERY_INFORMATION, * PSYSTEM_HYPERVISOR_QUERY_INFORMATION;

typedef struct _SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION
{
    PVOID HypervisorSharedUserVa;
}SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION, * PSYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION;

typedef struct _SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION
{
    DWORD FlagsToEnable;
    DWORD FlagsToDisable;
}SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION, * PSYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION;

typedef struct _SYSTEM_LOOKASIDE_INFORMATION
{
    WORD CurrentDepth;
    WORD MaximumDepth;
    DWORD TotalAllocates;
    DWORD AllocateMisses;
    DWORD TotalFrees;
    DWORD FreeMisses;
    DWORD Type;
    DWORD Tag;
    DWORD Size;
}SYSTEM_LOOKASIDE_INFORMATION, * PSYSTEM_LOOKASIDE_INFORMATION;

typedef struct _SYSTEM_LOW_PRIORITY_IO_INFORMATION
{
    DWORD LowPriReadOperations;
    DWORD LowPriWriteOperations;
    DWORD KernelBumpedToNormalOperations;
    DWORD LowPriPagingReadOperations;
    DWORD KernelPagingReadsBumpedToNormal;
    DWORD LowPriPagingWriteOperations;
    DWORD KernelPagingWritesBumpedToNormal;
    DWORD BoostedIrpCount;
    DWORD BoostedPagingIrpCount;
    DWORD BlanketBoostCount;
}SYSTEM_LOW_PRIORITY_IO_INFORMATION, * PSYSTEM_LOW_PRIORITY_IO_INFORMATION;

typedef struct _SYSTEM_MANUFACTURING_INFORMATION
{
    DWORD Options;
    UNICODE_STRING ProfileName;
}SYSTEM_MANUFACTURING_INFORMATION, * PSYSTEM_MANUFACTURING_INFORMATION;

typedef struct _SYSTEM_MEMORY_CHANNEL_INFORMATION
{
    DWORD ChannelNumber;
    DWORD ChannelHeatIndex;
    QWORD TotalPageCount;
    QWORD ZeroPageCount;
    QWORD FreePageCount;
    QWORD StandbyPageCount;
}SYSTEM_MEMORY_CHANNEL_INFORMATION, * PSYSTEM_MEMORY_CHANNEL_INFORMATION;

typedef struct _SYSTEM_MEMORY_INFORMATION
{
    QWORD PagedPoolCommitPageCount;
    QWORD NonPagedPoolPageCount;
    QWORD MdlPageCount;
    QWORD CommitPageCount;
}SYSTEM_MEMORY_INFORMATION, * PSYSTEM_MEMORY_INFORMATION;

typedef enum _SYSTEM_MEMORY_LIST_COMMAND // int32_t
{
    MemoryCaptureAccessedBits = 0x0,
    MemoryCaptureAndResetAccessedBits = 0x1,
    MemoryEmptyWorkingSets = 0x2,
    MemoryFlushModifiedList = 0x3,
    MemoryPurgeStandbyList = 0x4,
    MemoryPurgeLowPriorityStandbyList = 0x5,
    MemoryCommandMax = 0x6
}SYSTEM_MEMORY_LIST_COMMAND, * PSYSTEM_MEMORY_LIST_COMMAND;

typedef struct _SYSTEM_MEMORY_LIST_INFORMATION
{
    QWORD ZeroPageCount;
    QWORD FreePageCount;
    QWORD ModifiedPageCount;
    QWORD ModifiedNoWritePageCount;
    QWORD BadPageCount;
    QWORD PageCountByPriority[0x8];
    QWORD RepurposedPagesByPriority[0x8];
    QWORD ModifiedPageCountPageFile;
}SYSTEM_MEMORY_LIST_INFORMATION, * PSYSTEM_MEMORY_LIST_INFORMATION;

typedef struct _PHYSICAL_CHANNEL_RUN
{
    DWORD NodeNumber;
    DWORD ChannelNumber;
    QWORD BasePage;
    QWORD PageCount;
    QWORD Flags;
}PHYSICAL_CHANNEL_RUN, * PPHYSICAL_CHANNEL_RUN;

typedef struct _SYSTEM_MEMORY_TOPOLOGY_INFORMATION
{
    QWORD NumberOfRuns;
    DWORD NumberOfNodes;
    DWORD NumberOfChannels;
    PHYSICAL_CHANNEL_RUN Run[0x1];
}SYSTEM_MEMORY_TOPOLOGY_INFORMATION, * PSYSTEM_MEMORY_TOPOLOGY_INFORMATION;

typedef struct _SYSTEM_MEMORY_USAGE_INFORMATION
{
    QWORD TotalPhysicalBytes;
    QWORD AvailableBytes;
    __int64 ResidentAvailableBytes;
    QWORD CommittedBytes;
    QWORD SharedCommittedBytes;
    QWORD CommitLimitBytes;
    QWORD PeakCommitmentBytes;
}SYSTEM_MEMORY_USAGE_INFORMATION, * PSYSTEM_MEMORY_USAGE_INFORMATION;

typedef struct _SYSTEM_NUMA_INFORMATION
{
    DWORD HighestNodeNumber;
    DWORD Reserved;
    union
    {
        GROUP_AFFINITY ActiveProcessorsGroupAffinity[0x40];
        QWORD AvailableMemory[0x40];
        QWORD Pad[0x80];
    } __inner2;
}SYSTEM_NUMA_INFORMATION, * PSYSTEM_NUMA_INFORMATION;

typedef struct _SYSTEM_OBJECTTYPE_INFORMATION
{
    DWORD NextEntryOffset;
    DWORD NumberOfObjects;
    DWORD NumberOfHandles;
    DWORD TypeIndex;
    DWORD InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    DWORD ValidAccessMask;
    DWORD PoolType;
    UCHAR SecurityRequired;
    UCHAR WaitableObject;
    UNICODE_STRING TypeName;
}SYSTEM_OBJECTTYPE_INFORMATION, * PSYSTEM_OBJECTTYPE_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION
{
    UNICODE_STRING Name;
}OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION
{
    DWORD NextEntryOffset;
    PVOID Object;
    PVOID CreatorUniqueProcess;
    WORD CreatorBackTraceIndex;
    WORD Flags;
    LONG PointerCount;
    LONG HandleCount;
    DWORD PagedPoolCharge;
    DWORD NonPagedPoolCharge;
    PVOID ExclusiveProcessId;
    PVOID SecurityDescriptor;
    OBJECT_NAME_INFORMATION NameInfo;
}SYSTEM_OBJECT_INFORMATION, * PSYSTEM_OBJECT_INFORMATION;

typedef struct _SYSTEM_PAGEFILE_INFORMATION
{
    DWORD NextEntryOffset;
    DWORD TotalSize;
    DWORD TotalInUse;
    DWORD PeakUsage;
    UNICODE_STRING PageFileName;
}SYSTEM_PAGEFILE_INFORMATION, * PSYSTEM_PAGEFILE_INFORMATION;

typedef struct _SYSTEM_PAGEFILE_INFORMATION_EX
{
    SYSTEM_PAGEFILE_INFORMATION Info;
    DWORD MinimumSize;
    DWORD MaximumSize;
}SYSTEM_PAGEFILE_INFORMATION_EX, * PSYSTEM_PAGEFILE_INFORMATION_EX;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleProcessTime;
    LARGE_INTEGER IoReadTransferCount;
    LARGE_INTEGER IoWriteTransferCount;
    LARGE_INTEGER IoOtherTransferCount;
    DWORD IoReadOperationCount;
    DWORD IoWriteOperationCount;
    DWORD IoOtherOperationCount;
    DWORD AvailablePages;
    DWORD CommittedPages;
    DWORD CommitLimit;
    DWORD PeakCommitment;
    DWORD PageFaultCount;
    DWORD CopyOnWriteCount;
    DWORD TransitionCount;
    DWORD CacheTransitionCount;
    DWORD DemandZeroCount;
    DWORD PageReadCount;
    DWORD PageReadIoCount;
    DWORD CacheReadCount;
    DWORD CacheIoCount;
    DWORD DirtyPagesWriteCount;
    DWORD DirtyWriteIoCount;
    DWORD MappedPagesWriteCount;
    DWORD MappedWriteIoCount;
    DWORD PagedPoolPages;
    DWORD NonPagedPoolPages;
    DWORD PagedPoolAllocs;
    DWORD PagedPoolFrees;
    DWORD NonPagedPoolAllocs;
    DWORD NonPagedPoolFrees;
    DWORD FreeSystemPtes;
    DWORD ResidentSystemCodePage;
    DWORD TotalSystemDriverPages;
    DWORD TotalSystemCodePages;
    DWORD NonPagedPoolLookasideHits;
    DWORD PagedPoolLookasideHits;
    DWORD AvailablePagedPoolPages;
    DWORD ResidentSystemCachePage;
    DWORD ResidentPagedPoolPage;
    DWORD ResidentSystemDriverPage;
    DWORD CcFastReadNoWait;
    DWORD CcFastReadWait;
    DWORD CcFastReadResourceMiss;
    DWORD CcFastReadNotPossible;
    DWORD CcFastMdlReadNoWait;
    DWORD CcFastMdlReadWait;
    DWORD CcFastMdlReadResourceMiss;
    DWORD CcFastMdlReadNotPossible;
    DWORD CcMapDataNoWait;
    DWORD CcMapDataWait;
    DWORD CcMapDataNoWaitMiss;
    DWORD CcMapDataWaitMiss;
    DWORD CcPinMappedDataCount;
    DWORD CcPinReadNoWait;
    DWORD CcPinReadWait;
    DWORD CcPinReadNoWaitMiss;
    DWORD CcPinReadWaitMiss;
    DWORD CcCopyReadNoWait;
    DWORD CcCopyReadWait;
    DWORD CcCopyReadNoWaitMiss;
    DWORD CcCopyReadWaitMiss;
    DWORD CcMdlReadNoWait;
    DWORD CcMdlReadWait;
    DWORD CcMdlReadNoWaitMiss;
    DWORD CcMdlReadWaitMiss;
    DWORD CcReadAheadIos;
    DWORD CcLazyWriteIos;
    DWORD CcLazyWritePages;
    DWORD CcDataFlushes;
    DWORD CcDataPages;
    DWORD ContextSwitches;
    DWORD FirstLevelTbFills;
    DWORD SecondLevelTbFills;
    DWORD SystemCalls;
    QWORD CcTotalDirtyPages;
    QWORD CcDirtyPageThreshold;
    __int64 ResidentAvailablePages;
    QWORD SharedCommittedPages;
}SYSTEM_PERFORMANCE_INFORMATION, * PSYSTEM_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_PHYSICAL_MEMORY_INFORMATION
{
    QWORD TotalPhysicalBytes;
    QWORD LowestPhysicalAddress;
    QWORD HighestPhysicalAddress;
}SYSTEM_PHYSICAL_MEMORY_INFORMATION, * PSYSTEM_PHYSICAL_MEMORY_INFORMATION;

typedef struct _SYSTEM_PLATFORM_BINARY_INFORMATION
{
    QWORD PhysicalAddress;
    PVOID HandoffBuffer;
    PVOID CommandLineBuffer;
    DWORD HandoffBufferSize;
    DWORD CommandLineBufferSize;
}SYSTEM_PLATFORM_BINARY_INFORMATION, * PSYSTEM_PLATFORM_BINARY_INFORMATION;

typedef struct _SYSTEM_POLICY_INFORMATION
{
    PVOID InputData;
    PVOID OutputData;
    DWORD InputDataSize;
    DWORD OutputDataSize;
    DWORD Version;
}SYSTEM_POLICY_INFORMATION, * PSYSTEM_POLICY_INFORMATION;

typedef struct _SYSTEM_POOLTAG
{
    union
    {
        UCHAR Tag[0x4];
        DWORD TagUlong;
    } __inner0;
    DWORD PagedAllocs;
    DWORD PagedFrees;
    QWORD PagedUsed;
    DWORD NonPagedAllocs;
    DWORD NonPagedFrees;
    QWORD NonPagedUsed;
}SYSTEM_POOLTAG, * PSYSTEM_POOLTAG;

typedef struct _SYSTEM_POOLTAG_INFORMATION
{
    DWORD Count;
    SYSTEM_POOLTAG TagInfo[0x1];
}SYSTEM_POOLTAG_INFORMATION, * PSYSTEM_POOLTAG_INFORMATION;

typedef struct _SYSTEM_POOL_ENTRY
{
    UCHAR Allocated;
    UCHAR Spare0;
    WORD AllocatorBackTraceIndex;
    DWORD Size;
    union
    {
        UCHAR Tag[0x4];
        DWORD TagUlong;
        PVOID ProcessChargedQuota;
    } __inner4;
}SYSTEM_POOL_ENTRY, * PSYSTEM_POOL_ENTRY;

typedef struct _SYSTEM_POOL_INFORMATION
{
    QWORD TotalSize;
    PVOID FirstEntry;
    WORD EntryOverhead;
    UCHAR PoolTagPresent;
    UCHAR Spare0;
    DWORD NumberOfEntries;
    SYSTEM_POOL_ENTRY Entries[0x1];
}SYSTEM_POOL_INFORMATION, * PSYSTEM_POOL_INFORMATION;

typedef struct _SYSTEM_POOL_ZEROING_INFORMATION
{
    UCHAR PoolZeroingSupportPresent;
}SYSTEM_POOL_ZEROING_INFORMATION, * PSYSTEM_POOL_ZEROING_INFORMATION;

typedef struct _SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
{
    UCHAR EfiLauncherEnabled;
}SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION, * PSYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION;

typedef struct _SYSTEM_POWER_INFORMATION
{
    DWORD MaxIdlenessAllowed;
    DWORD Idleness;
    DWORD TimeRemaining;
    UCHAR CoolingMode;
}SYSTEM_POWER_INFORMATION, * PSYSTEM_POWER_INFORMATION;

typedef struct _SYSTEM_PREFETCH_PATCH_INFORMATION
{
    DWORD PrefetchPatchCount;
}SYSTEM_PREFETCH_PATCH_INFORMATION, * PSYSTEM_PREFETCH_PATCH_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION
{
    QWORD Cycles[0x4][0x2];
}SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION, * PSYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION
{
    QWORD CycleTime;
}SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION, * PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_FEATURES_INFORMATION
{
    QWORD ProcessorFeatureBits;
    QWORD Reserved[0x3];
}SYSTEM_PROCESSOR_FEATURES_INFORMATION, * PSYSTEM_PROCESSOR_FEATURES_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION
{
    QWORD CycleTime;
}SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION, * PSYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_IDLE_INFORMATION
{
    QWORD IdleTime;
    QWORD C1Time;
    QWORD C2Time;
    QWORD C3Time;
    DWORD C1Transitions;
    DWORD C2Transitions;
    DWORD C3Transitions;
    DWORD Padding;
}SYSTEM_PROCESSOR_IDLE_INFORMATION, * PSYSTEM_PROCESSOR_IDLE_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
    WORD ProcessorArchitecture;
    WORD ProcessorLevel;
    WORD ProcessorRevision;
    WORD MaximumProcessors;
    DWORD ProcessorFeatureBits;
}SYSTEM_PROCESSOR_INFORMATION, * PSYSTEM_PROCESSOR_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
{
    DWORD Operation;
}SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION, * PSYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION
{
    DWORD ProcessorCount;
    DWORD Offsets[0x1];
}SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION, * PSYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    DWORD InterruptCount;
}SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, * PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX
{
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    DWORD InterruptCount;
    DWORD Spare0;
    LARGE_INTEGER AvailableTime;
    LARGE_INTEGER Spare1;
    LARGE_INTEGER Spare2;
}SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX, * PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX;

typedef struct _XSAVE_CPU_INFO
{
    UCHAR Processor;
    WORD Family;
    WORD Model;
    WORD Stepping;
    WORD ExtendedModel;
    DWORD ExtendedFamily;
    QWORD MicrocodeVersion;
    DWORD Reserved;
}XSAVE_CPU_INFO, * PXSAVE_CPU_INFO;

typedef struct _XSAVE_CPU_ERRATA
{
    DWORD NumberOfErrata;
    XSAVE_CPU_INFO Errata[0x1];
}XSAVE_CPU_ERRATA, * PXSAVE_CPU_ERRATA;

typedef struct _XSAVE_SUPPORTED_CPU
{
    XSAVE_CPU_INFO CpuInfo;
    union
    {
        XSAVE_CPU_ERRATA* CpuErrata;
        QWORD Unused;
    } __inner1;
}XSAVE_SUPPORTED_CPU, * PXSAVE_SUPPORTED_CPU;

typedef struct _XSAVE_VENDOR
{
    DWORD VendorId[0x3];
    XSAVE_SUPPORTED_CPU SupportedCpu;
}XSAVE_VENDOR, * PXSAVE_VENDOR;

typedef struct _XSAVE_VENDORS
{
    DWORD NumberOfVendors;
    XSAVE_VENDOR Vendor[0x1];
}XSAVE_VENDORS, * PXSAVE_VENDORS;

typedef struct _XSAVE_FEATURE
{
    DWORD FeatureId;
    union
    {
        XSAVE_VENDORS* Vendors;
        QWORD Unused;
    } __inner1;
}XSAVE_FEATURE, * PXSAVE_FEATURE;

typedef struct _XSAVE_POLICY
{
    DWORD Version;
    DWORD Size;
    DWORD Flags;
    DWORD MaxSaveAreaLength;
    DWORD FeatureBitmask;
    DWORD NumberOfFeatures;
    XSAVE_FEATURE Features[0x1];
}XSAVE_POLICY, * PXSAVE_POLICY;

typedef struct _SYSTEM_PROCESSOR_POLICY_INFORMATION
{
    DWORD Length;
    DWORD PolicyId;
    XSAVE_POLICY Policy;
}SYSTEM_PROCESSOR_POLICY_INFORMATION, * PSYSTEM_PROCESSOR_POLICY_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_POWER_INFORMATION
{
    UCHAR CurrentFrequency;
    UCHAR ThermalLimitFrequency;
    UCHAR ConstantThrottleFrequency;
    UCHAR DegradedThrottleFrequency;
    UCHAR LastBusyFrequency;
    UCHAR LastC3Frequency;
    UCHAR LastAdjustedBusyFrequency;
    UCHAR ProcessorMinThrottle;
    UCHAR ProcessorMaxThrottle;
    DWORD NumberOfFrequencies;
    DWORD PromotionCount;
    DWORD DemotionCount;
    DWORD ErrorCount;
    DWORD RetryCount;
    QWORD CurrentFrequencyTime;
    QWORD CurrentProcessorTime;
    QWORD CurrentProcessorIdleTime;
    QWORD LastProcessorTime;
    QWORD LastProcessorIdleTime;
    QWORD Energy;
}SYSTEM_PROCESSOR_POWER_INFORMATION, * PSYSTEM_PROCESSOR_POWER_INFORMATION;

typedef struct _SYSTEM_PROCESS_ID_INFORMATION
{
    PVOID ProcessId;
    UNICODE_STRING ImageName;
}SYSTEM_PROCESS_ID_INFORMATION, * PSYSTEM_PROCESS_ID_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    /*typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
    ULONG HardFaultCount; // since WIN7
    ULONG NumberOfThreadsHighWatermark; // since WIN7
    ULONGLONG CycleTime; // since WIN7
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1]; // SystemProcessInformation
    // SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1]; // SystemExtendedProcessinformation
    // SYSTEM_EXTENDED_THREAD_INFORMATION + SYSTEM_PROCESS_INFORMATION_EXTENSION // SystemFullProcessInformation
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;*/
    DWORD NextEntryOffset;
    DWORD NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    DWORD HardFaultCount;
    DWORD NumberOfThreadsHighWatermark;
    QWORD CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    PVOID UniqueProcessId;
    PVOID InheritedFromUniqueProcessId;
    DWORD HandleCount;
    DWORD SessionId;
    QWORD UniqueProcessKey;
    QWORD PeakVirtualSize;
    QWORD VirtualSize;
    DWORD PageFaultCount;
    QWORD PeakWorkingSetSize;
    QWORD WorkingSetSize;
    QWORD QuotaPeakPagedPoolUsage;
    QWORD QuotaPagedPoolUsage;
    QWORD QuotaPeakNonPagedPoolUsage;
    QWORD QuotaNonPagedPoolUsage;
    QWORD PagefileUsage;
    QWORD PeakPagefileUsage;
    QWORD PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
}SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_REF_TRACE_INFORMATION
{
    UCHAR TraceEnable;
    UCHAR TracePermanent;
    UNICODE_STRING TraceProcessName;
    UNICODE_STRING TracePoolTags;
}SYSTEM_REF_TRACE_INFORMATION, * PSYSTEM_REF_TRACE_INFORMATION;

typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION
{
    DWORD RegistryQuotaAllowed;
    DWORD RegistryQuotaUsed;
    QWORD PagedPoolSize;
}SYSTEM_REGISTRY_QUOTA_INFORMATION, * PSYSTEM_REGISTRY_QUOTA_INFORMATION;

typedef struct _SYSTEM_ROOT_SILO_INFORMATION
{
    DWORD NumberOfSilos;
    DWORD SiloIdList[0x1];
}SYSTEM_ROOT_SILO_INFORMATION, * PSYSTEM_ROOT_SILO_INFORMATION;

typedef struct _SYSTEM_SECUREBOOT_INFORMATION
{
    UCHAR SecureBootEnabled;
    UCHAR SecureBootCapable;
}SYSTEM_SECUREBOOT_INFORMATION, * PSYSTEM_SECUREBOOT_INFORMATION;

typedef struct _SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION
{
    DWORD PlatformManifestSize;
    UCHAR PlatformManifest[0x1];
}SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION, * PSYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION;

typedef struct _SYSTEM_SECUREBOOT_POLICY_INFORMATION
{
    GUID PolicyPublisher;
    DWORD PolicyVersion;
    DWORD PolicyOptions;
}SYSTEM_SECUREBOOT_POLICY_INFORMATION, * PSYSTEM_SECUREBOOT_POLICY_INFORMATION;

typedef struct _SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
{
    SYSTEM_SECUREBOOT_POLICY_INFORMATION PolicyInformation;
    DWORD PolicySize;
    UCHAR Policy[0x1];
}SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION, * PSYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION;

typedef struct _SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
{
    DWORD ExtentCount;
    DWORD ValidStructureSize;
    DWORD NextExtentIndex;
    DWORD ExtentRestart;
    DWORD CycleCount;
    DWORD TimeoutCount;
    QWORD CycleTime;
    QWORD CycleTimeMax;
    QWORD ExtentTime;
    DWORD ExtentTimeIndex;
    DWORD ExtentTimeMaxIndex;
    QWORD ExtentTimeMax;
    QWORD HyperFlushTimeMax;
    QWORD TranslateVaTimeMax;
    QWORD DebugExemptionCount;
    QWORD TbHitCount;
    QWORD TbMissCount;
    QWORD VinaPendingYield;
    QWORD HashCycles;
    DWORD HistogramOffset;
    DWORD HistogramBuckets;
    DWORD HistogramShift;
    DWORD Reserved1;
    QWORD PageNotPresentCount;
}SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION, * PSYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION;

typedef struct _SYSTEM_SECURITY_MODEL_INFORMATION
{
    struct
    {
        union
        {
            DWORD SModeAdminlessEnabled;
            DWORD AllowDeviceOwnerProtectionDowngrade;
            DWORD Reserved;
        } __bitfield0;
    } SecurityModelFlags;
}SYSTEM_SECURITY_MODEL_INFORMATION, * PSYSTEM_SECURITY_MODEL_INFORMATION;

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
    union
    {
        PVOID VirtualAddress;
        union
        {
            QWORD NonPaged;
        } __bitfield0;
    } __inner0;
    QWORD SizeInBytes;
    union
    {
        UCHAR Tag[0x4];
        DWORD TagUlong;
    } __inner2;

}SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_SESSION_BIGPOOL_INFORMATION
{
    QWORD NextEntryOffset;
    DWORD SessionId;
    DWORD Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[0x1];
}SYSTEM_SESSION_BIGPOOL_INFORMATION, * PSYSTEM_SESSION_BIGPOOL_INFORMATION;

typedef struct _SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
{
    QWORD NextEntryOffset;
    DWORD SessionId;
    DWORD ViewFailures;
    QWORD NumberOfBytesAvailable;
    QWORD NumberOfBytesAvailableContiguous;
}SYSTEM_SESSION_MAPPED_VIEW_INFORMATION, * PSYSTEM_SESSION_MAPPED_VIEW_INFORMATION;

typedef struct _SYSTEM_SESSION_POOLTAG_INFORMATION
{
    QWORD NextEntryOffset;
    DWORD SessionId;
    DWORD Count;
    SYSTEM_POOLTAG TagInfo[0x1];
}SYSTEM_SESSION_POOLTAG_INFORMATION, * PSYSTEM_SESSION_POOLTAG_INFORMATION;

typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
    DWORD SessionId;
    DWORD SizeOfBuf;
    PVOID Buffer;
}SYSTEM_SESSION_PROCESS_INFORMATION, * PSYSTEM_SESSION_PROCESS_INFORMATION;

typedef struct _SYSTEM_SHADOW_STACK_INFORMATION
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD CetCapable;
            DWORD UserCetAllowed;
            DWORD ReservedForUserCet;
            DWORD KernelCetEnabled;
            DWORD ReservedForKernelCet;
            DWORD Reserved;
        } __bitfield0;
    } __inner0;
}SYSTEM_SHADOW_STACK_INFORMATION, * PSYSTEM_SHADOW_STACK_INFORMATION;

typedef struct _SYSTEM_SINGLE_MODULE_INFORMATION
{
    PVOID TargetModuleAddress;
    RTL_PROCESS_MODULE_INFORMATION_EX ExInfo;
}SYSTEM_SINGLE_MODULE_INFORMATION, * PSYSTEM_SINGLE_MODULE_INFORMATION;

typedef struct _SYSTEM_SPECIAL_POOL_INFORMATION
{
    DWORD PoolTag;
    DWORD Flags;
}SYSTEM_SPECIAL_POOL_INFORMATION, * PSYSTEM_SPECIAL_POOL_INFORMATION;

typedef struct _SYSTEM_SPECULATION_CONTROL_INFORMATION
{
    struct
    {
        union
        {
            DWORD BpbEnabled;
            DWORD BpbDisabledSystemPolicy;
            DWORD BpbDisabledNoHardwareSupport;
            DWORD SpecCtrlEnumerated;
            DWORD SpecCmdEnumerated;
            DWORD IbrsPresent;
            DWORD StibpPresent;
            DWORD SmepPresent;
            DWORD SpeculativeStoreBypassDisableAvailable;
            DWORD SpeculativeStoreBypassDisableSupported;
            DWORD SpeculativeStoreBypassDisabledSystemWide;
            DWORD SpeculativeStoreBypassDisabledKernel;
            DWORD SpeculativeStoreBypassDisableRequired;
            DWORD BpbDisabledKernelToUser;
            DWORD SpecCtrlRetpolineEnabled;
            DWORD SpecCtrlImportOptimizationEnabled;
            DWORD EnhancedIbrs;
            DWORD HvL1tfStatusAvailable;
            DWORD HvL1tfProcessorNotAffected;
            DWORD HvL1tfMigitationEnabled;
            DWORD HvL1tfMigitationNotEnabled_Hardware;
            DWORD HvL1tfMigitationNotEnabled_LoadOption;
            DWORD HvL1tfMigitationNotEnabled_CoreScheduler;
            DWORD EnhancedIbrsReported;
            DWORD MdsHardwareProtected;
            DWORD MbClearEnabled;
            DWORD MbClearReported;
            DWORD Reserved;
        } __bitfield0;
    } SpeculationControlFlags;
}SYSTEM_SPECULATION_CONTROL_INFORMATION, * PSYSTEM_SPECULATION_CONTROL_INFORMATION;

typedef struct _SYSTEM_SYSTEM_DISK_INFORMATION
{
    UNICODE_STRING SystemDisk;
}SYSTEM_SYSTEM_DISK_INFORMATION, * PSYSTEM_SYSTEM_DISK_INFORMATION;

typedef struct _SYSTEM_SYSTEM_PARTITION_INFORMATION
{
    UNICODE_STRING SystemPartition;
}SYSTEM_SYSTEM_PARTITION_INFORMATION, * PSYSTEM_SYSTEM_PARTITION_INFORMATION;

typedef struct _SYSTEM_THREAD_CID_PRIORITY_INFORMATION
{
    struct _CLIENT_ID ClientId;
    LONG Priority;
}SYSTEM_THREAD_CID_PRIORITY_INFORMATION, * PSYSTEM_THREAD_CID_PRIORITY_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG TimeZoneId;
    ULONG Reserved;
    ULONGLONG BootTimeBias;
    ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, * PSYSTEM_TIMEOFDAY_INFORMATION;

typedef struct _SYSTEM_TPM_INFORMATION
{
    DWORD Flags;
}SYSTEM_TPM_INFORMATION, * PSYSTEM_TPM_INFORMATION;

typedef struct _SYSTEM_VA_LIST_INFORMATION
{
    QWORD VirtualSize;
    QWORD VirtualPeak;
    QWORD VirtualLimit;
    QWORD AllocationFailures;
}SYSTEM_VA_LIST_INFORMATION, * PSYSTEM_VA_LIST_INFORMATION;

typedef struct _SYSTEM_VDM_INSTEMUL_INFORMATION
{
    DWORD SegmentNotPresent;
    DWORD VdmOpcode0F;
    DWORD OpcodeESPrefix;
    DWORD OpcodeCSPrefix;
    DWORD OpcodeSSPrefix;
    DWORD OpcodeDSPrefix;
    DWORD OpcodeFSPrefix;
    DWORD OpcodeGSPrefix;
    DWORD OpcodeOPER32Prefix;
    DWORD OpcodeADDR32Prefix;
    DWORD OpcodeINSB;
    DWORD OpcodeINSW;
    DWORD OpcodeOUTSB;
    DWORD OpcodeOUTSW;
    DWORD OpcodePUSHF;
    DWORD OpcodePOPF;
    DWORD OpcodeINTnn;
    DWORD OpcodeINTO;
    DWORD OpcodeIRET;
    DWORD OpcodeINBimm;
    DWORD OpcodeINWimm;
    DWORD OpcodeOUTBimm;
    DWORD OpcodeOUTWimm;
    DWORD OpcodeINB;
    DWORD OpcodeINW;
    DWORD OpcodeOUTB;
    DWORD OpcodeOUTW;
    DWORD OpcodeLOCKPrefix;
    DWORD OpcodeREPNEPrefix;
    DWORD OpcodeREPPrefix;
    DWORD OpcodeHLT;
    DWORD OpcodeCLI;
    DWORD OpcodeSTI;
    DWORD BopCount;
}SYSTEM_VDM_INSTEMUL_INFORMATION, * PSYSTEM_VDM_INSTEMUL_INFORMATION;

typedef struct _SYSTEM_VERIFIER_ISSUE
{
    QWORD IssueType;
    PVOID Address;
    QWORD Parameters[0x2];
}SYSTEM_VERIFIER_ISSUE, * PSYSTEM_VERIFIER_ISSUE;

typedef struct _SYSTEM_VERIFIER_CANCELLATION_INFORMATION
{
    DWORD CancelProbability;
    DWORD CancelThreshold;
    DWORD CompletionThreshold;
    DWORD CancellationVerifierDisabled;
    DWORD AvailableIssues;
    SYSTEM_VERIFIER_ISSUE Issues[0x80];
}SYSTEM_VERIFIER_CANCELLATION_INFORMATION, * PSYSTEM_VERIFIER_CANCELLATION_INFORMATION;

typedef struct _SYSTEM_VERIFIER_INFORMATION
{
    DWORD NextEntryOffset;
    DWORD Level;
    DWORD RuleClasses[0x2];
    DWORD TriageContext;
    union
    {
        struct
        {
            union
            {
                DWORD AreAllDriversBeingVerified;
                DWORD DisabledFromCrash;
                DWORD Spare;
            } __bitfield0;
        } Flags;
        DWORD Whole;
    } u1;
    UNICODE_STRING DriverName;
    DWORD RaiseIrqls;
    DWORD AcquireSpinLocks;
    DWORD SynchronizeExecutions;
    DWORD AllocationsAttempted;
    DWORD AllocationsSucceeded;
    DWORD AllocationsSucceededSpecialPool;
    DWORD AllocationsWithNoTag;
    DWORD TrimRequests;
    DWORD Trims;
    DWORD AllocationsFailed;
    DWORD AllocationsFailedDeliberately;
    DWORD Loads;
    DWORD Unloads;
    DWORD UnTrackedPool;
    DWORD CurrentPagedPoolAllocations;
    DWORD CurrentNonPagedPoolAllocations;
    DWORD PeakPagedPoolAllocations;
    DWORD PeakNonPagedPoolAllocations;
    QWORD PagedPoolUsageInBytes;
    QWORD NonPagedPoolUsageInBytes;
    QWORD PeakPagedPoolUsageInBytes;
    QWORD PeakNonPagedPoolUsageInBytes;
}SYSTEM_VERIFIER_INFORMATION, * PSYSTEM_VERIFIER_INFORMATION;

typedef struct _SYSTEM_VERIFIER_COUNTERS_INFORMATION
{
    SYSTEM_VERIFIER_INFORMATION Legacy;
    DWORD RaiseIrqls;
    DWORD AcquireSpinLocks;
    DWORD SynchronizeExecutions;
    DWORD AllocationsWithNoTag;
    DWORD AllocationsFailed;
    DWORD AllocationsFailedDeliberately;
    QWORD LockedBytes;
    QWORD PeakLockedBytes;
    QWORD MappedLockedBytes;
    QWORD PeakMappedLockedBytes;
    QWORD MappedIoSpaceBytes;
    QWORD PeakMappedIoSpaceBytes;
    QWORD PagesForMdlBytes;
    QWORD PeakPagesForMdlBytes;
    QWORD ContiguousMemoryBytes;
    QWORD PeakContiguousMemoryBytes;
    DWORD ExecutePoolTypes;
    DWORD ExecutePageProtections;
    DWORD ExecutePageMappings;
    DWORD ExecuteWriteSections;
    DWORD SectionAlignmentFailures;
    DWORD IATInExecutableSection;
}SYSTEM_VERIFIER_COUNTERS_INFORMATION, * PSYSTEM_VERIFIER_COUNTERS_INFORMATION;

typedef struct _SYSTEM_VERIFIER_FAULTS_INFORMATION
{
    DWORD Probability;
    DWORD MaxProbability;
    UNICODE_STRING PoolTags;
    UNICODE_STRING Applications;
}SYSTEM_VERIFIER_FAULTS_INFORMATION, * PSYSTEM_VERIFIER_FAULTS_INFORMATION;

typedef struct _SYSTEM_VERIFIER_INFORMATION_EX
{
    DWORD VerifyMode;
    DWORD OptionChanges;
    UNICODE_STRING PreviousBucketName;
    DWORD IrpCancelTimeoutMsec;
    DWORD VerifierExtensionEnabled;
    DWORD Reserved[0x1];
}SYSTEM_VERIFIER_INFORMATION_EX, * PSYSTEM_VERIFIER_INFORMATION_EX;

typedef struct _SYSTEM_VERIFIER_TRIAGE_INFORMATION
{
    DWORD ActionTaken;
    QWORD CrashData[0x5];
    DWORD VerifierMode;
    DWORD VerifierFlags;
    USHORT VerifierTargets[0x100];
}SYSTEM_VERIFIER_TRIAGE_INFORMATION, * PSYSTEM_VERIFIER_TRIAGE_INFORMATION;

typedef struct _SYSTEM_VHD_BOOT_INFORMATION
{
    UCHAR OsDiskIsVhd;
    DWORD OsVhdFilePathOffset;
    USHORT OsVhdParentVolume[0x1];
}SYSTEM_VHD_BOOT_INFORMATION, * PSYSTEM_VHD_BOOT_INFORMATION;

typedef struct _SYSTEM_VSM_PROTECTION_INFORMATION
{
    UCHAR DmaProtectionsAvailable;
    UCHAR DmaProtectionsInUse;
    UCHAR HardwareMbecAvailable;
    UCHAR ApicVirtualizationAvailable;
}SYSTEM_VSM_PROTECTION_INFORMATION, * PSYSTEM_VSM_PROTECTION_INFORMATION;

typedef enum _WATCHDOG_INFORMATION_CLASS // int32_t
{
    WdInfoTimeoutValue = 0x0,
    WdInfoResetTimer = 0x1,
    WdInfoStopTimer = 0x2,
    WdInfoStartTimer = 0x3,
    WdInfoTriggerAction = 0x4,
    WdInfoState = 0x5,
    WdInfoTriggerReset = 0x6,
    WdInfoNop = 0x7,
    WdInfoGeneratedLastReset = 0x8,
    WdInfoInvalid = 0x9
}WATCHDOG_INFORMATION_CLASS, * PWATCHDOG_INFORMATION_CLASS;

typedef struct _SYSTEM_WATCHDOG_TIMER_INFORMATION
{
    WATCHDOG_INFORMATION_CLASS WdInfoClass;
    DWORD DataValue;
}SYSTEM_WATCHDOG_TIMER_INFORMATION, * PSYSTEM_WATCHDOG_TIMER_INFORMATION;

typedef struct _SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
{
    QWORD WorkloadClass;
    QWORD CpuSets[0x1];
}SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION, * PSYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION;

typedef struct _SYSTEM_WRITE_CONSTRAINT_INFORMATION
{
    DWORD WriteConstraintPolicy;
    DWORD Reserved;
}SYSTEM_WRITE_CONSTRAINT_INFORMATION, * PSYSTEM_WRITE_CONSTRAINT_INFORMATION;

typedef enum _PROCESS_INFORMATION_CLASS
{
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG
    ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL (requires SeDebugPrivilege)
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
    ProcessAllowedCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets, // 80
    ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage,
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // since REDSTONE4 // 90
    ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since REDSTONE5
    ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation, // since 20H1 // 100
    ProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange, // since WIN11
    ProcessApplyStateChange,
    ProcessEnableOptionalXStateFeatures,
    ProcessAltPrefetchParam, // since 22H1
    ProcessAssignCpuPartitions,
    ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation, // PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT
    ProcessEffectivePagePriority, // q: ULONG
    MaxProcessInfoClass
} PROCESS_INFORMATION_CLASS, * PPROCESS_INFORMATION_CLASS;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    KAFFINITY AffinityMask;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION_WOW64
{
    NTSTATUS ExitStatus;
    ULONG64  PebBaseAddress;
    ULONG64  AffinityMask;
    KPRIORITY BasePriority;
    ULONG64  UniqueProcessId;
    ULONG64  InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_WOW64, * PPROCESS_BASIC_INFORMATION_WOW64;

typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION
{
    SIZE_T Size; // set to sizeof structure on input
    PROCESS_BASIC_INFORMATION BasicInfo;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG IsProtectedProcess : 1;
            ULONG IsWow64Process : 1;
            ULONG IsProcessDeleting : 1;
            ULONG IsCrossSessionCreate : 1;
            ULONG IsFrozen : 1;
            ULONG IsBackground : 1;
            ULONG IsStronglyNamed : 1;
            ULONG IsSecureProcess : 1;
            ULONG IsSubsystemProcess : 1;
            ULONG SpareBits : 23;
        };
    };
} PROCESS_EXTENDED_BASIC_INFORMATION, * PPROCESS_EXTENDED_BASIC_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION64
{
    LONG ExitStatus;
    DWORD Pad1;
    QWORD PebBaseAddress;
    QWORD AffinityMask;
    LONG BasePriority;
    DWORD Pad2;
    QWORD UniqueProcessId;
    QWORD InheritedFromUniqueProcessId;
}PROCESS_BASIC_INFORMATION64, * PPROCESS_BASIC_INFORMATION64;

typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION64
{
    QWORD Size;
    PROCESS_BASIC_INFORMATION64 BasicInfo;
    union
    {
        DWORD Flags;
        union
        {
            DWORD IsProtectedProcess;
            DWORD IsWow64Process;
            DWORD IsProcessDeleting;
            DWORD IsCrossSessionCreate;
            DWORD IsFrozen;
            DWORD IsBackground;
            DWORD IsStronglyNamed;
            DWORD IsSecureProcess;
            DWORD IsPicoProcess;
            DWORD SpareBits;
        } __bitfield56;
    } __inner2;
}PROCESS_EXTENDED_BASIC_INFORMATION64, * PPROCESS_EXTENDED_BASIC_INFORMATION64;

typedef enum _PROCESS_NAME_FORMAT // uint32_t
{
    PROCESS_NAME_WIN32 = 0x0,
    PROCESS_NAME_NATIVE = 0x1
}PROCESS_NAME_FORMAT, * PPROCESS_NAME_FORMAT;

typedef struct _PROCESS_PROTECTION_LEVEL_INFORMATION
{
    DWORD ProtectionLevel;
}PROCESS_PROTECTION_LEVEL_INFORMATION, * PPROCESS_PROTECTION_LEVEL_INFORMATION;

typedef enum _QUERY_USER_NOTIFICATION_STATE // int32_t
{
    QUNS_NOT_PRESENT = 0x1,
    QUNS_BUSY = 0x2,
    QUNS_RUNNING_D3D_FULL_SCREEN = 0x3,
    QUNS_PRESENTATION_MODE = 0x4,
    QUNS_ACCEPTS_NOTIFICATIONS = 0x5,
    QUNS_QUIET_TIME = 0x6,
    QUNS_APP = 0x7
}QUERY_USER_NOTIFICATION_STATE, * PQUERY_USER_NOTIFICATION_STATE;

typedef enum _QUEUE_STATUS_FLAGS // uint32_t
{
    QS_ALLEVENTS = 0x4bf,
    QS_ALLINPUT = 0x4ff,
    QS_ALLPOSTMESSAGE = 0x100,
    QS_HOTKEY = 0x80,
    QS_INPUT = 0x407,
    QS_KEY = 0x1,
    QS_MOUSE = 0x6,
    QS_MOUSEBUTTON = 0x4,
    QS_MOUSEMOVE = 0x2,
    QS_PAINT = 0x20,
    QS_POSTMESSAGE = 0x8,
    QS_RAWINPUT = 0x400,
    QS_SENDMESSAGE = 0x40,
    QS_TIMER = 0x10
}QUEUE_STATUS_FLAGS, * PQUEUE_STATUS_FLAGS;

typedef enum _THREAD_INFORMATION_CLASS
{
    ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
    ThreadTimes, // q: KERNEL_USER_TIMES
    ThreadPriority, // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
    ThreadBasePriority, // s: KPRIORITY
    ThreadAffinityMask, // s: KAFFINITY
    ThreadImpersonationToken, // s: HANDLE
    ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress, // q: ULONG_PTR
    ThreadZeroTlsCell, // s: ULONG // TlsIndex // 10
    ThreadPerformanceCount, // q: LARGE_INTEGER
    ThreadAmILastThread, // q: ULONG
    ThreadIdealProcessor, // s: ULONG
    ThreadPriorityBoost, // qs: ULONG
    ThreadSetTlsArrayAddress, // s: ULONG_PTR
    ThreadIsIoPending, // q: ULONG
    ThreadHideFromDebugger, // q: BOOLEAN; s: void
    ThreadBreakOnTermination, // qs: ULONG
    ThreadSwitchLegacyState, // s: void // NtCurrentThread // NPX/FPU
    ThreadIsTerminated, // q: ULONG // 20
    ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority, // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
    ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
    ThreadPagePriority, // qs: PAGE_PRIORITY_INFORMATION
    ThreadActualBasePriority, // s: LONG (requires SeIncreaseBasePriorityPrivilege)
    ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context, // qs: WOW64_CONTEX, ARM_NT_CONTEXT since 20H1
    ThreadGroupInformation, // qs: GROUP_AFFINITY // 30
    ThreadUmsInformation, // q: THREAD_UMS_INFORMATION
    ThreadCounterProfiling, // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
    ThreadIdealProcessorEx, // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
    ThreadCpuAccountingInformation, // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
    ThreadSuspendCount, // q: ULONG // since WINBLUE
    ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId, // q: GUID
    ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
    ThreadSelectedCpuSets,
    ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
    ThreadActualGroupAffinity, // q: GROUP_AFFINITY // since THRESHOLD2
    ThreadDynamicCodePolicyInfo, // q: ULONG; s: ULONG (NtCurrentThread)
    ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables
    ThreadWorkOnBehalfTicket, // RTL_WORK_ON_BEHALF_TICKET_EX
    ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ThreadDbgkWerReportActive, // s: ULONG; s: 0 disables, otherwise enables
    ThreadAttachContainer, // s: HANDLE (job object) // NtCurrentThread
    ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ThreadPowerThrottlingState, // POWER_THROTTLING_THREAD_STATE
    ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
    ThreadCreateStateChange, // since WIN11
    ThreadApplyStateChange,
    ThreadStrongerBadHandleChecks, // since 22H1
    ThreadEffectiveIoPriority, // q: IO_PRIORITY_HINT
    ThreadEffectivePagePriority, // q: ULONG
    MaxThreadInfoClass
} THREAD_INFORMATION_CLASS;

typedef struct _THREAD_BASIC_INFORMATION
{
    LONG ExitStatus;
    TEB* TebBaseAddress;
    CLIENT_ID ClientId;
    QWORD AffinityMask;
    LONG Priority;
    LONG BasePriority;
}THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef struct _THREAD_CYCLE_TIME_INFORMATION
{
    QWORD AccumulatedCycles;
    QWORD CurrentCycleCount;
}THREAD_CYCLE_TIME_INFORMATION, * PTHREAD_CYCLE_TIME_INFORMATION;

typedef struct _THREAD_LAST_SYSCALL_INFORMATION
{
    PVOID FirstArgument;
    USHORT SystemCallNumber;
    USHORT Pad[0x3];
    QWORD WaitTime;
}THREAD_LAST_SYSCALL_INFORMATION, * PTHREAD_LAST_SYSCALL_INFORMATION;

typedef struct _THREAD_NAME_INFORMATION
{
    UNICODE_STRING ThreadName;
}THREAD_NAME_INFORMATION, * PTHREAD_NAME_INFORMATION;

typedef enum _HARDWARE_COUNTER_TYPE // int32_t
{
    PMCCounter = 0x0,
    MaxHardwareCounterType = 0x1
}HARDWARE_COUNTER_TYPE, * PHARDWARE_COUNTER_TYPE;

typedef struct _COUNTER_READING
{
    HARDWARE_COUNTER_TYPE Type;
    DWORD Index;
    QWORD Start;
    QWORD Total;
}COUNTER_READING, * PCOUNTER_READING;

typedef struct _THREAD_PERFORMANCE_DATA
{
    USHORT Size;
    USHORT Version;
    PROCESSOR_NUMBER ProcessorNumber;
    DWORD ContextSwitches;
    DWORD HwCountersCount;
    QWORD volatile UpdateCount;
    QWORD WaitReasonBitMap;
    QWORD HardwareCounters;
    COUNTER_READING CycleTime;
    COUNTER_READING HwCounters[0x10];
}THREAD_PERFORMANCE_DATA, * PTHREAD_PERFORMANCE_DATA;

typedef struct _THREAD_PROFILING_INFORMATION
{
    QWORD HardwareCounters;
    DWORD Flags;
    DWORD Enable;
    THREAD_PERFORMANCE_DATA* PerformanceData;
}THREAD_PROFILING_INFORMATION, * PTHREAD_PROFILING_INFORMATION;

typedef struct _THREAD_TEB_INFORMATION
{
    PVOID TebInformation;
    USHORT TebOffset;
    USHORT BytesToRead;
}THREAD_TEB_INFORMATION, * PTHREAD_TEB_INFORMATION;

typedef struct _THREAD_TLS_INFORMATION
{
    USHORT Flags;
    union
    {
        PVOID NewTlsData;
        PVOID OldTlsData;
    } __inner1;
    PVOID ThreadId;
}THREAD_TLS_INFORMATION, * PTHREAD_TLS_INFORMATION;

typedef enum _THREAD_UMS_INFORMATION_COMMAND // int32_t
{
    UmsInformationCommandInvalid = 0x0,
    UmsInformationCommandAttach = 0x1,
    UmsInformationCommandDetach = 0x2,
    UmsInformationCommandQuery = 0x3
}THREAD_UMS_INFORMATION_COMMAND, * PTHREAD_UMS_INFORMATION_COMMAND;

typedef struct _RTL_UMS_COMPLETION_LIST
{
    SINGLE_LIST_ENTRY* ThreadListHead;
    PVOID CompletionEvent;
    DWORD CompletionFlags;
    SINGLE_LIST_ENTRY InternalListHead;
}RTL_UMS_COMPLETION_LIST, * PRTL_UMS_COMPLETION_LIST;

typedef struct _RTL_UMS_CONTEXT
{
    SINGLE_LIST_ENTRY Link;
    CONTEXT Context;
    PVOID Teb;
    PVOID UserContext;
    union
    {
        union
        {
            DWORD volatile ScheduledThread;
            DWORD volatile Suspended;
            DWORD volatile VolatileContext;
            DWORD volatile Terminated;
            DWORD volatile DebugActive;
            DWORD volatile RunningOnSelfThread;
            DWORD volatile DenyRunningOnSelfThread;
        } __bitfield1264;
        LONG volatile Flags;
    } __inner4;

    union
    {
        union
        {
            QWORD volatile KernelUpdateLock;
            QWORD volatile PrimaryClientID;
        } __bitfield1272;
        QWORD volatile ContextLock;
    } __inner5;
    struct RTL_UMS_CONTEXT* PrimaryUmsContext;
    DWORD SwitchCount;
    DWORD KernelYieldCount;
    DWORD MixedYieldCount;
    DWORD YieldCount;
}RTL_UMS_CONTEXT, * PRTL_UMS_CONTEXT;

typedef struct _THREAD_UMS_INFORMATION
{
    THREAD_UMS_INFORMATION_COMMAND Command;
    union
    {
        struct
        {
            RTL_UMS_COMPLETION_LIST* CompletionList;
            RTL_UMS_CONTEXT* UmsContext;
        } __inner0;
        DWORD Flags;
        union
        {
            DWORD IsUmsSchedulerThread;
            DWORD IsUmsWorkerThread;
        } __bitfield8;
    } __inner1;
}THREAD_UMS_INFORMATION, * PTHREAD_UMS_INFORMATION;

typedef struct _INITIAL_TEB
{
    struct
    {
        PVOID OldStackBase;
        PVOID OldStackLimit;
    } OldInitialTeb;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocationBase;
} INITIAL_TEB, * PINITIAL_TEB;

//Source: http://processhacker.sourceforge.net
typedef enum _FILE_INFORMATION_CLASS
{
    /*FileDirectoryInformation = 1, // FILE_DIRECTORY_INFORMATION
    FileFullDirectoryInformation, // FILE_FULL_DIR_INFORMATION
    FileBothDirectoryInformation, // FILE_BOTH_DIR_INFORMATION
    FileBasicInformation, // FILE_BASIC_INFORMATION
    FileStandardInformation, // FILE_STANDARD_INFORMATION
    FileInternalInformation, // FILE_INTERNAL_INFORMATION
    FileEaInformation, // FILE_EA_INFORMATION
    FileAccessInformation, // FILE_ACCESS_INFORMATION
    FileNameInformation, // FILE_NAME_INFORMATION
    FileRenameInformation, // FILE_RENAME_INFORMATION // 10
    FileLinkInformation, // FILE_LINK_INFORMATION
    FileNamesInformation, // FILE_NAMES_INFORMATION
    FileDispositionInformation, // FILE_DISPOSITION_INFORMATION
    FilePositionInformation, // FILE_POSITION_INFORMATION
    FileFullEaInformation, // FILE_FULL_EA_INFORMATION
    FileModeInformation, // FILE_MODE_INFORMATION
    FileAlignmentInformation, // FILE_ALIGNMENT_INFORMATION
    FileAllInformation, // FILE_ALL_INFORMATION
    FileAllocationInformation, // FILE_ALLOCATION_INFORMATION
    FileEndOfFileInformation, // FILE_END_OF_FILE_INFORMATION // 20
    FileAlternateNameInformation, // FILE_NAME_INFORMATION
    FileStreamInformation, // FILE_STREAM_INFORMATION
    FilePipeInformation, // FILE_PIPE_INFORMATION
    FilePipeLocalInformation, // FILE_PIPE_LOCAL_INFORMATION
    FilePipeRemoteInformation, // FILE_PIPE_REMOTE_INFORMATION
    FileMailslotQueryInformation, // FILE_MAILSLOT_QUERY_INFORMATION
    FileMailslotSetInformation, // FILE_MAILSLOT_SET_INFORMATION
    FileCompressionInformation, // FILE_COMPRESSION_INFORMATION
    FileObjectIdInformation, // FILE_OBJECTID_INFORMATION
    FileCompletionInformation, // FILE_COMPLETION_INFORMATION // 30
    FileMoveClusterInformation, // FILE_MOVE_CLUSTER_INFORMATION
    FileQuotaInformation, // FILE_QUOTA_INFORMATION
    FileReparsePointInformation, // FILE_REPARSE_POINT_INFORMATION
    FileNetworkOpenInformation, // FILE_NETWORK_OPEN_INFORMATION
    FileAttributeTagInformation, // FILE_ATTRIBUTE_TAG_INFORMATION
    FileTrackingInformation, // FILE_TRACKING_INFORMATION
    FileIdBothDirectoryInformation, // FILE_ID_BOTH_DIR_INFORMATION
    FileIdFullDirectoryInformation, // FILE_ID_FULL_DIR_INFORMATION
    FileValidDataLengthInformation, // FILE_VALID_DATA_LENGTH_INFORMATION
    FileShortNameInformation, // FILE_NAME_INFORMATION // 40
    FileIoCompletionNotificationInformation, // FILE_IO_COMPLETION_NOTIFICATION_INFORMATION // since VISTA
    FileIoStatusBlockRangeInformation, // FILE_IOSTATUSBLOCK_RANGE_INFORMATION
    FileIoPriorityHintInformation, // FILE_IO_PRIORITY_HINT_INFORMATION
    FileSfioReserveInformation, // FILE_SFIO_RESERVE_INFORMATION
    FileSfioVolumeInformation, // FILE_SFIO_VOLUME_INFORMATION
    FileHardLinkInformation, // FILE_LINKS_INFORMATION
    FileProcessIdsUsingFileInformation, // FILE_PROCESS_IDS_USING_FILE_INFORMATION
    FileNormalizedNameInformation, // FILE_NAME_INFORMATION
    FileNetworkPhysicalNameInformation, // FILE_NETWORK_PHYSICAL_NAME_INFORMATION
    FileIdGlobalTxDirectoryInformation, // FILE_ID_GLOBAL_TX_DIR_INFORMATION // since WIN7 // 50
    FileIsRemoteDeviceInformation, // FILE_IS_REMOTE_DEVICE_INFORMATION
    FileUnusedInformation,
    FileNumaNodeInformation, // FILE_NUMA_NODE_INFORMATION
    FileStandardLinkInformation, // FILE_STANDARD_LINK_INFORMATION
    FileRemoteProtocolInformation, // FILE_REMOTE_PROTOCOL_INFORMATION
    FileRenameInformationBypassAccessCheck, // (kernel-mode only); FILE_RENAME_INFORMATION // since WIN8
    FileLinkInformationBypassAccessCheck, // (kernel-mode only); FILE_LINK_INFORMATION
    FileVolumeNameInformation, // FILE_VOLUME_NAME_INFORMATION
    FileIdInformation, // FILE_ID_INFORMATION
    FileIdExtdDirectoryInformation, // FILE_ID_EXTD_DIR_INFORMATION
    FileReplaceCompletionInformation, // FILE_COMPLETION_INFORMATION // since WINBLUE
    FileHardLinkFullIdInformation, // FILE_LINK_ENTRY_FULL_ID_INFORMATION
    FileIdExtdBothDirectoryInformation, // FILE_ID_EXTD_BOTH_DIR_INFORMATION // since THRESHOLD
    FileDispositionInformationEx, // FILE_DISPOSITION_INFO_EX // since REDSTONE
    FileRenameInformationEx,
    FileRenameInformationExBypassAccessCheck,
    FileDesiredStorageClassInformation, // FILE_DESIRED_STORAGE_CLASS_INFORMATION // since REDSTONE2
    FileStatInformation, // FILE_STAT_INFORMATION
    FileMemoryPartitionInformation = 0x45,
    FileStatLxInformation = 0x46,
    FileCaseSensitiveInformation = 0x47,
    FileLinkInformationEx = 0x48,
    FileLinkInformationExBypassAccessCheck = 0x49,
    FileStorageReserveIdInformation = 0x4a,
    FileCaseSensitiveInformationForceAccessCheck = 0x4b,
    FileMaximumInformation = 0x4c*/
    FileDirectoryInformation = 0x1,
    FileFullDirectoryInformation = 0x2,
    FileBothDirectoryInformation = 0x3,
    FileBasicInformation = 0x4,
    FileStandardInformation = 0x5,
    FileInternalInformation = 0x6,
    FileEaInformation = 0x7,
    FileAccessInformation = 0x8,
    FileNameInformation = 0x9,
    FileRenameInformation = 0xa,
    FileLinkInformation = 0xb,
    FileNamesInformation = 0xc,
    FileDispositionInformation = 0xd,
    FilePositionInformation = 0xe,
    FileFullEaInformation = 0xf,
    FileModeInformation = 0x10,
    FileAlignmentInformation = 0x11,
    FileAllInformation = 0x12,
    FileAllocationInformation = 0x13,
    FileEndOfFileInformation = 0x14,
    FileAlternateNameInformation = 0x15,
    FileStreamInformation = 0x16,
    FilePipeInformation = 0x17,
    FilePipeLocalInformation = 0x18,
    FilePipeRemoteInformation = 0x19,
    FileMailslotQueryInformation = 0x1a,
    FileMailslotSetInformation = 0x1b,
    FileCompressionInformation = 0x1c,
    FileObjectIdInformation = 0x1d,
    FileCompletionInformation = 0x1e,
    FileMoveClusterInformation = 0x1f,
    FileQuotaInformation = 0x20,
    FileReparsePointInformation = 0x21,
    FileNetworkOpenInformation = 0x22,
    FileAttributeTagInformation = 0x23,
    FileTrackingInformation = 0x24,
    FileIdBothDirectoryInformation = 0x25,
    FileIdFullDirectoryInformation = 0x26,
    FileValidDataLengthInformation = 0x27,
    FileShortNameInformation = 0x28,
    FileIoCompletionNotificationInformation = 0x29,
    FileIoStatusBlockRangeInformation = 0x2a,
    FileIoPriorityHintInformation = 0x2b,
    FileSfioReserveInformation = 0x2c,
    FileSfioVolumeInformation = 0x2d,
    FileHardLinkInformation = 0x2e,
    FileProcessIdsUsingFileInformation = 0x2f,
    FileNormalizedNameInformation = 0x30,
    FileNetworkPhysicalNameInformation = 0x31,
    FileIdGlobalTxDirectoryInformation = 0x32,
    FileIsRemoteDeviceInformation = 0x33,
    FileUnusedInformation = 0x34,
    FileNumaNodeInformation = 0x35,
    FileStandardLinkInformation = 0x36,
    FileRemoteProtocolInformation = 0x37,
    FileRenameInformationBypassAccessCheck = 0x38,
    FileLinkInformationBypassAccessCheck = 0x39,
    FileVolumeNameInformation = 0x3a,
    FileIdInformation = 0x3b,
    FileIdExtdDirectoryInformation = 0x3c,
    FileReplaceCompletionInformation = 0x3d,
    FileHardLinkFullIdInformation = 0x3e,
    FileIdExtdBothDirectoryInformation = 0x3f,
    FileDispositionInformationEx = 0x40,
    FileRenameInformationEx = 0x41,
    FileRenameInformationExBypassAccessCheck = 0x42,
    FileDesiredStorageClassInformation = 0x43,
    FileStatInformation = 0x44,
    FileMemoryPartitionInformation = 0x45,
    FileStatLxInformation = 0x46,
    FileCaseSensitiveInformation = 0x47,
    FileLinkInformationEx = 0x48,
    FileLinkInformationExBypassAccessCheck = 0x49,
    FileStorageReserveIdInformation = 0x4a,
    FileCaseSensitiveInformationForceAccessCheck = 0x4b,
    FileMaximumInformation = 0x4c
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _FILE_BASIC_INFORMATION
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION
{
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION_EX
{
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
    BOOLEAN AlternateStream;
    BOOLEAN MetadataAttribute;
} FILE_STANDARD_INFORMATION_EX, * PFILE_STANDARD_INFORMATION_EX;

typedef struct _FILE_INTERNAL_INFORMATION
{
    LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, * PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION
{
    ULONG EaSize;
} FILE_EA_INFORMATION, * PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION
{
    ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, * PFILE_ACCESS_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION
{
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, * PFILE_POSITION_INFORMATION;

typedef struct _FILE_MODE_INFORMATION
{
    ULONG Mode;
} FILE_MODE_INFORMATION, * PFILE_MODE_INFORMATION;

typedef struct _FILE_ALIGNMENT_INFORMATION
{
    ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION, * PFILE_ALIGNMENT_INFORMATION;

typedef struct _FILE_NAME_INFORMATION
{
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, * PFILE_NAME_INFORMATION;

typedef struct _FILE_ALL_INFORMATION
{
    FILE_BASIC_INFORMATION BasicInformation;
    FILE_STANDARD_INFORMATION StandardInformation;
    FILE_INTERNAL_INFORMATION InternalInformation;
    FILE_EA_INFORMATION EaInformation;
    FILE_ACCESS_INFORMATION AccessInformation;
    FILE_POSITION_INFORMATION PositionInformation;
    FILE_MODE_INFORMATION ModeInformation;
    FILE_ALIGNMENT_INFORMATION AlignmentInformation;
    FILE_NAME_INFORMATION NameInformation;
} FILE_ALL_INFORMATION, * PFILE_ALL_INFORMATION;

typedef struct _FILE_ALLOCATION_INFORMATION
{
    LARGE_INTEGER AllocationSize;
}FILE_ALLOCATION_INFORMATION, * PFILE_ALLOCATION_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, * PFILE_NETWORK_OPEN_INFORMATION;

typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION
{
    ULONG FileAttributes;
    ULONG ReparseTag;
} FILE_ATTRIBUTE_TAG_INFORMATION, * PFILE_ATTRIBUTE_TAG_INFORMATION;

typedef struct _FILE_COMPRESSION_INFORMATION
{
    LARGE_INTEGER CompressedFileSize;
    USHORT CompressionFormat;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved[3];
} FILE_COMPRESSION_INFORMATION, * PFILE_COMPRESSION_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION
{
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, * PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_END_OF_FILE_INFORMATION
{
    LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, * PFILE_END_OF_FILE_INFORMATION;

typedef struct _FILE_FULL_EA_INFORMATION
{
    DWORD NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    WORD EaValueLength;
    char EaName[0x1];
}FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION
{
    DWORD NextEntryOffset;
    UCHAR EaNameLength;
    char EaName[0x1];
}FILE_GET_EA_INFORMATION, * PFILE_GET_EA_INFORMATION;

typedef struct _FILE_GET_QUOTA_INFORMATION
{
    DWORD NextEntryOffset;
    DWORD SidLength;
    SID Sid;
}FILE_GET_QUOTA_INFORMATION, * PFILE_GET_QUOTA_INFORMATION;

typedef struct _FILE_VOLUME_NAME_INFORMATION
{
    DWORD DeviceNameLength;
    WCHAR DeviceName[0x1];
}FILE_VOLUME_NAME_INFORMATION, * PFILE_VOLUME_NAME_INFORMATION;

typedef struct _FILESYSTEM_STATISTICS
{
    WORD FileSystemType;
    WORD Version;
    DWORD SizeOfCompleteStructure;
    DWORD UserFileReads;
    DWORD UserFileReadBytes;
    DWORD UserDiskReads;
    DWORD UserFileWrites;
    DWORD UserFileWriteBytes;
    DWORD UserDiskWrites;
    DWORD MetaDataReads;
    DWORD MetaDataReadBytes;
    DWORD MetaDataDiskReads;
    DWORD MetaDataWrites;
    DWORD MetaDataWriteBytes;
    DWORD MetaDataDiskWrites;
}FILESYSTEM_STATISTICS, * PFILESYSTEM_STATISTICS;

typedef struct _FILESYSTEM_STATISTICS_EX
{
    WORD FileSystemType;
    WORD Version;
    DWORD SizeOfCompleteStructure;
    QWORD UserFileReads;
    QWORD UserFileReadBytes;
    QWORD UserDiskReads;
    QWORD UserFileWrites;
    QWORD UserFileWriteBytes;
    QWORD UserDiskWrites;
    QWORD MetaDataReads;
    QWORD MetaDataReadBytes;
    QWORD MetaDataDiskReads;
    QWORD MetaDataWrites;
    QWORD MetaDataWriteBytes;
    QWORD MetaDataDiskWrites;
}FILESYSTEM_STATISTICS_EX, * PFILESYSTEM_STATISTICS_EX;

#define FLAGS_END_OF_FILE_INFO_EX_EXTEND_PAGING 0x00000001
#define FLAGS_END_OF_FILE_INFO_EX_NO_EXTRA_PAGING_EXTEND 0x00000002
#define FLAGS_END_OF_FILE_INFO_EX_TIME_CONSTRAINED 0x00000004
#define FLAGS_DELAY_REASONS_LOG_FILE_FULL 0x00000001
#define FLAGS_DELAY_REASONS_BITMAP_SCANNED 0x00000002

typedef struct _FILE_END_OF_FILE_INFORMATION_EX
{
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER PagingFileSizeInMM;
    LARGE_INTEGER PagingFileMaxSize;
    ULONG Flags;
} FILE_END_OF_FILE_INFORMATION_EX, * PFILE_END_OF_FILE_INFORMATION_EX;

#define FILE_LINK_REPLACE_IF_EXISTS 0x00000001 // since RS5
#define FILE_LINK_POSIX_SEMANTICS 0x00000002

#define FILE_LINK_SUPPRESS_STORAGE_RESERVE_INHERITANCE 0x00000008
#define FILE_LINK_NO_INCREASE_AVAILABLE_SPACE 0x00000010
#define FILE_LINK_NO_DECREASE_AVAILABLE_SPACE 0x00000020
#define FILE_LINK_PRESERVE_AVAILABLE_SPACE 0x00000030
#define FILE_LINK_IGNORE_READONLY_ATTRIBUTE 0x00000040
#define FILE_LINK_FORCE_RESIZE_TARGET_SR 0x00000080 // since 19H1
#define FILE_LINK_FORCE_RESIZE_SOURCE_SR 0x00000100
#define FILE_LINK_FORCE_RESIZE_SR 0x00000180

typedef struct _FILE_LINK_INFORMATION
{
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_INFORMATION, * PFILE_LINK_INFORMATION;

typedef struct _FILE_MOVE_CLUSTER_INFORMATION
{
    ULONG ClusterCount;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_MOVE_CLUSTER_INFORMATION, * PFILE_MOVE_CLUSTER_INFORMATION;

typedef struct _FILE_RENAME_INFORMATION
{
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, * PFILE_RENAME_INFORMATION;

#define FILE_RENAME_REPLACE_IF_EXISTS 0x00000001 // since REDSTONE
#define FILE_RENAME_POSIX_SEMANTICS 0x00000002
#define FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE 0x00000004 // since REDSTONE3
#define FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE 0x00000008 // since REDSTONE5
#define FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE 0x00000010
#define FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE 0x00000020
#define FILE_RENAME_PRESERVE_AVAILABLE_SPACE 0x00000030
#define FILE_RENAME_IGNORE_READONLY_ATTRIBUTE 0x00000040
#define FILE_RENAME_FORCE_RESIZE_TARGET_SR 0x00000080 // since 19H1
#define FILE_RENAME_FORCE_RESIZE_SOURCE_SR 0x00000100
#define FILE_RENAME_FORCE_RESIZE_SR 0x00000180

typedef struct _FILE_RENAME_INFORMATION_EX
{
    ULONG Flags;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION_EX, * PFILE_RENAME_INFORMATION_EX;

typedef struct _FILE_ID_EXTD_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    ULONG ReparsePointTag;
    FILE_ID_128 FileId;
    WCHAR FileName[1];
} FILE_ID_EXTD_DIR_INFORMATION, * PFILE_ID_EXTD_DIR_INFORMATION;

typedef struct _FILE_ID_EXTD_BOTH_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    ULONG ReparsePointTag;
    FILE_ID_128 FileId;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_ID_EXTD_BOTH_DIR_INFORMATION, * PFILE_ID_EXTD_BOTH_DIR_INFORMATION;

#define FILE_CS_FLAG_CASE_SENSITIVE_DIR     0x00000001

// private
typedef struct _FILE_CASE_SENSITIVE_INFORMATION
{
    ULONG Flags;
} FILE_CASE_SENSITIVE_INFORMATION, * PFILE_CASE_SENSITIVE_INFORMATION;

// private
typedef enum _FILE_KNOWN_FOLDER_TYPE
{
    KnownFolderNone,
    KnownFolderDesktop,
    KnownFolderDocuments,
    KnownFolderDownloads,
    KnownFolderMusic,
    KnownFolderPictures,
    KnownFolderVideos,
    KnownFolderOther,
    KnownFolderMax = 7
} FILE_KNOWN_FOLDER_TYPE;

// private
typedef struct _FILE_KNOWN_FOLDER_INFORMATION
{
    FILE_KNOWN_FOLDER_TYPE Type;
} FILE_KNOWN_FOLDER_INFORMATION, * PFILE_KNOWN_FOLDER_INFORMATION;

// NtQueryDirectoryFile types

typedef struct _FILE_DIRECTORY_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, * PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, * PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, * PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, * PFILE_NAMES_INFORMATION;

typedef struct _FILE_STAT_INFORMATION {
    LARGE_INTEGER FileId;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         FileAttributes;
    ULONG         ReparseTag;
    ULONG         NumberOfLinks;
    ACCESS_MASK   EffectiveAccess;
} FILE_STAT_INFORMATION, * PFILE_STAT_INFORMATION;

typedef enum _FILE_INFO_BY_HANDLE_CLASS // uint32_t
{
    FileBasicInfo = 0x0,
    FileStandardInfo = 0x1,
    FileNameInfo = 0x2,
    FileRenameInfo = 0x3,
    FileDispositionInfo = 0x4,
    FileAllocationInfo = 0x5,
    FileEndOfFileInfo = 0x6,
    FileStreamInfo = 0x7,
    FileCompressionInfo = 0x8,
    FileAttributeTagInfo = 0x9,
    FileIdBothDirectoryInfo = 0xa,
    FileIdBothDirectoryRestartInfo = 0xb,
    FileIoPriorityHintInfo = 0xc,
    FileRemoteProtocolInfo = 0xd,
    FileFullDirectoryInfo = 0xe,
    FileFullDirectoryRestartInfo = 0xf,
    FileStorageInfo = 0x10,
    FileAlignmentInfo = 0x11,
    FileIdInfo = 0x12,
    FileIdExtdDirectoryInfo = 0x13,
    FileIdExtdDirectoryRestartInfo = 0x14,
    FileDispositionInfoEx = 0x15,
    FileRenameInfoEx = 0x16,
    FileCaseSensitiveInfo = 0x17,
    FileNormalizedNameInfo = 0x18,
    MaximumFileInfoByHandleClass = 0x19
}FILE_INFO_BY_HANDLE_CLASS, * PFILE_INFO_BY_HANDLE_CLASS;

typedef struct _BY_HANDLE_FILE_INFORMATION
{
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD dwVolumeSerialNumber;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD nNumberOfLinks;
    DWORD nFileIndexHigh;
    DWORD nFileIndexLow;
}BY_HANDLE_FILE_INFORMATION, * PBY_HANDLE_FILE_INFORMATION;

typedef enum _ENUM_FILE_INFORMATION_CLASS //int32_t
{
    ENUM_FILE_ID_BOTH_DIR_INFO = 0x0,
    ENUM_FILE_BOTH_DIR_INFO = 0x1,
    ENUM_FILE_FULL_DIR_INFO = 0x2
}ENUM_FILE_INFORMATION_CLASS, * PENUM_FILE_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS //uint32_t
{
    ObjectBasicInformation = 0x0,
    ObjectNameInformation = 0x1,
    ObjectTypeInformation = 0x2,
    ObjectTypesInformation = 0x3,
    ObjectHandleFlagInformation = 0x4,
    ObjectSessionInformation = 0x5,
    ObjectSessionObjectInformation = 0x6,
    MaxObjectInfoClass = 0x7
}OBJECT_INFORMATION_CLASS, * POBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_TYPES_INFORMATION
{
    DWORD NumberOfTypes;
}OBJECT_TYPES_INFORMATION, * POBJECT_TYPES_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    DWORD TotalNumberOfObjects;
    DWORD TotalNumberOfHandles;
    DWORD TotalPagedPoolUsage;
    DWORD TotalNonPagedPoolUsage;
    DWORD TotalNamePoolUsage;
    DWORD TotalHandleTableUsage;
    DWORD HighWaterNumberOfObjects;
    DWORD HighWaterNumberOfHandles;
    DWORD HighWaterPagedPoolUsage;
    DWORD HighWaterNonPagedPoolUsage;
    DWORD HighWaterNamePoolUsage;
    DWORD HighWaterHandleTableUsage;
    DWORD InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    DWORD ValidAccessMask;
    UCHAR SecurityRequired;
    UCHAR MaintainHandleCount;
    UCHAR TypeIndex;
    char ReservedByte;
    DWORD PoolType;
    DWORD DefaultPagedPoolCharge;
    DWORD DefaultNonPagedPoolCharge;
}OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _SECURITY_QUALITY_OF_SERVICE
{
    DWORD Length;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    UCHAR ContextTrackingMode;
    UCHAR EffectiveOnly;
}SECURITY_QUALITY_OF_SERVICE, * PSECURITY_QUALITY_OF_SERVICE;

typedef struct _OBJECT_CREATE_INFORMATION
{
    DWORD Attributes;
    PVOID RootDirectory;           //maybe unicodestring
    char ProbeMode;
    DWORD PagedPoolCharge;
    DWORD NonPagedPoolCharge;
    DWORD SecurityDescriptorCharge;
    SECURITY_DESCRIPTOR* SecurityDescriptor;//PVOID
    SECURITY_QUALITY_OF_SERVICE* SecurityQos;
    SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;

}OBJECT_CREATE_INFORMATION, * POBJECT_CREATE_INFORMATION;

typedef struct _OBJECT_HANDLE_INFORMATION
{
    DWORD HandleAttributes;
    DWORD GrantedAccess;
}OBJECT_HANDLE_INFORMATION, * POBJECT_HANDLE_INFORMATION;

typedef enum _OBJECT_SECURITY_INFORMATION // uint32_t
{
    ATTRIBUTE_SECURITY_INFORMATION = 0x20,
    BACKUP_SECURITY_INFORMATION = 0x10000,
    DACL_SECURITY_INFORMATION = 0x4,
    GROUP_SECURITY_INFORMATION = 0x2,
    LABEL_SECURITY_INFORMATION = 0x10,
    OWNER_SECURITY_INFORMATION = 0x1,
    PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000,
    PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
    SACL_SECURITY_INFORMATION = 0x8,
    SCOPE_SECURITY_INFORMATION = 0x40,
    UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
    UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
}OBJECT_SECURITY_INFORMATION, * POBJECT_SECURITY_INFORMATION;

typedef enum _JOB_OBJECT_INFORMATION_CLASS // int32_t
{
    JobObjectBasicAccountingInformation = 0x1,
    JobObjectBasicLimitInformation = 0x2,
    JobObjectBasicProcessIdList = 0x3,
    JobObjectBasicUIRestrictions = 0x4,
    JobObjectSecurityLimitInformation = 0x5,
    JobObjectEndOfJobTimeInformation = 0x6,
    JobObjectAssociateCompletionPortInformation = 0x7,
    JobObjectBasicAndIoAccountingInformation = 0x8,
    JobObjectExtendedLimitInformation = 0x9,
    JobObjectJobSetInformation = 0xa,
    JobObjectGroupInformation = 0xb,
    JobObjectNotificationLimitInformation = 0xc,
    JobObjectLimitViolationInformation = 0xd,
    JobObjectGroupInformationEx = 0xe,
    JobObjectCpuRateControlInformation = 0xf,
    JobObjectCompletionFilter = 0x10,
    JobObjectCompletionCounter = 0x11,
    JobObjectFreezeInformation = 0x12,
    JobObjectExtendedAccountingInformation = 0x13,
    JobObjectWakeInformation = 0x14,
    JobObjectBackgroundInformation = 0x15,
    JobObjectSchedulingRankBiasInformation = 0x16,
    JobObjectTimerVirtualizationInformation = 0x17,
    JobObjectCycleTimeNotification = 0x18,
    JobObjectClearEvent = 0x19,
    JobObjectInterferenceInformation = 0x1a,
    JobObjectClearPeakJobMemoryUsed = 0x1b,
    JobObjectMemoryUsageInformation = 0x1c,
    JobObjectSharedCommit = 0x1d,
    JobObjectContainerId = 0x1e,
    JobObjectIoRateControlInformation = 0x1f,
    JobObjectSiloRootDirectory = 0x25,
    JobObjectServerSiloBasicInformation = 0x26,
    JobObjectServerSiloUserSharedData = 0x27,
    JobObjectServerSiloInitialize = 0x28,
    JobObjectServerSiloRunningState = 0x29,
    JobObjectIoAttribution = 0x2a,
    JobObjectMemoryPartitionInformation = 0x2b,
    JobObjectContainerTelemetryId = 0x2c,
    JobObjectSiloSystemRoot = 0x2d,
    JobObjectEnergyTrackingState = 0x2e,
    JobObjectThreadImpersonationInformation = 0x2f,
    JobObjectReserved1Information = 0x12,
    JobObjectReserved2Information = 0x13,
    JobObjectReserved3Information = 0x14,
    JobObjectReserved4Information = 0x15,
    JobObjectReserved5Information = 0x16,
    JobObjectReserved6Information = 0x17,
    JobObjectReserved7Information = 0x18,
    JobObjectReserved8Information = 0x19,
    JobObjectReserved9Information = 0x1a,
    JobObjectReserved10Information = 0x1b,
    JobObjectReserved11Information = 0x1c,
    JobObjectReserved12Information = 0x1d,
    JobObjectReserved13Information = 0x1e,
    JobObjectReserved14Information = 0x1f,
    JobObjectNetRateControlInformation = 0x20,
    JobObjectNotificationLimitInformation2 = 0x21,
    JobObjectLimitViolationInformation2 = 0x22,
    JobObjectCreateSilo = 0x23,
    JobObjectSiloBasicInformation = 0x24,
    JobObjectReserved15Information = 0x25,
    JobObjectReserved16Information = 0x26,
    JobObjectReserved17Information = 0x27,
    JobObjectReserved18Information = 0x28,
    JobObjectReserved19Information = 0x29,
    JobObjectReserved20Information = 0x2a,
    JobObjectReserved21Information = 0x2b,
    JobObjectReserved22Information = 0x2c,
    JobObjectReserved23Information = 0x2d,
    JobObjectReserved24Information = 0x2e,
    JobObjectReserved25Information = 0x2f,
    MaxJobObjectInfoClass = 0x30
}JOB_OBJECT_INFORMATION_CLASS, * PJOB_OBJECT_INFORMATION_CLASS;

typedef struct _JOBOBJECT_ASSOCIATE_COMPLETION_PORT
{
    PVOID CompletionKey;
    PVOID CompletionPort;
}JOBOBJECT_ASSOCIATE_COMPLETION_PORT, * PJOBOBJECT_ASSOCIATE_COMPLETION_PORT;

typedef struct _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
{
    LARGE_INTEGER TotalUserTime;
    LARGE_INTEGER TotalKernelTime;
    LARGE_INTEGER ThisPeriodTotalUserTime;
    LARGE_INTEGER ThisPeriodTotalKernelTime;
    DWORD TotalPageFaultCount;
    DWORD TotalProcesses;
    DWORD ActiveProcesses;
    DWORD TotalTerminatedProcesses;
}JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, * PJOBOBJECT_BASIC_ACCOUNTING_INFORMATION;

typedef struct _IO_COUNTERS
{
    QWORD ReadOperationCount;
    QWORD WriteOperationCount;
    QWORD OtherOperationCount;
    QWORD ReadTransferCount;
    QWORD WriteTransferCount;
    QWORD OtherTransferCount;
}IO_COUNTERS, * PIO_COUNTERS;

typedef struct _JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION
{
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION BasicInfo;
    IO_COUNTERS IoInfo;
}JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION, * PJOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION;

typedef struct _JOBOBJECT_BASIC_LIMIT_INFORMATION
{
    LARGE_INTEGER PerProcessUserTimeLimit;
    LARGE_INTEGER PerJobUserTimeLimit;
    DWORD LimitFlags;
    QWORD MinimumWorkingSetSize;
    QWORD MaximumWorkingSetSize;
    DWORD ActiveProcessLimit;
    QWORD Affinity;
    DWORD PriorityClass;
    DWORD SchedulingClass;
}JOBOBJECT_BASIC_LIMIT_INFORMATION, * PJOBOBJECT_BASIC_LIMIT_INFORMATION;

typedef struct _JOBOBJECT_BASIC_PROCESS_ID_LIST
{
    DWORD NumberOfAssignedProcesses;
    DWORD NumberOfProcessIdsInList;
    QWORD ProcessIdList[0x1];
}JOBOBJECT_BASIC_PROCESS_ID_LIST, * PJOBOBJECT_BASIC_PROCESS_ID_LIST;

typedef struct _JOBOBJECT_BASIC_UI_RESTRICTIONS
{
    DWORD UIRestrictionsClass;
}JOBOBJECT_BASIC_UI_RESTRICTIONS, * PJOBOBJECT_BASIC_UI_RESTRICTIONS;

typedef struct _JOBOBJECT_CONTAINER_IDENTIFIER_V2
{
    GUID ContainerId;
    GUID ContainerTelemetryId;
    DWORD JobId;
}JOBOBJECT_CONTAINER_IDENTIFIER_V2, * PJOBOBJECT_CONTAINER_IDENTIFIER_V2;

typedef struct _JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
{
    DWORD ControlFlags;
    union
    {
        DWORD CpuRate;
        DWORD Weight;
        struct
        {
            WORD MinRate;
            WORD MaxRate;
        } __inner2;
    } __inner1;
}JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, * PJOBOBJECT_CPU_RATE_CONTROL_INFORMATION;

typedef struct _JOBOBJECT_END_OF_JOB_TIME_INFORMATION
{
    DWORD EndOfJobTimeAction;
}JOBOBJECT_END_OF_JOB_TIME_INFORMATION, * PJOBOBJECT_END_OF_JOB_TIME_INFORMATION;

typedef union _JOBOBJECT_ENERGY_TRACKING_STATE
{
    QWORD Value;
    struct
    {
        DWORD UpdateMask;
        DWORD DesiredState;
    } __inner1;
}JOBOBJECT_ENERGY_TRACKING_STATE, * PJOBOBJECT_ENERGY_TRACKING_STATE;

typedef struct _PROCESS_DISK_COUNTERS
{
    QWORD BytesRead;
    QWORD BytesWritten;
    QWORD ReadOperationCount;
    QWORD WriteOperationCount;
    QWORD FlushOperationCount;
}PROCESS_DISK_COUNTERS, * PPROCESS_DISK_COUNTERS;

typedef union _ENERGY_STATE_DURATION
{
    QWORD Value;
    struct
    {
        DWORD LastChangeTime;
        DWORD Duration;
    } __inner1;
    DWORD IsInState;
}ENERGY_STATE_DURATION, * PENERGY_STATE_DURATION;

typedef struct _PROCESS_ENERGY_VALUES
{
    QWORD Cycles[0x4][0x2];
    QWORD DiskEnergy;
    QWORD NetworkTailEnergy;
    QWORD MBBTailEnergy;
    QWORD NetworkTxRxBytes;
    QWORD MBBTxRxBytes;
    union
    {
        ENERGY_STATE_DURATION Durations[0x3];
        struct
        {
            ENERGY_STATE_DURATION ForegroundDuration;
            ENERGY_STATE_DURATION DesktopVisibleDuration;
            ENERGY_STATE_DURATION PSMForegroundDuration;
        } __inner1;
    } __inner6;
    DWORD CompositionRendered;
    DWORD CompositionDirtyGenerated;
    DWORD CompositionDirtyPropagated;
    DWORD Reserved1;
    QWORD AttributedCycles[0x4][0x2];
    QWORD WorkOnBehalfCycles[0x4][0x2];
}PROCESS_ENERGY_VALUES, * PPROCESS_ENERGY_VALUES;

typedef struct _JOBOBJECT_EXTENDED_ACCOUNTING_INFORMATION
{
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION BasicInfo;
    IO_COUNTERS IoInfo;
    PROCESS_DISK_COUNTERS DiskIoInfo;
    QWORD ContextSwitches;
    LARGE_INTEGER TotalCycleTime;
    QWORD ReadyTime;
    PROCESS_ENERGY_VALUES EnergyValues;
}JOBOBJECT_EXTENDED_ACCOUNTING_INFORMATION, * PJOBOBJECT_EXTENDED_ACCOUNTING_INFORMATION;

typedef struct _JOBOBJECT_EXTENDED_ACCOUNTING_INFORMATION_V2
{
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION BasicInfo;
    IO_COUNTERS IoInfo;
    PROCESS_DISK_COUNTERS DiskIoInfo;
    QWORD ContextSwitches;
    LARGE_INTEGER TotalCycleTime;
    QWORD ReadyTime;
    PROCESS_ENERGY_VALUES EnergyValues;
    QWORD KernelWaitTime;
    QWORD UserWaitTime;
}JOBOBJECT_EXTENDED_ACCOUNTING_INFORMATION_V2, * PJOBOBJECT_EXTENDED_ACCOUNTING_INFORMATION_V2;

typedef struct _JOBOBJECT_EXTENDED_LIMIT_INFORMATION
{
    JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
    IO_COUNTERS IoInfo;
    QWORD ProcessMemoryLimit;
    QWORD JobMemoryLimit;
    QWORD PeakProcessMemoryUsed;
    QWORD PeakJobMemoryUsed;
}JOBOBJECT_EXTENDED_LIMIT_INFORMATION, * PJOBOBJECT_EXTENDED_LIMIT_INFORMATION;

typedef struct _JOBOBJECT_EXTENDED_LIMIT_INFORMATION_V2
{
    JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
    IO_COUNTERS IoInfo;
    QWORD ProcessMemoryLimit;
    QWORD JobMemoryLimit;
    QWORD PeakProcessMemoryUsed;
    QWORD PeakJobMemoryUsed;
    QWORD JobTotalMemoryLimit;
}JOBOBJECT_EXTENDED_LIMIT_INFORMATION_V2, * PJOBOBJECT_EXTENDED_LIMIT_INFORMATION_V2;

typedef struct _JOBOBJECT_WAKE_FILTER
{
    DWORD HighEdgeFilter;
    DWORD LowEdgeFilter;
}JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER;

typedef struct _JOBOBJECT_FREEZE_INFORMATION
{
    union
    {
        DWORD Flags;
        union
        {
            DWORD FreezeOperation;
            DWORD FilterOperation;
            DWORD SwapOperation;
            DWORD Reserved;
        } __bitfield0;
    } __inner0;
    UCHAR Freeze;
    UCHAR Swap;
    UCHAR Reserved0[0x2];
    JOBOBJECT_WAKE_FILTER WakeFilter;
}JOBOBJECT_FREEZE_INFORMATION, * PJOBOBJECT_FREEZE_INFORMATION;

typedef struct _JOBOBJECT_INTERFERENCE_INFORMATION
{
    QWORD Count;
}JOBOBJECT_INTERFERENCE_INFORMATION, * PJOBOBJECT_INTERFERENCE_INFORMATION;

typedef struct _JOBOBJECT_IO_ATTRIBUTION_STATS
{
    QWORD IoCount;
    QWORD TotalNonOverlappedQueueTime;
    QWORD TotalNonOverlappedServiceTime;
    QWORD TotalSize;
}JOBOBJECT_IO_ATTRIBUTION_STATS, * PJOBOBJECT_IO_ATTRIBUTION_STATS;

typedef struct _JOBOBJECT_IO_ATTRIBUTION_INFORMATION
{
    DWORD ControlFlags;
    JOBOBJECT_IO_ATTRIBUTION_STATS ReadStats;
    JOBOBJECT_IO_ATTRIBUTION_STATS WriteStats;
}JOBOBJECT_IO_ATTRIBUTION_INFORMATION, * PJOBOBJECT_IO_ATTRIBUTION_INFORMATION;

typedef struct _JOBOBJECT_JOBSET_INFORMATION
{
    DWORD MemberLevel;
}JOBOBJECT_JOBSET_INFORMATION, * PJOBOBJECT_JOBSET_INFORMATION;

typedef enum _JOBOBJECT_RATE_CONTROL_TOLERANCE // int32_t
{
    ToleranceLow = 0x1,
    ToleranceMedium = 0x2,
    ToleranceHigh = 0x3
}JOBOBJECT_RATE_CONTROL_TOLERANCE, * PJOBOBJECT_RATE_CONTROL_TOLERANCE;

typedef enum _JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL // int32_t
{
    ToleranceIntervalShort = 0x1,
    ToleranceIntervalMedium = 0x2,
    ToleranceIntervalLong = 0x3
}JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL, * PJOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL;

typedef struct _JOBOBJECT_LIMIT_VIOLATION_INFORMATION
{
    DWORD LimitFlags;
    DWORD ViolationLimitFlags;
    QWORD IoReadBytes;
    QWORD IoReadBytesLimit;
    QWORD IoWriteBytes;
    QWORD IoWriteBytesLimit;
    LARGE_INTEGER PerJobUserTime;
    LARGE_INTEGER PerJobUserTimeLimit;
    QWORD JobMemory;
    QWORD JobMemoryLimit;
    JOBOBJECT_RATE_CONTROL_TOLERANCE RateControlTolerance;
    JOBOBJECT_RATE_CONTROL_TOLERANCE RateControlToleranceLimit;
}JOBOBJECT_LIMIT_VIOLATION_INFORMATION, * PJOBOBJECT_LIMIT_VIOLATION_INFORMATION;

typedef struct _JOBOBJECT_LIMIT_VIOLATION_INFORMATION_V2
{
    DWORD LimitFlags;
    DWORD ViolationLimitFlags;
    QWORD IoReadBytes;
    QWORD IoReadBytesLimit;
    QWORD IoWriteBytes;
    QWORD IoWriteBytesLimit;
    LARGE_INTEGER PerJobUserTime;
    LARGE_INTEGER PerJobUserTimeLimit;
    QWORD JobMemory;
    QWORD JobLowMemoryLimit;
    QWORD JobHighMemoryLimit;
    JOBOBJECT_RATE_CONTROL_TOLERANCE RateControlTolerance;
    JOBOBJECT_RATE_CONTROL_TOLERANCE RateControlToleranceLimit;
}JOBOBJECT_LIMIT_VIOLATION_INFORMATION_V2, * PJOBOBJECT_LIMIT_VIOLATION_INFORMATION_V2;

typedef struct _JOBOBJECT_MEMORY_USAGE_INFORMATION
{
    QWORD JobMemory;
    QWORD PeakJobMemoryUsed;
}JOBOBJECT_MEMORY_USAGE_INFORMATION, * PJOBOBJECT_MEMORY_USAGE_INFORMATION;

typedef struct _JOBOBJECT_MEMORY_USAGE_INFORMATION_V2
{
    JOBOBJECT_MEMORY_USAGE_INFORMATION BasicInfo;
    QWORD JobSharedMemory;
    QWORD Reserved[0x2];
}JOBOBJECT_MEMORY_USAGE_INFORMATION_V2, * PJOBOBJECT_MEMORY_USAGE_INFORMATION_V2;

typedef struct _JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION
{
    QWORD IoReadBytesLimit;
    QWORD IoWriteBytesLimit;
    LARGE_INTEGER PerJobUserTimeLimit;
    QWORD JobMemoryLimit;
    JOBOBJECT_RATE_CONTROL_TOLERANCE RateControlTolerance;
    JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL RateControlToleranceInterval;
    DWORD LimitFlags;

}JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION, * PJOBOBJECT_NOTIFICATION_LIMIT_INFORMATION;

typedef struct _JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_V2
{
    QWORD IoReadBytesLimit;
    QWORD IoWriteBytesLimit;
    LARGE_INTEGER PerJobUserTimeLimit;
    QWORD JobLowMemoryLimit;
    QWORD JobHighMemoryLimit;
    JOBOBJECT_RATE_CONTROL_TOLERANCE RateControlTolerance;
    JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL RateControlToleranceInterval;
    DWORD LimitFlags;

}JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_V2, * PJOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_V2;

typedef struct _JOBOBJECT_SECURITY_LIMIT_INFORMATION
{
    DWORD SecurityLimitFlags;
    PVOID JobToken;
    TOKEN_GROUPS* SidsToDisable;
    TOKEN_PRIVILEGES* PrivilegesToDelete;
    TOKEN_GROUPS* RestrictedSids;
}JOBOBJECT_SECURITY_LIMIT_INFORMATION, * PJOBOBJECT_SECURITY_LIMIT_INFORMATION;

typedef struct _JOBOBJECT_WAKE_INFORMATION
{
    QWORD NotificationChannel;
    QWORD WakeCounters[0x7];
}JOBOBJECT_WAKE_INFORMATION, * PJOBOBJECT_WAKE_INFORMATION;

typedef struct _JOBOBJECT_WAKE_INFORMATION_V1
{
    QWORD NotificationChannel;
    QWORD WakeCounters[0x4];
}JOBOBJECT_WAKE_INFORMATION_V1, * PJOBOBJECT_WAKE_INFORMATION_V1;

typedef enum _TRACE_INFORMATION_CLASS // int32_t
{
    TraceIdClass = 0x0,
    TraceHandleClass = 0x1,
    TraceEnableFlagsClass = 0x2,
    TraceEnableLevelClass = 0x3,
    GlobalLoggerHandleClass = 0x4,
    EventLoggerHandleClass = 0x5,
    AllLoggerHandlesClass = 0x6,
    TraceHandleByNameClass = 0x7,
    LoggerEventsLostClass = 0x8,
    TraceSessionSettingsClass = 0x9,
    LoggerEventsLoggedClass = 0xa,
    DiskIoNotifyRoutinesClass = 0xb,
    TraceInformationClassReserved1 = 0xc,
    AllPossibleNotifyRoutinesClass = 0xc,
    FltIoNotifyRoutinesClass = 0xd,
    TraceInformationClassReserved2 = 0xe,
    WdfNotifyRoutinesClass = 0xf,
    MaxTraceInformationClass = 0x10
}TRACE_INFORMATION_CLASS, * PTRACE_INFORMATION_CLASS;

typedef enum _FS_INFORMATION_CLASS // int32_t
{
    FileFsVolumeInformation = 0x1,
    FileFsLabelInformation = 0x2,
    FileFsSizeInformation = 0x3,
    FileFsDeviceInformation = 0x4,
    FileFsAttributeInformation = 0x5,
    FileFsControlInformation = 0x6,
    FileFsFullSizeInformation = 0x7,
    FileFsObjectIdInformation = 0x8,
    FileFsDriverPathInformation = 0x9,
    FileFsVolumeFlagsInformation = 0xa,
    FileFsSectorSizeInformation = 0xb,
    FileFsDataCopyInformation = 0xc,
    FileFsMetadataSizeInformation = 0xd,
    FileFsFullSizeInformationEx = 0xe,
    FileFsMaximumInformation = 0xf
}FS_INFORMATION_CLASS, * PFS_INFORMATION_CLASS;

typedef struct _FILE_FS_ATTRIBUTE_INFORMATION
{
    DWORD FileSystemAttributes;
    LONG MaximumComponentNameLength;
    DWORD FileSystemNameLength;
    PWSTR FileSystemName[0x1];
}FILE_FS_ATTRIBUTE_INFORMATION, * PFILE_FS_ATTRIBUTE_INFORMATION;

typedef struct _FILE_FS_CONTROL_INFORMATION
{
    LARGE_INTEGER FreeSpaceStartFiltering;
    LARGE_INTEGER FreeSpaceThreshold;
    LARGE_INTEGER FreeSpaceStopFiltering;
    LARGE_INTEGER DefaultQuotaThreshold;
    LARGE_INTEGER DefaultQuotaLimit;
    DWORD FileSystemControlFlags;
}FILE_FS_CONTROL_INFORMATION, * PFILE_FS_CONTROL_INFORMATION;

typedef struct _FILE_FS_DATA_COPY_INFORMATION
{
    DWORD NumberOfCopies;
}FILE_FS_DATA_COPY_INFORMATION, * PFILE_FS_DATA_COPY_INFORMATION;

typedef struct _FILE_FS_DEVICE_INFORMATION
{
    DWORD DeviceType;
    DWORD Characteristics;
}FILE_FS_DEVICE_INFORMATION, * PFILE_FS_DEVICE_INFORMATION;

typedef struct _FILE_FS_DRIVER_PATH_INFORMATION
{
    UCHAR DriverInPath;
    DWORD DriverNameLength;
    PWSTR DriverName[0x1];
}FILE_FS_DRIVER_PATH_INFORMATION, * PFILE_FS_DRIVER_PATH_INFORMATION;

typedef struct _FILE_FS_FULL_SIZE_INFORMATION
{
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER CallerAvailableAllocationUnits;
    LARGE_INTEGER ActualAvailableAllocationUnits;
    DWORD SectorsPerAllocationUnit;
    DWORD BytesPerSector;
}FILE_FS_FULL_SIZE_INFORMATION, * PFILE_FS_FULL_SIZE_INFORMATION;

typedef struct _FILE_FS_FULL_SIZE_INFORMATION_EX
{
    QWORD ActualTotalAllocationUnits;
    QWORD ActualAvailableAllocationUnits;
    QWORD ActualPoolUnavailableAllocationUnits;
    QWORD CallerTotalAllocationUnits;
    QWORD CallerAvailableAllocationUnits;
    QWORD CallerPoolUnavailableAllocationUnits;
    QWORD UsedAllocationUnits;
    QWORD TotalReservedAllocationUnits;
    QWORD VolumeStorageReserveAllocationUnits;
    QWORD AvailableCommittedAllocationUnits;
    QWORD PoolAvailableAllocationUnits;
    DWORD SectorsPerAllocationUnit;
    DWORD BytesPerSector;
}FILE_FS_FULL_SIZE_INFORMATION_EX, * PFILE_FS_FULL_SIZE_INFORMATION_EX;

typedef struct _FILE_FS_LABEL_INFORMATION
{
    DWORD VolumeLabelLength;
    PWSTR VolumeLabel[0x1];
}FILE_FS_LABEL_INFORMATION, * PFILE_FS_LABEL_INFORMATION;

typedef struct _FILE_FS_METADATA_SIZE_INFORMATION
{
    LARGE_INTEGER TotalMetadataAllocationUnits;
    DWORD SectorsPerAllocationUnit;
    DWORD BytesPerSector;
}FILE_FS_METADATA_SIZE_INFORMATION, * PFILE_FS_METADATA_SIZE_INFORMATION;

typedef struct _FILE_FS_OBJECTID_INFORMATION
{
    UCHAR ObjectId[0x10];
    UCHAR ExtendedInfo[0x30];
}FILE_FS_OBJECTID_INFORMATION, * PFILE_FS_OBJECTID_INFORMATION;

typedef struct _FILE_FS_PERSISTENT_VOLUME_INFORMATION
{
    DWORD VolumeFlags;
    DWORD FlagMask;
    DWORD Version;
    DWORD Reserved;
}FILE_FS_PERSISTENT_VOLUME_INFORMATION, * PFILE_FS_PERSISTENT_VOLUME_INFORMATION;

typedef struct _FILE_FS_SECTOR_SIZE_INFORMATION
{
    DWORD LogicalBytesPerSector;
    DWORD PhysicalBytesPerSectorForAtomicity;
    DWORD PhysicalBytesPerSectorForPerformance;
    DWORD FileSystemEffectivePhysicalBytesPerSectorForAtomicity;
    DWORD Flags;
    DWORD ByteOffsetForSectorAlignment;
    DWORD ByteOffsetForPartitionAlignment;
}FILE_FS_SECTOR_SIZE_INFORMATION, * PFILE_FS_SECTOR_SIZE_INFORMATION;

typedef struct _FILE_FS_SIZE_INFORMATION
{
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER AvailableAllocationUnits;
    DWORD SectorsPerAllocationUnit;
    DWORD BytesPerSector;
}FILE_FS_SIZE_INFORMATION, * PFILE_FS_SIZE_INFORMATION;

typedef struct _FILE_FS_VOLUME_FLAGS_INFORMATION
{
    DWORD Flags;
}FILE_FS_VOLUME_FLAGS_INFORMATION, * PFILE_FS_VOLUME_FLAGS_INFORMATION;

typedef struct _FILE_FS_VOLUME_INFORMATION
{
    LARGE_INTEGER VolumeCreationTime;
    DWORD VolumeSerialNumber;
    DWORD VolumeLabelLength;
    UCHAR SupportsObjects;
    PWSTR VolumeLabel[0x1];
}FILE_FS_VOLUME_INFORMATION, * PFILE_FS_VOLUME_INFORMATION;

typedef enum _HEAP_INFORMATION_CLASS // int32_t
{
    HeapCompatibilityInformation = 0x0,
    HeapEnableTerminationOnCorruption = 0x1,
    HeapExtendedInformation = 0x2,
    HeapOptimizeResources = 0x3,
    HeapTaggingInformation = 0x4,
    HeapStackDatabase = 0x5,
    HeapMemoryLimit = 0x6,
    HeapDetailedFailureInformation = -0x7fffffff,
    HeapSetDebuggingInformation = -0x7ffffffe
}HEAP_INFORMATION_CLASS, * PHEAP_INFORMATION_CLASS;

typedef enum _HEAP_FLAGS
{
    HEAP_NONE = 0x0,
    HEAP_NO_SERIALIZE = 0x1,
    HEAP_GROWABLE = 0x2,
    HEAP_GENERATE_EXCEPTIONS = 0x4,
    HEAP_ZERO_MEMORY = 0x8,
    HEAP_REALLOC_IN_PLACE_ONLY = 0x10,
    HEAP_TAIL_CHECKING_ENABLED = 0x20,
    HEAP_FREE_CHECKING_ENABLED = 0x40,
    HEAP_DISABLE_COALESCE_ON_FREE = 0x80,
    HEAP_CREATE_ALIGN_16 = 0x10000,
    HEAP_CREATE_ENABLE_TRACING = 0x20000,
    HEAP_CREATE_ENABLE_EXECUTE = 0x40000,
    HEAP_MAXIMUM_TAG = 0xfff,
    HEAP_PSEUDO_TAG_FLAG = 0x8000,
    HEAP_TAG_SHIFT = 0x12,
    HEAP_CREATE_SEGMENT_HEAP = 0x100,
    HEAP_CREATE_HARDENED = 0x200
}HEAP_FLAGS, * PHEAP_FLAGS;

typedef struct _HEAP_OPTIMIZE_RESOURCES_INFORMATION
{
    DWORD Version;
    DWORD Flags;
}HEAP_OPTIMIZE_RESOURCES_INFORMATION, * PHEAP_OPTIMIZE_RESOURCES_INFORMATION;

typedef struct _SEGMENT_HEAP_PERFORMANCE_COUNTER_INFORMATION
{
    QWORD SegmentReserveSize;
    QWORD SegmentCommitSize;
    QWORD SegmentCount;
    QWORD AllocatedSize;
    QWORD LargeAllocReserveSize;
    QWORD LargeAllocCommitSize;
}SEGMENT_HEAP_PERFORMANCE_COUNTER_INFORMATION, * PSEGMENT_HEAP_PERFORMANCE_COUNTER_INFORMATION;

typedef struct _HEAP_PERFORMANCE_COUNTERS_INFORMATION
{
    DWORD Size;
    DWORD Version;
    DWORD HeapIndex;
    DWORD LastHeapIndex;
    QWORD BaseAddress;
    QWORD ReserveSize;
    QWORD CommitSize;
    DWORD SegmentCount;
    QWORD LargeUCRMemory;
    DWORD UCRLength;
    QWORD AllocatedSpace;
    QWORD FreeSpace;
    DWORD FreeListLength;
    DWORD Contention;
    DWORD VirtualBlocks;
    DWORD CommitRate;
    DWORD DecommitRate;
    SEGMENT_HEAP_PERFORMANCE_COUNTER_INFORMATION SegmentHeapPerfInformation;
}HEAP_PERFORMANCE_COUNTERS_INFORMATION, * PHEAP_PERFORMANCE_COUNTERS_INFORMATION;

typedef struct _HEAP_RANGE_INFORMATION
{
    QWORD Address;
    QWORD Size;
    DWORD Type;
    DWORD Protection;
    QWORD FirstBlockInformationOffset;
    QWORD NextRangeInformationOffset;
}HEAP_RANGE_INFORMATION, * PHEAP_RANGE_INFORMATION;

typedef struct _HEAP_REGION_INFORMATION
{
    QWORD Address;
    QWORD ReserveSize;
    QWORD CommitSize;
    QWORD FirstRangeInformationOffset;
    QWORD NextRegionInformationOffset;
}HEAP_REGION_INFORMATION, * PHEAP_REGION_INFORMATION;

typedef struct _HEAP_SUMMARY
{
    DWORD cb;
    QWORD cbAllocated;
    QWORD cbCommitted;
    QWORD cbReserved;
    QWORD cbMaxReserve;
}HEAP_SUMMARY, * PHEAP_SUMMARY;

typedef struct _HEAP_INFORMATION
{
    QWORD Address;
    DWORD Mode;
    QWORD ReserveSize;
    QWORD CommitSize;
    QWORD FirstRegionInformationOffset;
    QWORD NextHeapInformationOffset;
}HEAP_INFORMATION, * PHEAP_INFORMATION;

typedef struct _HEAP_BLOCK_EXTRA_INFORMATION
{
    UCHAR Next;
    DWORD Type;
    QWORD Size;
}HEAP_BLOCK_EXTRA_INFORMATION, * PHEAP_BLOCK_EXTRA_INFORMATION;

typedef struct _HEAP_BLOCK_INFORMATION
{
    QWORD Address;
    DWORD Flags;
    QWORD DataSize;
    QWORD OverheadSize;
    QWORD NextBlockInformationOffset;
}HEAP_BLOCK_INFORMATION, * PHEAP_BLOCK_INFORMATION;

typedef struct _HEAP_BLOCK_SETTABLE_INFORMATION
{
    QWORD Settable;
    WORD TagIndex;
    WORD AllocatorBackTraceIndex;
}HEAP_BLOCK_SETTABLE_INFORMATION, * PHEAP_BLOCK_SETTABLE_INFORMATION;

typedef struct _PROCESS_HEAP_INFORMATION
{
    QWORD ReserveSize;
    QWORD CommitSize;
    QWORD NumberOfHeaps;
    QWORD FirstHeapInformationOffset;
}PROCESS_HEAP_INFORMATION, * PPROCESS_HEAP_INFORMATION;

typedef struct _HEAP_INFORMATION_ITEM
{
    DWORD Level;
    QWORD Size;
    union
    {
        PROCESS_HEAP_INFORMATION ProcessHeapInformation;
        HEAP_INFORMATION HeapInformation;
        HEAP_REGION_INFORMATION HeapRegionInformation;
        HEAP_RANGE_INFORMATION HeapRangeInformation;
        HEAP_BLOCK_INFORMATION HeapBlockInformation;
        HEAP_PERFORMANCE_COUNTERS_INFORMATION HeapPerfInformation;
        QWORD DynamicStart;
    } __inner2;
}HEAP_INFORMATION_ITEM, * PHEAP_INFORMATION_ITEM;

typedef struct _HEAP_EXTENDED_INFORMATION
{
    PVOID Process;
    QWORD Heap;
    QWORD Level;
    LONG(*CallbackRoutine)(HEAP_INFORMATION_ITEM*, PVOID);
    PVOID CallbackContext;
    union
    {
        PROCESS_HEAP_INFORMATION ProcessHeapInformation;
        HEAP_INFORMATION HeapInformation;
    } __inner5;
}HEAP_EXTENDED_INFORMATION, * PHEAP_EXTENDED_INFORMATION;

typedef DWORD WINAPI CSRGETPROCESSID(VOID);
typedef CSRGETPROCESSID* LPCSRGETPROCESSID;

typedef NTSTATUS NTAPI DBGPRINT(
    PCSTR Format,                   //_In_z_ _Printf_format_string_ 
    ...
); typedef DBGPRINT* LPDBGPRINT;

/*
typedef NTSTATUS NTAPI LDRGETPROCEDUREADDRESS(
    HMODULE ModuleHandle,
    CHAR* FunctionName,
    WORD Oridinal,
    PVOID* FunctionAddress
); typedef LDRGETPROCEDUREADDRESS* LPLDRGETPROCEDUREADDRESS;
*/
typedef NTSTATUS NTAPI LDRGETPROCEDUREADDRESS(
    PVOID DllHandle,                                                //_In_
    PANSI_STRING ProcedureName,                                     //_In_opt_
    ULONG ProcedureNumber,                                          //_In_opt_
    PVOID* ProcedureAddress                                         //_Out_
); typedef LDRGETPROCEDUREADDRESS* LPLDRGETPROCEDUREADDRESS;

typedef NTSTATUS NTAPI LDRLOADDLL(
    PWSTR SearchPathw,
    PULONG DllCharacteristics,
    PUNICODE_STRING DllName,
    PVOID* BaseAddress
); typedef LDRLOADDLL* LPLDRLOADDLL;

typedef NTSTATUS NTAPI NTALLOCATEVIRTUALMEMORY(
    HANDLE     ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR  ZeroBits,
    PSIZE_T    RegionSize,
    ULONG      AllocationType,
    ULONG      Protect
); typedef NTALLOCATEVIRTUALMEMORY* LPNTALLOCATEVIRTUALMEMORY;

typedef NTSTATUS NTAPI NTCLOSE(
    HANDLE Handle
); typedef NTCLOSE* LPNTCLOSE;

typedef NTSTATUS NTAPI NTCREATEPROCESS(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle
); typedef NTCREATEPROCESS* PNTCREATEPROCESS;

typedef NTSTATUS NTAPI NTCREATEPROCESSEX(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags, // PROCESS_CREATE_FLAGS_*
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle,
    ULONG Reserved // JobMemberLevel
); typedef NTCREATEPROCESSEX* PNTCREATEPROCESSEX;

typedef NTSTATUS NTAPI NTCREATESECTION(
    PHANDLE SectionHandle,                          //_Out_
    ACCESS_MASK DesiredAccess,                      //_In_
    POBJECT_ATTRIBUTES ObjectAttributes,            //_In_opt_
    PLARGE_INTEGER MaximumSize,                     //_In_opt_
    ULONG SectionPageProtection,                    //_In_
    ULONG AllocationAttributes,                     //_In_
    HANDLE FileHandle                               //_In_opt_
); typedef NTCREATESECTION* LPNTCREATESECTION;

typedef NTSTATUS NTAPI NTCREATESECTIONEX(
    PHANDLE SectionHandle,                          //_Out_
    ACCESS_MASK DesiredAccess,                      //_In_
    POBJECT_ATTRIBUTES ObjectAttributes,            //_In_opt_
    PLARGE_INTEGER MaximumSize,                     //_In_opt_
    ULONG SectionPageProtection,                    //_In_
    ULONG AllocationAttributes,                     //_In_
    HANDLE FileHandle,                              //_In_opt_
    PMEM_EXTENDED_PARAMETER ExtendedParameters,     //_Inout_updates_opt_(ExtendedParameterCount)
    ULONG ExtendedParameterCount                    //_In_
); typedef NTCREATESECTIONEX* LPNTCREATESECTIONEX;

typedef NTSTATUS NTAPI NTCREATETHREAD(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PCONTEXT ThreadContext,
    PINITIAL_TEB InitialTeb,
    BOOLEAN CreateSuspended
); typedef NTCREATETHREAD* PNTCREATETHREAD;

typedef NTSTATUS NTAPI NTCREATEUSERPROCESS(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList
); typedef NTCREATEUSERPROCESS* LPNTCREATEUSERPROCESS;

typedef NTSTATUS NTAPI NTDELETEFILE(
    POBJECT_ATTRIBUTES ObjectAttributes                 //_In_
); typedef NTDELETEFILE* LPNTDELETEFILE;

typedef NTSTATUS NTAPI NTEXTENDSECTION(
    HANDLE SectionHandle,                               //_In_                           
    PLARGE_INTEGER NewSectionSize                       //_Inout_
); typedef NTEXTENDSECTION* LPNTEXTENDSECTION;

typedef NTSTATUS NTAPI NTFREEVIRTUALMEMORY(
    HANDLE  ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType
); typedef NTFREEVIRTUALMEMORY* LPNTFREEVIRTUALMEMORY;

typedef NTSTATUS NTAPI NTGETCONTEXTTHREAD(
    HANDLE ThreadHandle,                                //_In_
    PCONTEXT ThreadContext                              //_Inout_
); typedef NTGETCONTEXTTHREAD* LPNTGETCONTEXTTHREAD;

typedef NTSTATUS NTAPI NTINITIATEPOWERACTION(
    POWER_ACTION SystemAction,                          //_In_
    SYSTEM_POWER_STATE LightestSystemState,             //_In_
    ULONG Flags, // POWER_ACTION_* flags                //_In_
    BOOLEAN Asynchronous                                //_In_
); typedef NTINITIATEPOWERACTION* LPNTINITIATEPOWERACTION;

typedef NTSTATUS NTAPI NTMAPVIEWOFSECTION(
    HANDLE SectionHandle,                               //_In_
    HANDLE ProcessHandle,                               //_In_
    PVOID* BaseAddress,                                 //_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) 
    ULONG_PTR ZeroBits,                                 //_In_
    SIZE_T CommitSize,                                  //_In_
    PLARGE_INTEGER SectionOffset,                       //_Inout_opt_
    PSIZE_T ViewSize,                                   //_Inout_
    SECTION_INHERIT InheritDisposition,                 //_In_
    ULONG AllocationType,                               //_In_
    ULONG Win32Protect                                  //_In_
); typedef NTMAPVIEWOFSECTION* LPNTMAPVIEWOFSECTION;

typedef NTSTATUS NTAPI NTMAPVIEWOFSECTIONEX(
    HANDLE SectionHandle,                               //_In_
    HANDLE ProcessHandle,                               //_In_
    PVOID* BaseAddress,                                 //_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) 
    PLARGE_INTEGER SectionOffset,                       //_Inout_opt_
    PSIZE_T ViewSize,                                   //_Inout_
    ULONG AllocationType,                               //_In_
    ULONG Win32Protect,                                 //_In_
    PMEM_EXTENDED_PARAMETER ExtendedParameters,         //_Inout_updates_opt_(ParameterCount) 
    ULONG ExtendedParameterCount                        //_In_
); typedef NTMAPVIEWOFSECTIONEX* LPNTMAPVIEWOFSECTIONEX;

typedef NTSTATUS NTAPI NTOPENFILE(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions
); typedef NTOPENFILE* LPNTOPENFILE;

typedef NTSTATUS NTAPI NTOPENPROCESS(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
); typedef NTOPENPROCESS* LPNTOPENPROCESS;

typedef NTSTATUS NTAPI NTPROTECTVIRTUALMEMORY(
    HANDLE                 ProcessHandle,
    PVOID* BaseAddress,
    PULONG                 NumberOfBytesToProtect,
    ULONG                  NewAccessProtection,
    PULONG                 OldAccessProtection
); typedef NTPROTECTVIRTUALMEMORY* LPNTPROTECTVIRTUALMEMORY;

typedef NTSTATUS NTAPI NTQUERYINFORMATIONBYNAME(
    POBJECT_ATTRIBUTES ObjectAttributes,                        //_In_
    PIO_STATUS_BLOCK IoStatusBlock,                             //_Out_
    PVOID FileInformation,                                      //_Out_writes_bytes_(Length)
    ULONG Length,                                               //_In_
    FILE_INFORMATION_CLASS FileInformationClass                 //_In_
); typedef NTQUERYINFORMATIONBYNAME* LPNTQUERYINFORMATIONBYNAME;

typedef NTSTATUS NTAPI NTQUERYINFORMATIONFILE(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass
); typedef NTQUERYINFORMATIONFILE* LPNTQUERYINFORMATIONFILE;

typedef NTSTATUS NTAPI NTQUERYINFORMATIONPROCESS(
    HANDLE                     ProcessHandle,
    PROCESS_INFORMATION_CLASS  ProcessInformationClass,
    PVOID                      ProcessInformation,
    ULONG                      ProcessInformationLength,
    PULONG                     ReturnLength
); typedef NTQUERYINFORMATIONPROCESS* LPNTQUERYINFORMATIONPROCESS;

typedef NTSTATUS NTAPI NTQUERYSYSTEMINFORMATION(
    SYSTEM_INFORMATION_CLASS       SystemInformationClass,
    PVOID                          SystemInformation,
    ULONG                          SystemInformationLength,
    PULONG                         ReturnLength
); typedef NTQUERYSYSTEMINFORMATION* LPNTQUERYSYSTEMINFORMATION;

typedef NTSTATUS NTAPI NTRAISEHARDERROR(
    NTSTATUS ErrorStatus,                           //_In_
    ULONG NumberOfParameters,                       //_In_
    ULONG UnicodeStringParameterMask,               //_In_
    PULONG_PTR Parameters,                          //_In_reads_(NumberOfParameters) 
    ULONG ValidResponseOptions,                     //_In_
    PULONG Response                                 //_Out_
); typedef NTRAISEHARDERROR* LPNTRAISEHARDERROR;

typedef NTSTATUS NTAPI NTREADFILE(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID            ApcRoutine,   //PIO_APC_ROUTINE//This parameter is reserved. Device and intermediate drivers should set this pointer to NULL.
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
); typedef NTREADFILE* LPNTREADFILE;

typedef NTSTATUS NTAPI  NTREMOVEPROCESSDEBUG(
    HANDLE ProcessHandle,                               //_In_
    HANDLE DebugObjectHandle                            //_In_
); typedef NTREMOVEPROCESSDEBUG* LPNTREMOVEPROCESSDEBUG;

typedef NTSTATUS NTAPI NTRESUMEPROCESS(
    HANDLE ProcessHandle
); typedef NTRESUMEPROCESS* PNTRESUMEPROCESS;

typedef NTSTATUS NTAPI NTSETCONTEXTTHREAD(
    HANDLE ThreadHandle,                                //_In_
    PCONTEXT ThreadContext //PCONTEXT(!WoW64)           //_In_
); typedef NTSETCONTEXTTHREAD* LPNTSETCONTEXTTHREAD;

typedef NTSTATUS NTAPI NTSETINFORMATIONFILE(
    HANDLE FileHandle,                                  //_In_
    PIO_STATUS_BLOCK IoStatusBlock,                     //_Out_
    PVOID FileInformation,                              //_In_reads_bytes_(Length)
    ULONG Length,                                       //_In_
    FILE_INFORMATION_CLASS FileInformationClass         //_In_
); typedef NTSETINFORMATIONFILE* LPNTSETINFORMATIONFILE;

typedef NTSTATUS NTAPI NTSETINFORMATIONPROCESS(
    HANDLE ProcessHandle,                               //_In_
    PROCESS_INFORMATION_CLASS ProcessInformationClass,  //_In_
    PVOID ProcessInformation,                           //_In_reads_bytes_(ProcessInformationLength) 
    ULONG ProcessInformationLength                      //_In_
); typedef NTSETINFORMATIONPROCESS* LPNTSETINFORMATIONPROCESS;

typedef NTSTATUS NTAPI NTSETSYSTEMPOWERSTATE(
    POWER_ACTION SystemAction,                          //_In_
    SYSTEM_POWER_STATE LightestSystemState,             //_In_
    ULONG Flags // POWER_ACTION_* flags                 //_In_
); typedef NTSETSYSTEMPOWERSTATE* LPNTSETSYSTEMPOWERSTATE;

typedef NTSTATUS NTAPI NTSETTHREADEXECUTIONSTATE(
    EXECUTION_STATE NewFlags, // ES_* flags             //_In_
    EXECUTION_STATE* PreviousFlags                      //_Out_
); typedef NTSETTHREADEXECUTIONSTATE* LPNTSETTHREADEXECUTIONSTATE;

typedef NTSTATUS NTAPI NTSHUTDOWNSYSTEM(
    SHUTDOWN_ACTION      Action                         //_In_
); typedef NTSHUTDOWNSYSTEM* LPNTSHUTDOWNSYSTEM;

typedef NTSTATUS NTAPI NTSUSPENDPROCESS(
    HANDLE ProcessHandle
); typedef NTSUSPENDPROCESS* PNTSUSPENDPROCESS;

typedef NTSTATUS NTAPI NTTERMINATEPROCESS(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
); typedef NTTERMINATEPROCESS* PNTTERMINATEPROCESS;

typedef NTSTATUS NTAPI NTUNMAPVIEWOFSECTION(
    HANDLE ProcessHandle,                               //_In_
    PVOID BaseAddress                                   //_In_opt_
); typedef NTUNMAPVIEWOFSECTION* LPNTUNMAPVIEWOFSECTION;

typedef NTSTATUS NTAPI NTUNMAPVIEWOFSECTIONEX(
    HANDLE ProcessHandle,                               //_In_
    PVOID BaseAddress,                                  //_In_opt_
    ULONG Flags                                         //_In_
); typedef NTUNMAPVIEWOFSECTIONEX* LPNTUNMAPVIEWOFSECTIONEX;

typedef NTSTATUS NTAPI NTWRITEVIRTUALMEMORY(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
); typedef NTWRITEVIRTUALMEMORY* LPNTWRITEVIRTUALMEMORY;

typedef NTSTATUS NTAPI RTLCREATEPROCESSPARAMETERSEX(
    PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,   //_Out_
    PUNICODE_STRING ImagePathName,                      //_In_
    PUNICODE_STRING DllPath,                            //_In_opt_
    PUNICODE_STRING CurrentDirectory,                   //_In_opt_
    PUNICODE_STRING CommandLine,                        //_In_opt_
    PVOID Environment,                                  //_In_opt_
    PUNICODE_STRING WindowTitle,                        //_In_opt_
    PUNICODE_STRING DesktopInfo,                        //_In_opt_
    PUNICODE_STRING ShellInfo,                          //_In_opt_
    PUNICODE_STRING RuntimeData,                        //_In_opt_
    ULONG Flags                                         //_In_
    //Flags : Pass RTL_USER_PROCESS_PARAMETERS_NORMALIZED to keep parameters normalized
); typedef RTLCREATEPROCESSPARAMETERSEX* LPRTLCREATEPROCESSPARAMETERSEX;

//call NtCreateUserProcess
typedef NTSTATUS NTAPI RTLCREATEUSERPROCESSEX(
    PUNICODE_STRING NtImagePathName,                                    //_In_
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,                     //_In_
    BOOLEAN InheritHandles,                                             //_In_
    PRTL_USER_PROCESS_EXTENDED_PARAMETERS ProcessExtendedParameters,    //_In_opt_
    PRTL_USER_PROCESS_INFORMATION ProcessInformation                    //_Out_
); typedef RTLCREATEUSERPROCESSEX* LPRTLCREATEUSERPROCESSEX;

typedef NTSTATUS NTAPI RTLACQUIREPRIVILEGE(
    PULONG Privilege,                                                   //_In_
    ULONG NumPriv,                                                      //_In_
    ULONG Flags,                                                        //_In_
    PVOID* ReturnedState                                                //_Out_
); typedef RTLACQUIREPRIVILEGE* LPRTLACQUIREPRIVILEGE;

#define RTL_ACQUIRE_PRIVILEGE_REVERT 0x00000001
#define RTL_ACQUIRE_PRIVILEGE_PROCESS 0x00000002

typedef NTSTATUS NTAPI RTLADJUSTPRIVILEGE(
    ULONG Privilege,                                                    //_In_
    BOOLEAN Enable,                                                     //_In_
    BOOLEAN Client,                                                     //_In_
    PBOOLEAN WasEnabled                                                 //_Out_
); typedef RTLADJUSTPRIVILEGE* LPRTLADJUSTPRIVILEGE;

typedef NTSTATUS NTAPI RTLINITANSISTRING(
    PANSI_STRING  DestinationString,                                    //_Out_ 
    PCSTR  SourceString                                                 //_In_opt_z_
); typedef RTLINITANSISTRING* LPRTLINITANSISTRING;

typedef NTSTATUS NTAPI RTLINITUNICODESTRING(
    PUNICODE_STRING DestinationString,                                  //_Out_
    PWSTR SourceString                                                  //_In_opt_z_
); typedef RTLINITUNICODESTRING* LPRTLINITUNICODESTRING;

typedef NTSTATUS NTAPI RTLREMOTECALL(
    HANDLE ProcessHandle,                                               //_In_
    HANDLE ThreadHandle,                                                //_In_
    PVOID CallSite,                                                     //_In_
    ULONG ArgumentCount,                                                //_In_
    PULONG_PTR Arguments,                                               //_In_opt_
    BOOLEAN PassContext,                                                //_In_
    BOOLEAN AlreadySuspended                                            //_In_
); typedef RTLREMOTECALL* PRTLREMOTECALL;

__forceinline WCHAR __cdecl ToLowerW(WCHAR ch)
{
    if (ch > 0x40 && ch < 0x5B)
    {
        return ch + 0x20;
    }
    return ch;
}

__forceinline char __cdecl ToLowerA(char ch)
{
    if (ch > 96 && ch < 123)
    {
        ch -= 32;
    }
    return ch;
}

__forceinline int __cdecl StringLengthA(char* str)
{
    int length;
    for (length = 0; str[length] != '\0'; length++) {}
    return length;
}

__forceinline int __cdecl StringLengthW(WCHAR* str) {
    int length;
    for (length = 0; str[length] != '\0'; length++) {}
    return length;
}

__forceinline BOOLEAN __cdecl CompareUnicode(PWSTR u1, PWSTR u2)
{
    for (int i = 0; i < StringLengthW(u1); i++)
    {
        if (ToLowerW(u1[i]) != ToLowerW(u2[i]))
            return FALSE;
    }
    return TRUE;
}

__forceinline BOOLEAN __cdecl CompareAnsi(char* u1, char* u2)
{
    for (int i = 0; i < StringLengthA(u1); i++)
    {
        if (ToLowerA(u1[i]) != ToLowerA(u2[i]))
            return FALSE;
    }
    return TRUE;
}

__forceinline char* __cdecl Separator(char* full_name)
{
    SIZE_T len = (SIZE_T)StringLengthA(full_name);

    for (SIZE_T i = 0; i < len; i++)
    {
        if (full_name[i] == '.')
        {
            return &full_name[i + 1];
        }
    }
    return NULL_PTR;
}

__forceinline BOOL __cdecl StringMatches(WCHAR* str1, WCHAR* str2)
{
    if (str1 == NULL_PTR || str2 == NULL_PTR || StringLengthW(str1) != StringLengthW(str2))
    {
        return FALSE;
    }

    for (int i = 0; str1[i] != '\0' && str2[i] != '\0'; i++)
    {
        if (ToLowerW(str1[i]) != ToLowerW(str2[i]))
        {
            return FALSE;
        }
    }
    return TRUE;
}

__forceinline BOOL __cdecl StringMatchesA(CHAR* str1, CHAR* str2)
{
    if (str1 == NULL_PTR || str2 == NULL_PTR || StringLengthA(str1) != StringLengthA(str2))
    {
        return FALSE;
    }

    for (int i = 0; str1[i] != '\0' && str2[i] != '\0'; i++)
    {
        if (ToLowerA(str1[i]) != ToLowerA(str2[i]))
        {
            return FALSE;
        }
    }
    return TRUE;
}


__forceinline LPVOID __cdecl NtCurrentPeb(void)
{
#if defined(_WIN64)
    UINT64 pPebLocation = __readgsqword(0x60);
    return (LPVOID)pPebLocation;
#else
    UINT32 pPebLocation = __readfsdword(0x30);
    return (LPVOID)pPebLocation;
#endif
}

__forceinline LPVOID __cdecl NtCurrentTIBOrTEB() {
#if defined(_WIN64)
    UINT64 pTibOrTEBLocation = __readgsqword(0x30);
    return (LPVOID)pTibOrTEBLocation;
#else
    UINT32 pTibOrTEBLocation = __readfsdword(0x18);
    return (LPVOID)pTibOrTEBLocation;
#endif
}

#if !defined(_WIN64)
__forceinline LPVOID __cdecl FastSysCallWoW64() {
    UINT32 wow64Transition = __readfsdword(0xC0);
    return (LPVOID)wow64Transition;
}
#endif

#define NtCurrentProcessId() (((PTEB)NtCurrentTIBOrTEB())->ClientId.UniqueProcess)
#define NtCurrentThreadId() (((PTEB)NtCurrentTIBOrTEB())->ClientId.UniqueThread)

__forceinline PVOID __cdecl GetModuleBaseAddress(PWSTR name)
{
    PPEB pPeb = (PPEB)NtCurrentPeb();
    PPEB_LDR_DATA pLdrData = (PPEB_LDR_DATA)pPeb->LdrData;

    for (PLDR_DATA_ENTRY pLdrDataEntry = (PLDR_DATA_ENTRY)pLdrData->InLoadOrderModuleList.Flink; pLdrDataEntry->BaseAddress != NULL_PTR; pLdrDataEntry = (PLDR_DATA_ENTRY)pLdrDataEntry->InLoadOrderModuleList.Flink)
    {
        if (CompareUnicode(name, pLdrDataEntry->BaseDllName.Buffer))
            return pLdrDataEntry->BaseAddress;
    }
    return NULL_PTR;
}

__forceinline LPVOID __cdecl GetProcedureAddressNt(char* sProcName)
{
    DWORD_PTR pBaseAddr = (DWORD_PTR)GetModuleBaseAddress(L"ntdll.dll\0");
    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
    IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

    DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
    DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
    WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

    if (((DWORD_PTR)sProcName >> 16) == 0)
    {
        WORD ordinal = (WORD)sProcName & 0xFFFF;
        DWORD Base = pExportDirAddr->Base;

        if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
            return NULL_PTR;

        return (PVOID)(pBaseAddr + (DWORD_PTR)pEAT[ordinal - Base]);
    }
    else
    {
        for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++)
        {
            char* sTmpFuncName = (char*)(pBaseAddr + (DWORD_PTR)pFuncNameTbl[i]);

            if (CompareAnsi(sProcName, sTmpFuncName) == TRUE)
            {
                return (LPVOID)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
            }
        }
    }
    return NULL;
}

__forceinline PVOID __cdecl MallocCustom(PSIZE_T size)
{
    LPNTALLOCATEVIRTUALMEMORY pNtAllocate = GetProcedureAddressNt("NtAllocateVirtualMemory\0");
    PVOID pAllocated = NULL_PTR;
    pNtAllocate((HANDLE)(-1), &pAllocated, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    return pAllocated;
}

__forceinline char* __cdecl ReverseSeparator(char* full_name)
{
    SIZE_T len = StringLengthA(full_name);

    int indexPoint = 5;//. d l l \0

    for (SIZE_T i = 0; i < len; i++)
    {
        if (full_name[i] == '.')
        {
            indexPoint += (int)i;
            break;
        }
    }
    DWORD_PTR size = (DWORD_PTR)((sizeof(char) * indexPoint));
    char* name = (char*)MallocCustom(&size);
    if (name != NULL_PTR)
    {
        for (int i = 0; i < indexPoint; i++)
            name[i] = full_name[i];

        name[indexPoint - 5] = '.';
        name[indexPoint - 4] = 'd';
        name[indexPoint - 3] = 'l';
        name[indexPoint - 2] = 'l';
        name[indexPoint - 1] = '\0';
        return name;
    }
    return NULL_PTR;
}

__forceinline WCHAR* __cdecl CharToWCharT(char* str)
{
    int length = StringLengthA(str);

    DWORD_PTR size = (DWORD_PTR)(sizeof(WCHAR) * length + 2);
    WCHAR* wStr = (WCHAR*)MallocCustom(&size);

    if (wStr != NULL_PTR)
    {
        for (int i = 0; i < length; i++)
        {
            wStr[i] = (WCHAR)(str[i]);
        }
        wStr[length] = '\0';
        return (WCHAR*)wStr;
    }
    return NULL_PTR;
}

//This function is a rework of function of Sektor7 Malware Development Intermediate Section 2. PE madness
//with https://github.com/arbiter34/GetProcAddress/blob/master/GetProcAddress/GetProcAddress.cpp
__forceinline LPVOID __cdecl GetProcedureAddress(HMODULE hMod, char* sProcName)
{
    LPNTFREEVIRTUALMEMORY pNtFree = GetProcedureAddressNt("NtFreeVirtualMemory\0");
    DWORD_PTR pBaseAddr = (DWORD_PTR)hMod;
    // get pointers to main headers/structures
    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
    IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

    // resolve addresses to Export Address Table, table of function names and "table of ordinals"
    DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
    DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
    WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

    // function address we're looking for
    // resolve function by ordinal
    if (((DWORD_PTR)sProcName >> 16) == 0)
    {
        WORD ordinal = (WORD)sProcName & 0xFFFF;	// convert to WORD
        DWORD Base = pExportDirAddr->Base;			// first ordinal number
        // check if ordinal is not out of scope
        if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
        {
            return NULL_PTR;
        }
        // get the function virtual address = RVA + BaseAddr
        return (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[ordinal - Base]);
    }
    else
    {    // resolve function by name
        // parse through table of function names
        for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++)
        {
            char* sTmpFuncName = (char*)(pBaseAddr + (DWORD_PTR)pFuncNameTbl[i]);

            if (CompareAnsi(sProcName, sTmpFuncName) == TRUE)
            {
                unsigned short NameOrdinal = ((unsigned short*)((unsigned long long)pBaseAddr + pExportDirAddr->AddressOfNameOrdinals))[i];
                unsigned int addr = ((unsigned int*)((unsigned long long)pBaseAddr + pExportDirAddr->AddressOfFunctions))[NameOrdinal];
                //Use Ordinal to Lookup Function Address and Calculate Absolute
                //if it's forwarded from another dll
                if (addr > pExportDataDir->VirtualAddress && addr < pExportDataDir->VirtualAddress + pExportDataDir->Size)
                {
                    //Grab and Parse Forward String
                    char* forwardStr = (char*)(pBaseAddr + addr);
                    char* funcName = Separator(forwardStr);
                    char* moduleName = ReverseSeparator(forwardStr);

                    SIZE_T size = ((SIZE_T)(StringLengthA(moduleName) * sizeof(WCHAR) + 2));
                    PWSTR moduleUnicode = MallocCustom(&size);
                    moduleUnicode = CharToWCharT(moduleName);
                    PVOID mod = GetModuleBaseAddress(moduleUnicode);

                    pNtFree((HANDLE)(-1), &moduleUnicode, &size, MEM_RELEASE);
                    size = ((SIZE_T)StringLengthA(moduleName));
                    pNtFree((HANDLE)(-1), &moduleName, &size, MEM_RELEASE);

                    return GetProcedureAddress((HMODULE)mod, funcName);
                }
                else
                {
                    return (LPVOID)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
                }
            }
        }
    }
    return NULL;
}

//Check signatures of a syscall at nt function address
//https://gist.github.com/wbenny/b08ef73b35782a1f57069dff2327ee4d
__forceinline BOOL __cdecl IsHookedNtDLL(LPVOID addressOfNtFunction)
{
    if (sizeof(void*) == 8)
    {
        /*
        4c 8b d1        mov r10, rcx
        b8 00 00 00 00  mov eax, 0x00
        */
        BYTE stub[] = "\x4c\x8b\xd1\xb8";
        for (int i = 0; i < 4; i++)
        {
            if (((PBYTE)addressOfNtFunction)[i] != stub[i])
            {
                return TRUE;
            }
        }
    }
    else
    {
        /*
        W10
        B8 00 00 00 00          mov eax, 0x0
        BA 00 00 00 00          mov edx, 0x0
        FF D2                   call edx
        C2 08 00                ret 0x08     //could be a C3

        W8
        B8 ?? ?? ?? ??          mov     eax, ??
        64 FF 15 C0 00 00 00    call    large dword ptr fs:0C0h
        [C2 ?? ?? | C3]         retn    [??]
        */
        BOOL maybe = FALSE;
        if (((PBYTE)addressOfNtFunction)[0] != ((BYTE)('\xb8')))
        {
            maybe = TRUE;
        }

        BOOL windows8CheckHooked = FALSE;

        if (((PBYTE)addressOfNtFunction)[5] != ((BYTE)('\x64'))
            || ((PBYTE)addressOfNtFunction)[6] != ((BYTE)('\xff'))
            || ((PBYTE)addressOfNtFunction)[7] != ((BYTE)('\x15'))
            || ((PBYTE)addressOfNtFunction)[8] != ((BYTE)('\xc0')))
        {
            windows8CheckHooked = TRUE;
        }

        BOOL windows10CheckHooked = FALSE;
        if (((PBYTE)addressOfNtFunction)[5] != ((BYTE)('\xBA'))
            || ((PBYTE)addressOfNtFunction)[10] != ((BYTE)('\xff'))
            || ((PBYTE)addressOfNtFunction)[11] != ((BYTE)('\xd2'))
            )
        {
            windows10CheckHooked = TRUE;
        }

        if (windows8CheckHooked && windows10CheckHooked)
        {
            return TRUE;
        }
    }
    return FALSE;
}

//This only works for x64. I don't have solution for WoW64 (x32 PE).
__forceinline CHAR* __cdecl PatchNTDllSection(NTSTATUS* n)
{
    //NTDLL path
#if defined(_WIN64)
    WCHAR filePath[] = L"\\??\\\\C:\\Windows\\System32\\ntdll.dll\0";
#else
    //this won't work
    WCHAR filePath[] = L"\\??\\\\C:\\Windows\\System32\\ntdll.dll\0";
    return (CHAR*)"NOT A x64 PE !";
#endif

    //Getting addresses of functions we need to use
    LPNTALLOCATEVIRTUALMEMORY pNtAllocate = GetProcedureAddressNt("NtAllocateVirtualMemory\0");
    LPRTLINITUNICODESTRING pRtlInitUnicode = GetProcedureAddressNt("RtlInitUnicodeString\0");
    LPNTOPENFILE pNtOpen = GetProcedureAddressNt("NtOpenFile\0");
    LPNTREADFILE pNtRead = GetProcedureAddressNt("NtReadFile\0");
    LPNTCLOSE pNtClose = GetProcedureAddressNt("NtClose\0");
    LPNTQUERYINFORMATIONFILE pNtQueryInformationFile = GetProcedureAddressNt("NtQueryInformationFile\0");
    LPNTWRITEVIRTUALMEMORY pNtWrite = GetProcedureAddressNt("NtWriteVirtualMemory\0");
    LPNTPROTECTVIRTUALMEMORY pNtProtect = GetProcedureAddressNt("NtProtectVirtualMemory\0");


    UNICODE_STRING object_name = { 0 };
    pRtlInitUnicode(&object_name, filePath);

    OBJECT_ATTRIBUTES attr = { 0 };
    attr.Length = sizeof(OBJECT_ATTRIBUTES);
    attr.RootDirectory = NULL_PTR;
    attr.ObjectName = &object_name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = NULL_PTR;
    attr.SecurityQualityOfService = NULL_PTR;
    IO_STATUS_BLOCK statusBlock = { 0 };
    HANDLE handle = NULL_PTR;

    //Getting a file handle to read the file
    *n = pNtOpen(&handle, GENERIC_READ | SYNCHRONIZE, &attr, &statusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT);

    if (*n != NT_SUCCESS)
    {
        return (CHAR*)"NtOpenFile failed !\0";
    }

    FILE_STANDARD_INFORMATION fileInfo = { 0 };

    //Query information to get file size and allocated a buffer
    *n = pNtQueryInformationFile(handle, &statusBlock, &fileInfo, sizeof(fileInfo), FileStandardInformation);

    if (*n != NT_SUCCESS)
    {
        return (CHAR*)"NtQuerySystemInformationFile failed !\0";
    }

    //Casting file size
#if defined(_WIN64)
    SIZE_T sizeFile = (SIZE_T)(fileInfo.EndOfFile.QuadPart + 1);
#else
    SIZE_T sizeFile = (SIZE_T)(fileInfo.EndOfFile.LowPart + 1);
#endif

    //Allocate our buffer
    BYTE* fileData = (BYTE*)MallocCustom(&sizeFile);
    LARGE_INTEGER liBytes = { 0 };

    //Read the file and put data in our buffer
#if defined(_WIN64)
    *n = pNtRead(handle, NULL_PTR, NULL_PTR, NULL_PTR, &statusBlock, fileData, (ULONG)(fileInfo.EndOfFile.QuadPart + 1), &liBytes, NULL_PTR);
#else
    * n = pNtRead(handle, NULL_PTR, NULL_PTR, NULL_PTR, &statusBlock, fileData, (ULONG)(fileInfo.EndOfFile.LowPart + 1), &liBytes, NULL_PTR);
#endif
    if (*n != NT_SUCCESS)
    {
        return (CHAR*)"NtReadFile failed !\0";
    }

    IMAGE_DOS_HEADER* pRawDosHeader = (IMAGE_DOS_HEADER*)fileData;
    IMAGE_NT_HEADERS* pRawNTHeader = (IMAGE_NT_HEADERS*)(((char*)pRawDosHeader) + pRawDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((DWORD_PTR)pRawNTHeader + 4 + sizeof(IMAGE_FILE_HEADER) + pRawNTHeader->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < pRawNTHeader->FileHeader.NumberOfSections; i++)// ++i
    {
        IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)((DWORD_PTR)sections + (i * sizeof(IMAGE_SECTION_HEADER)));

        //check if it is code section of raw PE
        if (CompareAnsi((char*)sec->Name, (char*)".text"))
        {
            PVOID ntdllAddress = GetModuleBaseAddress(L"ntdll.dll\0");
            PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllAddress;
            PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllAddress + hookedDosHeader->e_lfanew);
            IMAGE_SECTION_HEADER* sectionHooked = (IMAGE_SECTION_HEADER*)((DWORD_PTR)hookedNtHeader + 4 + sizeof(IMAGE_FILE_HEADER) + hookedNtHeader->FileHeader.SizeOfOptionalHeader);

            for (int j = 0; j < hookedNtHeader->FileHeader.NumberOfSections; j++)// ++i
            {
                IMAGE_SECTION_HEADER* hookedSectionHeader = (IMAGE_SECTION_HEADER*)((DWORD_PTR)sectionHooked + (j * sizeof(IMAGE_SECTION_HEADER)));

                //check if it is code section of mapped PE
                if (CompareAnsi((char*)hookedSectionHeader->Name, (char*)".text"))
                {
                    DWORD oldProtection = 0;
                    LPVOID addressToPatch = (LPVOID)((DWORD_PTR)ntdllAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress);
                    ULONG size = hookedSectionHeader->Misc.VirtualSize;

                    //Set protection page to write the section
                    *n = pNtProtect((HANDLE)(-1), &addressToPatch, &size, PAGE_EXECUTE_READWRITE, &oldProtection);

                    if (*n != NT_SUCCESS)
                    {
                        return (CHAR*)"NtProtectVirtualMemory 1 failed !\0";
                    }

                    ULONG writtenBytes = 0;

                    //Writting the section to ntdll loaded
                    *n = pNtWrite((HANDLE)(-1), (LPVOID)((DWORD_PTR)ntdllAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), fileData + sections[i].PointerToRawData, sections[i].SizeOfRawData, &writtenBytes);

                    if (*n != NT_SUCCESS && writtenBytes != sections[i].SizeOfRawData)
                    {
                        return (CHAR*)"NtWriteVirtualMemory failed !\0";
                    }
                    else
                    {
                        //Restoring old protection
                        *n = pNtProtect((HANDLE)(-1), &addressToPatch, &size, oldProtection, &oldProtection);

                        if (*n != NT_SUCCESS)
                        {
                            return (CHAR*)"NtProtectVirtualMemory 2 failed !\0";
                        }
                        return (CHAR*)"Success to patch section !\0";
                    }
                }
            }
        }
    }
    return (CHAR*)"Cannot find text section !";
}
