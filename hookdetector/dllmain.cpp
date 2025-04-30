#include <Windows.h>
#include "syscall.hpp"

#pragma comment(linker, "/ENTRY:DllMain")

#define MODULE_HASH_KERNEL32 0x1FED47BA
#define MODULE_HASH_USER32 0x9A138064
#define MODULE_HASH_NTDLL 0x48081EFB

#define PRINT(STR, ...) \
	if (1) { \
		LPWSTR buf = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024); \
		if (buf != NULL) { \
			int len = wsprintfW(buf, STR, __VA_ARGS__); \
			WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), buf, len, NULL, NULL); \
			HeapFree(GetProcessHeap(), 0, buf); \
		} \
	} \

// --- win internals

typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _UNICODE_STRING64 {
    USHORT  Length;
    USHORT  MaximumLength;
    DWORD64 Buffer;
} UNICODE_STRING64, * PUNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID      SectionPointer;
    ULONG      CheckSum;
    ULONG      TimeDateStamp;
    PVOID      LoadedImports;
    PVOID      EntryPointActivationContext;
    PVOID      PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

// --- nt functions

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _OBJECT_ATTRIBUTES64 {
    DWORD32         Length;
    DWORD64         RootDirectory;
    DWORD64         ObjectName;
    DWORD32         Attributes;
    DWORD64         SecurityDescriptor;
    DWORD64         SecurityQualityOfService;
} OBJECT_ATTRIBUTES64, *POBJECT_ATTRIBUTES64;

// ---

PEB* GetPEB() {
    PEB* peb = nullptr;
    __asm {
        mov eax, fs: [0x30]    // For x86 use fs:0x30, for x64 use gs:0x60
        mov peb, eax
    }
    return peb;
}

void memcpy(void* dst, void* src, UINT size)
{
    for (auto i = 0; i < size; ++i) {
        *(unsigned char*)((DWORD)dst + i) = *(unsigned char*)((DWORD)src + i);
    }
}

void* memset(void* dest, int c, size_t count)
{
    unsigned char* p = (unsigned char*)dest;
    while (count--)
        *p++ = (unsigned char)c;
    return dest;
}

UINT strcmpW(const wchar_t* a, const wchar_t* b)
{
    while (*a && (*a == *b)) {
        a++;
        b++;
    }

    return (UINT)(*a - *b);
}

void InitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
    SIZE_T length = 0;
    if (SourceString)
    {
        while (SourceString[length] != L'\0') {
            length++;
        }
    }

    DestinationString->Buffer = (PWSTR)SourceString;
    DestinationString->Length = (USHORT)(length * sizeof(WCHAR));
    DestinationString->MaximumLength = (USHORT)(DestinationString->Length + sizeof(WCHAR));
}

void InitUnicodeString64(PUNICODE_STRING64 DestinationString, PCWSTR SourceString)
{
    SIZE_T length = 0;
    if (SourceString)
    {
        while (SourceString[length] != L'\0') {
            length++;
        }
    }

    DestinationString->Buffer = (DWORD64)SourceString;
    DestinationString->Length = (USHORT)(length * sizeof(WCHAR));
    DestinationString->MaximumLength = (USHORT)(DestinationString->Length + sizeof(WCHAR));
}

UINT CalcHash(void* src, UINT size)
{
    UINT hash = 0x3f94ce13;

    for (auto i = 0; i < size; ++i) {
        const auto c = *(unsigned char*)((DWORD)src + i);
        hash = (hash >> 5) | (hash << (32 - 5));
        hash ^= c;
    }

    return hash;
}

HMODULE PebModuleHandle(UINT moduleHash)
{
    PEB* peb = GetPEB();
    if (!peb) {
        return 0;
    }

    PEB_LDR_DATA* ldrData = peb->Ldr;
    if (!ldrData) {
        return 0;
    }

    auto listEntry = peb->Ldr->InLoadOrderModuleList.Flink;
    do {
        const auto module = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        const auto hash = CalcHash(module->BaseDllName.Buffer, module->BaseDllName.Length);

        if (hash == moduleHash) {
            return (HMODULE)module->DllBase;
        }

        listEntry = listEntry->Flink;
    } while (listEntry != &peb->Ldr->InLoadOrderModuleList);

    return 0;
}

typedef bool(__stdcall* IterateProcCallback_t)(PVOID, const char*);
void IterateModuleProcs(HMODULE hModule, IterateProcCallback_t callback) {
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOSHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        const auto functionName = (char*)((BYTE*)hModule + pAddressOfNames[i]);
        if (callback((PVOID)((BYTE*)hModule + pAddressOfFunctions[pAddressOfNameOrdinals[i]]), functionName)) {
            return;
        }
    }
}

#ifdef _PRINT_MODULES
void PrintRealModules()
{
    const auto pKernel32 = GetModuleHandleA("KERNEL32.DLL");
    PRINT(L"KERNEL32.DLL - 0x%p\n", pKernel32);
    const auto pUser32 = GetModuleHandleA("user32.dll");
    PRINT(L"user32.dll - 0x%p\n", pUser32);
    const auto pNtDll = GetModuleHandleA("ntdll.dll");
    PRINT(L"ntdll.dll - 0x%p\n", pNtDll);
}
#endif

NTSTATUS SyscallNtOpenSection(PCWSTR sectionName, HANDLE* pOutHandle)
{
    STACK_ALIGN_TO_X64

    UNICODE_STRING64 uniName;
    InitUnicodeString64(&uniName, sectionName);

    OBJECT_ATTRIBUTES64 objAttr = { 0 };
    objAttr.Length = sizeof(objAttr);
    objAttr.ObjectName = (DWORD64)&uniName;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE;

    DWORD64 handle64 = NULL;
    const auto ret = syscall(0x37, MAKE_X64_PTR(handle64), SECTION_MAP_READ, MAKE_X64_PTR(objAttr));

    if (NT_SUCCESS(ret)) {
        *pOutHandle = (HANDLE)handle64;
    }

    return ret;
}

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

NTSTATUS SyscallNtMapViewOfSection(HANDLE hSection, PVOID* ppOutAddress)
{
    STACK_ALIGN_TO_X64

    DWORD64 viewSize = 0;
    DWORD64 sectionOffset = 0;
    DWORD64 zeroBits = 0;
    DWORD64 commitSize = 0;
    DWORD64 inherit = 1; // ViewShare
    DWORD64 allocType = 0;
    DWORD64 protect = PAGE_READONLY;

    DWORD64 processHandle = (DWORD64)-1;
    DWORD64 sectionHandle = (DWORD64)hSection;

    /*
  IN HANDLE               SectionHandle,
  IN HANDLE               ProcessHandle,
  IN OUT PVOID            *BaseAddress OPTIONAL,
  IN ULONG                ZeroBits OPTIONAL,
  IN ULONG                CommitSize,
  IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
  IN OUT PULONG           ViewSize,
  IN                      InheritDisposition,
  IN ULONG                AllocationType OPTIONAL,
  IN ULONG                Protect );
    */

    /*
    NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection");

    auto ret = NtMapViewOfSection(
        hSection,
        (HANDLE)-1,
        ppOutAddress,
        0,
        0,
        NULL,
        &viewSize,
        1, // ViewShare
        0,
        PAGE_READONLY
    );
    */

    const auto ret = syscall(
        0x28,
        sectionHandle,
        processHandle,
        X64_PTR(ppOutAddress),
        NULL,
        // ---
        protect,
        allocType,
        inherit,
        MAKE_X64_PTR(viewSize),
        sectionOffset,
        commitSize
    );

    return ret;
}

bool DetectHooks()
{
    STACK_ALIGN_TO_X64

#ifdef _PRINT_MODULES
    PrintRealModules();
#endif

    PRINT(L"We are loaded.\n");

    HANDLE handle = NULL;
    NTSTATUS ret = SyscallNtOpenSection(L"\\KnownDlls\\kernel32.dll", &handle);

    PRINT(L"RET: 0x%08X\n", ret);
    PRINT(L"hSection: 0x%08X\n", handle);

    PVOID baseAddress = NULL;
    ret = SyscallNtMapViewOfSection(handle, &baseAddress);

    if (ret == 0x40000003) {
        MessageBoxA(0, "Success", "Success", 0);
    }
    else {
        MessageBoxA(0, "Fail", "Fail", 0);
    }

    PRINT(L"RET: 0x%08X\n", ret);
    PRINT(L"baseAddress: 0x%08X\n", baseAddress);

    return false;


    const auto fnProcPrint = [](PVOID addr, const char* name) -> bool {
        wchar_t wname[256];
        MultiByteToWideChar(CP_ACP, 0, name, -1, wname, 256);
        PRINT(L"> %ws @ 0x%p\n", wname, addr);

        return false;
    };

    const auto pKernel32 = PebModuleHandle(MODULE_HASH_KERNEL32);
    PRINT(L"--- KERNEL32.DLL - 0x%p\n", pKernel32);
    IterateModuleProcs(pKernel32, fnProcPrint);
    const auto pUser32 = PebModuleHandle(MODULE_HASH_USER32);
    PRINT(L"--- user32.dll - 0x%p\n", pUser32);
    IterateModuleProcs(pUser32, fnProcPrint);
    const auto pNtDll = PebModuleHandle(MODULE_HASH_NTDLL);
    PRINT(L"--- ntdll.dll - 0x%p\n", pNtDll);
    IterateModuleProcs(pNtDll, fnProcPrint);

    // todo acquire syscall method to map sections

#ifdef _PRINT_MODULES
    const auto pGetModuleHandleA = GetProcAddress((HMODULE)pKernel32, "GetModuleHandleA");
    PRINT(L"GetModuleHandleA - 0x%p\n", pGetModuleHandleA);
    const auto pGetProcAddress = GetProcAddress((HMODULE)pKernel32, "GetProcAddress");
    PRINT(L"GetProcAddress - 0x%p\n", pGetProcAddress);
#endif

    return false;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        PRINT(L"Checking for API hooks in process...\n");
		if (DetectHooks()) {
			PRINT(L"API hooks found!\n");
		}
		else {
			PRINT(L"Process OK\n");
		}

        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
