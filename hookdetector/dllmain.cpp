#include <Windows.h>
#include "syscall.hpp"

#pragma comment(linker, "/ENTRY:DllMain")

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
        //PRINT(L"0x%p\n", ((DWORD)src + i));
        const auto c = *(unsigned char*)((DWORD)src + i);
        hash = (hash >> 5) | (hash << (32 - 5));
        hash ^= c;
    }

    return hash;
}

typedef bool(__stdcall* IterateModuleCallback_t)(HMODULE, ULONG, PWSTR);
void IteratePebModules(IterateModuleCallback_t callback)
{
    PEB* peb = GetPEB();
    if (!peb) {
        return;
    }

    PEB_LDR_DATA* ldrData = peb->Ldr;
    if (!ldrData) {
        return;
    }

    auto listEntry = peb->Ldr->InLoadOrderModuleList.Flink;
    do {
        const auto module = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (callback((HMODULE)module->DllBase, module->SizeOfImage, module->BaseDllName.Buffer)) {
            return;
        }

        listEntry = listEntry->Flink;
    } while (listEntry != &peb->Ldr->InLoadOrderModuleList);
}

typedef bool(__stdcall* IterateProcCallback_t)(PVOID, const char*, PVOID);
void IterateModuleProcs(HMODULE hModule, IterateProcCallback_t callback, PVOID pParam) {
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOSHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)hModule + pAddressOfNames[i]);
        PVOID functionStart = (PVOID)((BYTE*)hModule + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);

        if (callback(functionStart, functionName, pParam)) {
            return;
        }
    }
}

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
    NTSTATUS ret = syscall(0x37, MAKE_X64_PTR(handle64), SECTION_MAP_READ, MAKE_X64_PTR(objAttr));

if (NT_SUCCESS(ret)) {
    *pOutHandle = (HANDLE)handle64;
}

return ret;
}

NTSTATUS SyscallNtMapViewOfSection(HANDLE hSection, PVOID* ppOutAddress)
{
    STACK_ALIGN_TO_X64

        DWORD64 outBaseAddr64 = NULL;

    DWORD64 viewSize = 0;
    DWORD64 sectionOffset = 0;
    DWORD64 zeroBits = 0;
    DWORD64 commitSize = 0;
    DWORD64 inherit = 1; // ViewShare
    DWORD64 allocType = 0;
    DWORD64 protect = PAGE_READONLY;

    DWORD64 processHandle = (DWORD64)-1;
    DWORD64 sectionHandle = (DWORD64)hSection;

    NTSTATUS ret = syscall(
        0x28,
        sectionHandle,
        processHandle,
        MAKE_X64_PTR(outBaseAddr64),
        NULL,
        // ---
        protect,
        allocType,
        inherit,
        MAKE_X64_PTR(viewSize),
        sectionOffset,
        commitSize
    );

    if (outBaseAddr64) {
        *ppOutAddress = (PVOID)(DWORD)outBaseAddr64;
    }

    return ret;
}

PVOID MapKnownDll(const wchar_t* dllName)
{
    STACK_ALIGN_TO_X64

        wchar_t knownDllName[0x50];
    wsprintfW(knownDllName, L"\\KnownDlls32\\%ws", dllName);

    HANDLE handle = NULL;
    NTSTATUS ret = SyscallNtOpenSection(knownDllName, &handle);

    if (ret < 0) {
        return nullptr;
    }

    PVOID baseAddress = NULL;
    ret = SyscallNtMapViewOfSection(handle, &baseAddress);

    if (ret < 0) {
        return nullptr;
    }

    return baseAddress;
}

void DetectHooks()
{
    STACK_ALIGN_TO_X64

        const auto fnModuleIter = [](HMODULE module, ULONG size, PWSTR name) -> bool {
        PRINT(L"===================================================\n");
        PRINT(L"> %ws @ 0x%p, size: 0x%x\n", name, module, size);

        const auto knownDll = MapKnownDll(name);
        PRINT(L"> knownDll @ 0x%p\n", knownDll);
        if (!knownDll) {
            return false;
        }

        typedef struct {
            HMODULE module;
            PVOID knownDll;
            ULONG moduleSize;
        } procIter_t;
        procIter_t data{ module, knownDll, size };

        PRINT(L"> Iterating procedures...\n");
        const auto fnProcIter = [](PVOID fnStart, const char* name, PVOID pParam) -> bool {
            wchar_t wname[0x100];
            MultiByteToWideChar(CP_ACP, 0, name, -1, wname, 256);

            const auto data = (procIter_t*)pParam;
            const auto offset = (ULONG)fnStart - (ULONG)data->module;

            if ((ULONG)fnStart < (ULONG)data->module || offset > data->moduleSize) {
                return false;
            }

            const auto knownDllAddr = (PVOID)((ULONG)data->knownDll + offset);
            const auto size = 0x10;

            const auto moduleProcHash = CalcHash(fnStart, size);
            const auto knownDllProcHash = CalcHash(knownDllAddr, size);

            if (moduleProcHash != knownDllProcHash) {
                PRINT(L"---------------------------------------------------\n");
                PRINT(L">>> MODIFICATION DETECTED!\n");
                PRINT(L">>> %ws @ 0x%p, offset: 0x%x, size: 0x%x, knownDllAddr: 0x%p\n", wname, fnStart, offset, size, knownDllAddr);
                PRINT(L">>> Expected hash: 0x%x, got: 0x%x\n", knownDllProcHash, moduleProcHash);
            }

            return false;
        };

        IterateModuleProcs(module, fnProcIter, (PVOID)&data);

        PRINT(L"> Procs tested.\n");

        return false;
    };
    PRINT(L"Iterating modules...\n");
    IteratePebModules(fnModuleIter);

    PRINT(L"All possible modules tested.\n");
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (!GetConsoleWindow()) {
            AllocConsole();
        }
        DetectHooks();

        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
