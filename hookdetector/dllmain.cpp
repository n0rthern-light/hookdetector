#include "nt_def.hpp"
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
