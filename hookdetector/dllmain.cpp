#include <Windows.h>

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

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* pNtOpenSection64)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(NTAPI* pNtMapViewOfSection64)(
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

#pragma code_seg(push, myseg, ".text$heaven")
__declspec(allocate(".text$heaven"))
unsigned char HeavenGateShellcode[] = {
    // mov rcx, [rsi + 8]
    0x48, 0x8B, 0x4E, 0x08,
    // mov rdx, [rsi + 16]
    0x48, 0x8B, 0x56, 0x10,
    // mov r8, [rsi + 24]
    0x4C, 0x8B, 0x46, 0x18,
    // mov r9, [rsi + 32]
    0x4C, 0x8B, 0x4E, 0x20,
    // mov rax, [rsi]
    0x48, 0x8B, 0x06,
    // sub rsp, 0x28
    0x48, 0x83, 0xEC, 0x28,
    // mov [rsp+0x20], [rsi+40] ; Arg5
    0x48, 0x8B, 0x56, 0x28,
    0x48, 0x89, 0x54, 0x24, 0x20,
    // mov [rsp+0x28], [rsi+48] ; Arg6
    0x48, 0x8B, 0x56, 0x30,
    0x48, 0x89, 0x54, 0x24, 0x28,
    // syscall
    0x0F, 0x05,
    // add rsp, 0x28
    0x48, 0x83, 0xC4, 0x28,
    // mov [rsi], rax ; Save return value
    0x48, 0x89, 0x06,

    // Now dynamically push return address
    // push 0x23
    0x6A, 0x23,
    // mov eax, [rsi + 56]
    0x8B, 0x46, 0x38,
    // push rax
    0x50,
    // retf
    0xCB
};
#pragma code_seg(pop, myseg)

typedef struct _GATE_SYSCALL {
    DWORD64 SyscallId;    // [0]
    DWORD64 Arg1;         // [8]
    DWORD64 Arg2;         // [16]
    DWORD64 Arg3;         // [24]
    DWORD64 Arg4;         // [32]
    DWORD64 Arg5;         // [40]
    DWORD64 Arg6;         // [48]
    DWORD32 ReturnAddress32; // [56]  <- NEW FIELD
} GATE_SYSCALL, * PGATE_SYSCALL;

__declspec(naked) NTSTATUS HeavensGateSyscall(PGATE_SYSCALL pCall) {
    __asm {
        // Prologue (save state)
        pushad
        pushfd

        // Get pointer to PGATE_SYSCALL
        mov esi, [esp + 0x24] // 32-bit stack frame: after pushad+pushfd

        // Load return address into [esi + 56]
        // We need to manually compute it without labels.
        // Trick: After retf, execution will continue to the next instruction on the stack.
        // So just push current esp + 10h

        lea eax, [esp + 0x10]    // address after retf
        mov[esi + 56], eax

        // Jump into 64-bit HeavenGateShellcode
        push 0x33
        push offset HeavenGateShellcode
        retf

        // No labels needed!
        // After returning from 64-bit HeavenGateShellcode, execution continues here.

        // Restore state
        popfd
        popad

        // Return NTSTATUS from eax
        mov eax, [esp]
        add esp, 4
        ret
    }
}

bool DetectHooks()
{
#ifdef _PRINT_MODULES
    PrintRealModules();
#endif

    PRINT(L"We are loaded.\n");

    HANDLE hSection = NULL;

    WCHAR nameBuffer[] = L"\\KnownDlls\\kernel32.dll";
    UNICODE_STRING uniName;
    InitUnicodeString(&uniName, nameBuffer);

    OBJECT_ATTRIBUTES objAttr = { 0 };
    objAttr.Length = sizeof(objAttr);
    objAttr.ObjectName = &uniName;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE;

    GATE_SYSCALL gateCall = { 0 };
    gateCall.SyscallId = 0x27;
    gateCall.Arg1 = (DWORD64)(ULONG_PTR)&hSection;
    gateCall.Arg2 = SECTION_MAP_READ; // Desired access
    gateCall.Arg3 = (DWORD64)(ULONG_PTR)&objAttr;

    NTSTATUS status = HeavensGateSyscall(&gateCall);

    // Validate output
    if (NT_SUCCESS(status) && hSection != NULL)
    {
        PRINT(L"Success: 0x%p - handle", hSection);
    }
    else
    {
        PRINT(L"Failed on syscall");
    }

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
