#include "syscall.hpp"

#pragma code_seg(push, myseg, ".text$heaven")
__declspec(allocate(".text$heaven"))
unsigned char HeavenGateShellcode[] = {
    // -- setup args and syscall
    // mov eax, [esi]
    0x67, 0x8b, 0x06,
    // mov rcx, [rsi + 16] ;       Arg 1
    0x48, 0x8B, 0x4E, 0x10,
    // mov r10, rcx ;              Arg 1
    0x49, 0x89, 0xca,
    // mov rdx, [rsi + 24] ;       Arg 2
    0x48, 0x8B, 0x56, 0x18,
    // mov r8, [rsi + 32] ;        Arg 3
    0x4C, 0x8B, 0x46, 0x20,
    // mov r9, [rsi + 40] ;        Arg 4
    0x4C, 0x8B, 0x4E, 0x28,

    // -- preserve stack
    // push r12
    0x41, 0x54,
    // mov r12, rsp
    0x49, 0x89, 0xe4,

    // push qword ptr [rsi + 48] ; Arg 5
    0xFF, 0x76, 0x30,
    // push qword ptr [rsi + 56] ; Arg 6
    0xFF, 0x76, 0x38,
    // push qword ptr [rsi + 64] ; Arg 7
    0xFF, 0x76, 0x40,
    // push qword ptr [rsi + 72] ; Arg 8
    0xFF, 0x76, 0x48,
    // push qword ptr [rsi + 80] ; Arg 9
    0xFF, 0x76, 0x50,
    // push qword ptr [rsi + 88] ; Arg 10
    0xFF, 0x76, 0x58,
    // push qword ptr [rsi + 96] ; Arg 11
    0xFF, 0x176, 0x60,
    // push qword ptr [rsi + 104] ; Arg 12
    0xFF, 0x76, 0x68,
    // push qword ptr [rsi + 112] ; Arg 13
    0xFF, 0x76, 0x70,
    // push qword ptr [rsi + 120] ; Arg 14
    0xFF, 0x76, 0x78,
    // push qword ptr [rsi + 128] ; Arg 15
    0xFF, 0x76, 0x80,

    // syscall
    0x0F, 0x05,

    // mov [rsi + 8], rax ; Save return value
    0x48, 0x89, 0x46, 0x08,

    // -- revert stack (cleanup)
    // mov rsp, r12
    0x4c, 0x89, 0xe4,
    // pop r12
    0x41, 0x5c,

    // -- exit procedure

    // sub esp, 0x8
    0x83, 0xec, 0x08,
    // mov eax, 0x23
    0xb8, 0x23, 0x00, 0x00, 0x00,
    // mov DWORD PTR[esp + 0x4],eax
    0x67, 0x89, 0x44, 0x24, 0x04,
    // mov eax, [esi + 4]
    0x67, 0x8B, 0x46, 0x04,
    // mov DWORD PTR[esp],eax
    0x67, 0x89, 0x04, 0x24,
    // retf
    0xCB
};
#pragma code_seg(pop, myseg)

DWORD32 HeavensGateSyscall(HEAVENS_GATE_SYSCALL* pCall)
{
    __asm {
        mov esi, pCall // mov esi, pCall ([ebp + 8])

        mov edx, prologue
        mov dword ptr[esi + 4], edx // store ReturnAddress
        push 0x33
        push offset HeavenGateShellcode
        retf

    prologue:
        // Return NTSTATUS
        mov eax, [esi + 8]
        mov cx, ds // fix ESP register (for AMD)
        mov ss, cx // http://blog.rewolf.pl/blog/?p=1484
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
