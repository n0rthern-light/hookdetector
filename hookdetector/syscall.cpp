#include "syscall.hpp"

#pragma code_seg(push, myseg, ".text$heaven")
__declspec(allocate(".text$heaven"))
unsigned char HeavenGateShellcode[] = {
    // mov eax, [esi]
    0x67, 0x8b, 0x06,
    // mov rcx, [rsi + 16]
    0x48, 0x8B, 0x4E, 0x10,
    // mov r10, rcx - syscall convention (first arg in r10)
    0x49, 0x89, 0xca,
    // mov rdx, [rsi + 24]
    0x48, 0x8B, 0x56, 0x18,
    // mov r8, [rsi + 32]
    0x4C, 0x8B, 0x46, 0x20,
    // mov r9, [rsi + 40]
    0x4C, 0x8B, 0x4E, 0x28,
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
    0xFF, 0x76, 0x60,
    // push qword ptr [rsi + 104] ; Arg 12
    0xFF, 0x76, 0x68,
    // syscall
    0x0F, 0x05,
    // add rsp, 36 ; cleanup stack 
    0x48, 0x83, 0xc4, 0x40,
    // mov [rsi + 8], rax ; Save return value
    0x48, 0x89, 0x46, 0x08,

    // -- exit procedure

    // sub esp, 0x8
    0x83, 0xec, 0x08,
    // mov eax, 0x23
    0xb8, 0x23, 0x00, 0x00, 0x00,
    // mov    DWORD PTR[esp + 0x4],eax
    0x67, 0x89, 0x44, 0x24, 0x04,
    // mov eax, [rsi + 4]
    0x8B, 0x46, 0x04,
    // mov    DWORD PTR[esp],eax
    0x67, 0x89, 0x04, 0x24,

    // retf
    0xCB
};
#pragma code_seg(pop, myseg)

DWORD32 HeavensGateSyscall(HEAVENS_GATE_SYSCALL* pCall)
{
    // todo stack alignment? :)
    DWORD32 ret;
    __asm {
        push esi
        mov esi, pCall // mov esi, pCall

        mov edx, prologue
        mov dword ptr[esi + 4], edx // store ReturnAddress
        push 0x33
        push offset HeavenGateShellcode
        retf

    prologue:
        // Return NTSTATUS
        mov eax, [esi + 8]
        lea edx, ret
        mov [edx], eax

        pop esi
    }

    return ret;
}

