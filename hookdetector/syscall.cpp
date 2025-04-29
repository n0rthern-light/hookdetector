#include "syscall.hpp"

#pragma code_seg(push, myseg, ".text$heaven")
__declspec(allocate(".text$heaven"))
unsigned char HeavenGateShellcode[] = {
    // mov rax, [rsi]
    0x48, 0x8B, 0x06,
    // mov rcx, [rsi + 8]
    0x48, 0x8B, 0x4E, 0x08,
    // mov r10, rcx - syscall convention (first arg in r10)
    0x49, 0x89, 0xca,
    // mov rdx, [rsi + 16]
    0x48, 0x8B, 0x56, 0x10,
    // mov r8, [rsi + 24]
    0x4C, 0x8B, 0x46, 0x18,
    // mov r9, [rsi + 32]
    0x4C, 0x8B, 0x4E, 0x20,
    // push qword ptr [rsi + 40] ; Arg 5
    0xFF, 0x76, 0x28,
    // push qword ptr [rsi + 48] ; Arg 6
    0xFF, 0x76, 0x30,
    // syscall
    0x0F, 0x05,
    // add rsp, 16 ; cleanup stack 
    0x48, 0x83, 0xc4, 0x10,
    // mov [rsi + 60], rax ; Save return value
    0x48, 0x89, 0x46, 0x3c,

    // -- exit procedure

    // sub esp, 0x8
    0x83, 0xec, 0x08,
    // mov eax, 0x23
    0xb8, 0x23, 0x00, 0x00, 0x00,
    // mov    DWORD PTR[esp + 0x4],eax
    0x67, 0x89, 0x44, 0x24, 0x04,
    // mov eax, [rsi + 56]
    0x8B, 0x46, 0x38,
    // mov    DWORD PTR[esp],eax
    0x67, 0x89, 0x04, 0x24,

    // retf
    0xCB
};
#pragma code_seg(pop, myseg)

DWORD32 HeavensGateSyscall(HEAVENS_GATE_SYSCALL* pCall)
{
    DWORD32 ret;
    __asm {
        push esi
        mov esi, pCall // mov esi, pCall

        mov edx, prologue
        mov dword ptr[esi + 56], edx // store ReturnAddress
        push 0x33
        push offset HeavenGateShellcode
        retf

    prologue:
        // Return NTSTATUS
        mov eax, [esi + 60]
        lea edx, ret
        mov [edx], eax

        pop esi
    }

    return ret;
}

