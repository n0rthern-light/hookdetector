#ifndef SYSCALL_HPP
#define SYSCALL_HPP

#include "nt_def.hpp"

#define STACK_ALIGN_TO_X64 __asm { and esp, 0xFFFFFFF0 };

#define X64_PTR(ptr) (DWORD64)(DWORD32)(ptr)
#define MAKE_X64_PTR(var) X64_PTR(&var)

extern unsigned char HeavenGateShellcode[];

#pragma pack(push, 1)
typedef struct {
    DWORD32 SyscallId;     // [0]
    DWORD32 ReturnAddress; // [4]
    DWORD64 ReturnValue;   // [8]
    // --- register based args
    DWORD64 Arg1;          // [16]
    DWORD64 Arg2;          // [24]
    DWORD64 Arg3;          // [32]
    DWORD64 Arg4;          // [40]
    // --- stack based
    DWORD64 Arg5;          // [48]
    DWORD64 Arg6;          // [56]
    DWORD64 Arg7;          // [64]
    DWORD64 Arg8;          // [72]
    DWORD64 Arg9;          // [80]
    DWORD64 Arg10;         // [88]
    DWORD64 Arg11;         // [96]
    DWORD64 Arg12;         // [104]
    DWORD64 Arg13;         // [112]
    DWORD64 Arg14;         // [120]
    DWORD64 Arg15;         // [128]
} HEAVENS_GATE_SYSCALL;
#pragma pack(pop) 

DWORD32 HeavensGateSyscall(HEAVENS_GATE_SYSCALL* pCall);

__forceinline DWORD32 syscall(
    DWORD32 syscallId,
    DWORD64 Arg1 = NULL,
    DWORD64 Arg2 = NULL,
    DWORD64 Arg3 = NULL,
    DWORD64 Arg4 = NULL,
    DWORD64 StArg5 = NULL,
    DWORD64 StArg6 = NULL,
    DWORD64 StArg7 = NULL,
    DWORD64 StArg8 = NULL,
    DWORD64 StArg9 = NULL,
    DWORD64 StArg10 = NULL,
    DWORD64 StArg11 = NULL,
    DWORD64 StArg12 = NULL,
    DWORD64 StArg13 = NULL,
    DWORD64 StArg14 = NULL,
    DWORD64 StArg15 = NULL
) {
    auto call = HEAVENS_GATE_SYSCALL{
        syscallId,
        NULL,
        NULL,
        Arg1,
        Arg2,
        Arg3,
        Arg4,
        StArg5,
        StArg6,
        StArg7,
        StArg8,
        StArg9,
        StArg10,
        StArg11,
        StArg12,
        StArg13,
        StArg14,
        StArg15
    };

    return HeavensGateSyscall(&call);
}

NTSTATUS SyscallNtOpenSection(PCWSTR sectionName, HANDLE* pOutHandle);
NTSTATUS SyscallNtMapViewOfSection(HANDLE hSection, PVOID* ppOutAddress);

#endif
