#ifndef SYSCALL_HPP
#define SYSCALL_HPP

#include <Windows.h>

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
    DWORD64 StArg12 = NULL
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
        StArg12
    };

    return HeavensGateSyscall(&call);
}

#endif
