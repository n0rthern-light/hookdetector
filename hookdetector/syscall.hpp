#ifndef SYSCALL_HPP
#define SYSCALL_HPP

#include <Windows.h>

extern unsigned char HeavenGateShellcode[];

#pragma pack(push, 1)
typedef struct {
    DWORD64 SyscallId;    // [0]
    DWORD64 Arg1;         // [8]
    DWORD64 Arg2;         // [16]
    DWORD64 Arg3;         // [24]
    DWORD64 Arg4;         // [32]
    DWORD64 Arg5;         // [40]
    DWORD64 Arg6;         // [48]
    DWORD32 ReturnAddress;  // [56]
    DWORD64 ReturnValue;  // [60]
} HEAVENS_GATE_SYSCALL;
#pragma pack(pop) 

DWORD32 HeavensGateSyscall(HEAVENS_GATE_SYSCALL* pCall);

__forceinline DWORD32 syscall(
    DWORD32 syscallId,
    DWORD64 Arg1 = NULL,
    DWORD64 Arg2 = NULL,
    DWORD64 Arg3 = NULL,
    DWORD64 Arg4 = NULL,
    DWORD64 Arg5 = NULL,
    DWORD64 Arg6 = NULL
) {
    auto call = HEAVENS_GATE_SYSCALL{
        syscallId,
        Arg1,
        Arg2,
        Arg3,
        Arg4,
        Arg5,
        Arg6
    };

    return HeavensGateSyscall(&call);
}

#endif
