# 🪝 hookdetector
A DLL module for WOW64 processes (32-bit on 64-bit Windows) designed to detect Windows API hooks within the process's 32-bit DLLs.

## Goal of the project
The goal is to reliably detect hooks within x86 DLLs in an x86 process as long as there is no kernel-mode interference.

## How it works
The functionality relies on three concepts:
- Use of `\\KnownDlls32\\` named section objects which provide trusted, pre-mapped system DLLs in Windows to which the hookdetector compares actually mapped DLLs.
- Direct syscalls cannot be intercepted without kernel-mode hooks. And these are used to call mission-critical `NtApi` functions.
- Any WOW64 process can switch mode to 64-bit code execution, so the `syscall` CPU instruction is available (so called "heavens gate").

## Mission-critical NtApi functions
- `NtOpenSection` to open a handle to `\\KnownDlls32\\<windows-dll-that-need-to-be-tested>.dll`.
- `NtMapViewOfSection` to map opened section of a DLL to the virtual address space.

So these functions stubs are reimplemented inside [`hookdetector/syscalls.cpp`](hookdetector/syscall.cpp).

## Prerequisites
1. Windows 10+ OS (64-bit).
2. Target process (32-bit).

## Usage
1. Inject `hookdetector.dll` into any 32-bit process.
2. Wait for the console output.

![image](https://github.com/user-attachments/assets/8dcb134b-2b22-4802-b0a9-439abd2563ff)

*Example output after attaching x32dbg with ScyllaHide's hooks.*

## What could have been improved
1. Since it's possible to place API hooks inside 64-bit DLLs of a WOW64 process - for example, the 64-bit version of `ntdll.dll` could be hooked - these hooks WILL be undetected by the current solution, as 64-bit DLLs aren't accessible from 32-bit mode. This is something to consider implementing in the future to enable DLL scanning also in 64-bit mode.
2. The current solution compares only the first 16 bytes of a function's prologue, which is insufficient to detect all hooking methods. To improve accuracy, the entire function body should be compared instead.
3. Some functions are falsely reported as modified (due to byte diff of unknown to me origin). To reduce false positives, additional logic should be implemented or the above mentioned mechanism should be improved.

## Conclusion
This proof-of-concept hook detector effectively identifies inline hooks in 32-bit Windows DLLs and cannot be bypassed using user-mode hooks on `NtOpenSection` or `NtMapViewOfSection`, thanks to direct syscalls and the KnownDlls mechanism that prevents tampering with on-disk DLLs. However, while functional, it is far from a comprehensive solution. Applying the suggestions from previous sections could significantly improve its capabilities, but would also move it beyond the scope of a simple proof-of-concept. Nonetheless, this project serves as a solid foundation for basic hook detection or as inspiration for building a more advanced EDR solution.

## License
This project is licensed under the [MIT License](LICENSE).
