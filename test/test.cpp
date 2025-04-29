#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

// Define function prototypes
typedef NTSTATUS(NTAPI* NtOpenSection_t)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
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

typedef NTSTATUS(NTAPI* NtQueryPerformanceCounter_t)(
    PLARGE_INTEGER PerformanceCounter,
    PLARGE_INTEGER PerformanceFrequency
);

#define KERNEL32_KNOWNDLL L"\\KnownDlls\\kernel32.dll"

int main() {
    HANDLE hSection = NULL;
    UNICODE_STRING uName;
    OBJECT_ATTRIBUTES objAttr;
    PVOID baseAddress = NULL;
    SIZE_T viewSize = 0;

    // Get function pointers
    NtQueryPerformanceCounter_t NtQueryPerformanceCounter = (NtQueryPerformanceCounter_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryPerformanceCounter");
    NtOpenSection_t NtOpenSection = (NtOpenSection_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenSection");
    NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection");

    if (!NtOpenSection || !NtMapViewOfSection || !NtQueryPerformanceCounter) {
        printf("Failed to get NTDLL exports\n");
        return 1;
    }
    NTSTATUS status;

    LARGE_INTEGER counter;
    status = NtQueryPerformanceCounter(&counter, NULL);
    if (!NT_SUCCESS(status)) {
        printf("NtQueryPerformanceCounter failed: 0x%X\n", status);
        return 1;
    }
    else {
        printf("NtQueryPerformanceCounter success: 0x%016X", counter);
    }


    // Initialize UNICODE_STRING
    RtlInitUnicodeString(&uName, KERNEL32_KNOWNDLL);

    InitializeObjectAttributes(&objAttr, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenSection(&hSection, SECTION_MAP_READ, &objAttr);
    if (!NT_SUCCESS(status)) {
        printf("NtOpenSection failed: 0x%X\n", status);
        return 1;
    }

    viewSize = 0;
    baseAddress = NULL;

    status = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &baseAddress,
        0,
        0,
        NULL,
        &viewSize,
        1, // ViewShare
        0,
        PAGE_READONLY
    );

    if (!NT_SUCCESS(status)) {
        printf("NtMapViewOfSection failed: 0x%X\n", status);
        CloseHandle(hSection);
        return 1;
    }

    printf("kernel32.dll mapped at: %p\n", baseAddress);

    // You can now read from baseAddress
    // For example: print first few bytes
    BYTE* bytes = (BYTE*)baseAddress;
    printf("First bytes: %02X %02X %02X %02X\n", bytes[0], bytes[1], bytes[2], bytes[3]);

    // Cleanup
    UnmapViewOfFile(baseAddress);
    CloseHandle(hSection);

    return 0;
}

