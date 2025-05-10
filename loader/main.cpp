#include <Windows.h>

#pragma comment(linker, "/ENTRY:main")

#define PRINT(STR, ...) \
	if (1) { \
		LPWSTR buf = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024); \
		if (buf != NULL) { \
			int len = wsprintfW(buf, STR, __VA_ARGS__); \
			WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), buf, len, NULL, NULL); \
			HeapFree(GetProcessHeap(), 0, buf); \
		} \
	} \


void WaitForKey(LPCWSTR message)
{
	HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode = 0;

	GetConsoleMode(hInput, &mode);
	SetConsoleMode(hInput, mode | ENABLE_LINE_INPUT);

	DWORD read = 0;
	WCHAR buffer[2];
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), message, lstrlenW(message), nullptr, nullptr);
	ReadConsoleW(hInput, buffer, 2, &read, nullptr);
}


int main()
{
	WaitForKey(L"Press any key to continue...");

	PRINT(L"Loading hookdetector.dll...\n");
	const auto detector = LoadLibraryW(L"hookdetector.dll");
	PRINT(L"Hook detector loaded @ 0x%p\n", detector);

	WaitForKey(L"Press any key to exit...");

	return 0;
	//ExitProcess(0);
}