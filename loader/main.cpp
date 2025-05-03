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

int main()
{
	PRINT(L"Loading hookdetector.dll...\n");
	const auto detector = LoadLibraryW(L"hookdetector.dll");
	PRINT(L"Hook detector loaded @ 0x%p\n", detector);

	return 0;
	//ExitProcess(0);
}