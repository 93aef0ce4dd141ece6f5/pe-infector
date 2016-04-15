#include <Windows.h>
#include <winnt.h>

#include "main.h"

PIMAGE_DOS_HEADER GetDosHeader(PUCHAR file) {
	return (PIMAGE_DOS_HEADER)file;
}

/*
* returns the PE header
*/
PIMAGE_NT_HEADERS GetPeHeader(PUCHAR file) {
	PIMAGE_DOS_HEADER pidh = GetDosHeader(file);

	return (PIMAGE_NT_HEADERS)((DWORD)pidh + pidh->e_lfanew);
}

/*
* returns the file header
*/
PIMAGE_FILE_HEADER GetFileHeader(PUCHAR file) {
	PIMAGE_NT_HEADERS pinh = GetPeHeader(file);

	return (PIMAGE_FILE_HEADER)&pinh->FileHeader;
}

/*
* returns the optional header
*/
PIMAGE_OPTIONAL_HEADER GetOptionalHeader(PUCHAR file) {
	PIMAGE_NT_HEADERS pinh = GetPeHeader(file);

	return (PIMAGE_OPTIONAL_HEADER)&pinh->OptionalHeader;
}

/*
* returns the first section's header
* AKA .text or the code section
*/
PIMAGE_SECTION_HEADER GetFirstSectionHeader(PUCHAR file) {
	PIMAGE_NT_HEADERS pinh = GetPeHeader(file);

	return (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pinh);
}

PIMAGE_SECTION_HEADER GetLastSectionHeader(PUCHAR file) {
	return (PIMAGE_SECTION_HEADER)(GetFirstSectionHeader(file) + (GetPeHeader(file)->FileHeader.NumberOfSections - 1));
}

BOOL VerifyDOS(PIMAGE_DOS_HEADER pidh) {
	return pidh->e_magic == IMAGE_DOS_SIGNATURE ? TRUE : FALSE;
}

BOOL VerifyPE(PIMAGE_NT_HEADERS pinh) {
	return pinh->Signature == IMAGE_NT_SIGNATURE ? TRUE : FALSE;
}