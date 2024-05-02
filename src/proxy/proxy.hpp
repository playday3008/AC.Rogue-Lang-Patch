#pragma once

#include <Windows.h>
#include <ShlObj.h>

#include <string>

std::wstring GetModuleFileNameW(HMODULE hModule);

std::wstring GetSelfName(HMODULE hm);

std::wstring SHGetKnownFolderPath(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken);

HMODULE LoadLibraryW(const std::wstring &lpLibFileName);

void LoadOriginalLibrary(HMODULE hm);
