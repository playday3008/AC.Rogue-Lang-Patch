#pragma once

#include "../shared.hpp"

inline struct version_dll {
    HMODULE dll;
    FARPROC GetFileVersionInfoA;
    FARPROC GetFileVersionInfoByHandle;
    FARPROC GetFileVersionInfoExA;
    FARPROC GetFileVersionInfoExW;
    FARPROC GetFileVersionInfoSizeA;
    FARPROC GetFileVersionInfoSizeExA;
    FARPROC GetFileVersionInfoSizeExW;
    FARPROC GetFileVersionInfoSizeW;
    FARPROC GetFileVersionInfoW;
    FARPROC VerFindFileA;
    FARPROC VerFindFileW;
    FARPROC VerInstallFileA;
    FARPROC VerInstallFileW;
    FARPROC VerLanguageNameA;
    FARPROC VerLanguageNameW;
    FARPROC VerQueryValueA;
    FARPROC VerQueryValueW;

    void LoadOriginalLibrary(HMODULE module) {
        dll = module;
        shared.LoadOriginalLibrary(dll);
        GetFileVersionInfoA        = GetProcAddress(dll, "GetFileVersionInfoA");
        GetFileVersionInfoByHandle = GetProcAddress(dll, "GetFileVersionInfoByHandle");
        GetFileVersionInfoExA      = GetProcAddress(dll, "GetFileVersionInfoExA");
        GetFileVersionInfoExW      = GetProcAddress(dll, "GetFileVersionInfoExW");
        GetFileVersionInfoSizeA    = GetProcAddress(dll, "GetFileVersionInfoSizeA");
        GetFileVersionInfoSizeExA  = GetProcAddress(dll, "GetFileVersionInfoSizeExA");
        GetFileVersionInfoSizeExW  = GetProcAddress(dll, "GetFileVersionInfoSizeExW");
        GetFileVersionInfoSizeW    = GetProcAddress(dll, "GetFileVersionInfoSizeW");
        GetFileVersionInfoW        = GetProcAddress(dll, "GetFileVersionInfoW");
        VerFindFileA               = GetProcAddress(dll, "VerFindFileA");
        VerFindFileW               = GetProcAddress(dll, "VerFindFileW");
        VerInstallFileA            = GetProcAddress(dll, "VerInstallFileA");
        VerInstallFileW            = GetProcAddress(dll, "VerInstallFileW");
        VerLanguageNameA           = GetProcAddress(dll, "VerLanguageNameA");
        VerLanguageNameW           = GetProcAddress(dll, "VerLanguageNameW");
        VerQueryValueA             = GetProcAddress(dll, "VerQueryValueA");
        VerQueryValueW             = GetProcAddress(dll, "VerQueryValueW");
    }
} version;
