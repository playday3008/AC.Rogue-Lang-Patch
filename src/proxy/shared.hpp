#pragma once

#include <Windows.h>

inline struct shared_dll {
    FARPROC DllCanUnloadNow;
    FARPROC DllGetClassObject;
    FARPROC DllRegisterServer;
    FARPROC DllUnregisterServer;
    FARPROC DebugSetMute;

    void LoadOriginalLibrary(HMODULE dll) {
        DllCanUnloadNow     = GetProcAddress(dll, "DllCanUnloadNow");
        DllGetClassObject   = GetProcAddress(dll, "DllGetClassObject");
        DllRegisterServer   = GetProcAddress(dll, "DllRegisterServer");
        DllUnregisterServer = GetProcAddress(dll, "DllUnregisterServer");
        DebugSetMute        = GetProcAddress(dll, "DebugSetMute");
    }
} shared;
