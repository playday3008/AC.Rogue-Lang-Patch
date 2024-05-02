#include "proxy.hpp"

#include "version/version.hpp"

#include <filesystem>

bool iequals(const std::wstring_view s1, const std::wstring_view s2) {
    std::wstring str1(s1);
    std::wstring str2(s2);
    std::transform(str1.begin(), str1.end(), str1.begin(), [](const wchar_t c) {
        return ::towlower(c);
    });
    std::transform(str2.begin(), str2.end(), str2.begin(), [](const wchar_t c) {
        return ::towlower(c);
    });
    return (str1 == str2);
}

std::wstring GetModuleFileNameW(HMODULE hModule) {
    static constexpr auto INITIAL_BUFFER_SIZE = MAX_PATH;
    static constexpr auto MAX_ITERATIONS      = 7;
    std::wstring          ret;
    auto                  bufferSize = INITIAL_BUFFER_SIZE;
    for (size_t iterations = 0; iterations < MAX_ITERATIONS; ++iterations) {
        ret.resize(bufferSize);
        auto charsReturned = GetModuleFileNameW(hModule, ret.data(), bufferSize);
        if (charsReturned < ret.length()) {
            ret.resize(charsReturned);
            return ret;
        }
        bufferSize *= 2;
    }
    return L"";
}

std::wstring GetSelfName(HMODULE hm) {
    const std::wstring moduleFileName = GetModuleFileNameW(hm);
    return moduleFileName.substr(moduleFileName.find_last_of(L"/\\") + 1);
}

std::wstring SHGetKnownFolderPath(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken) {
    std::wstring r;
    WCHAR       *szSystemPath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(rfid, dwFlags, hToken, &szSystemPath))) {
        r = szSystemPath;
    }
    CoTaskMemFree(szSystemPath);
    return r;
};

HMODULE LoadLibraryW(const std::wstring &lpLibFileName) {
    return LoadLibraryW(lpLibFileName.c_str());
}

static LONG OriginalLibraryLoaded = 0;

void LoadOriginalLibrary(HMODULE hm) {
    if (_InterlockedCompareExchange(&OriginalLibraryLoaded, 1, 0) != 0)
        return;

    const auto szSelfName   = GetSelfName(hm);
    auto       szSystemPath = SHGetKnownFolderPath(FOLDERID_System, 0, nullptr);
    auto       szLocalPath  = GetModuleFileNameW(hm);
    szSystemPath += L'\\' + szSelfName;
    szLocalPath = szLocalPath.substr(0, szLocalPath.find_last_of(L"/\\") + 1);

    if (iequals(szSelfName, L"version.dll")) {
        szLocalPath += L"versionHooked.dll";
        if (std::filesystem::exists(szLocalPath))
            version.LoadOriginalLibrary(LoadLibraryW(szLocalPath));
        else
            version.LoadOriginalLibrary(LoadLibraryW(szSystemPath));
    } else {
        MessageBox(nullptr,
                   TEXT("This library isn't supported."),
                   TEXT("AC: Rogue Patcher"),
                   MB_ICONERROR);
        ExitProcess(0);
    }
}
