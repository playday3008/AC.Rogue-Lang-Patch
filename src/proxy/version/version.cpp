#include "version.hpp"

#if defined(__GNUC__) || defined(__clang__)

#    define NAKED  __attribute__((naked))
#    define EXTERN extern "C"

#    define WRAPPER(name)                                                           \
        NAKED EXTERN void _##name() {                                               \
            asm("jmp %[target]" : [target] "+r"(version.name) : "m"(version.name)); \
        }

#elif defined(_MSC_VER)

#    define EXTERN extern "C"

#    define WRAPPER(name)       \
        EXTERN void _##name() { \
            version.name();     \
        }

#else

#    define WRAPPER(name)

#endif

WRAPPER(GetFileVersionInfoA)
WRAPPER(GetFileVersionInfoByHandle)
WRAPPER(GetFileVersionInfoExA)
WRAPPER(GetFileVersionInfoExW)
WRAPPER(GetFileVersionInfoSizeA)
WRAPPER(GetFileVersionInfoSizeExA)
WRAPPER(GetFileVersionInfoSizeExW)
WRAPPER(GetFileVersionInfoSizeW)
WRAPPER(GetFileVersionInfoW)
WRAPPER(VerFindFileA)
WRAPPER(VerFindFileW)
WRAPPER(VerInstallFileA)
WRAPPER(VerInstallFileW)
WRAPPER(VerLanguageNameA)
WRAPPER(VerLanguageNameW)
WRAPPER(VerQueryValueA)
WRAPPER(VerQueryValueW)