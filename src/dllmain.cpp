#include <numbers>

#include <Windows.h>
#include <tchar.h>

#include "proxy/proxy.hpp"

#include <injector/injector.hpp>
#include <injector/calling.hpp>
#include <injector/hooking.hpp>
#include <injector/assembly.hpp>
#include <injector/utility.hpp>

#include <Hooking.Patterns.h>

#define MINI_CASE_SENSITIVE
#include <mini/ini.h>

void PatchACRogue() {
    // Load configuration
    const mINI::INIFile file("patch_config.ini");
    mINI::INIStructure  ini;
    if (!file.read(ini))
        return;

    // Spoof Uplay ID
    [&]() {
        if (!ini.has("Spoof") || !ini["Spoof"].has("Region"))
            return;

        static enum class eACRogueUplayId {
            UplayWW   = 0x37F,
            UplayRU   = 0x4A2,
            UplayAsia = 0x67D,
            SteamWW   = 0x3A6,
            SteamRU   = UplayRU + 1,
            SteamAsia = UplayAsia + 1,
        } eACRogueUplayId;

        const auto uplay_id = ini["Spoof"]["Region"];
        if (uplay_id == "WW")
            eACRogueUplayId = eACRogueUplayId::UplayWW;
        else if (uplay_id == "RU")
            eACRogueUplayId = eACRogueUplayId::UplayRU;
        else if (uplay_id == "Asia")
            eACRogueUplayId = eACRogueUplayId::UplayAsia;
        else
            return;

        // clang-format off
        static auto hookGetUplayId = hook::pattern(GetModuleHandle(nullptr),
            "48 83 EC 28 "         // ACC.exe+3040: sub rsp,0x28                     |
            "B9 ? ? ? ? "          // ACC.exe+3044: mov ecx,0xC                      |
            "E8 ? ? ? ? "          // ACC.exe+3049: call acc.14000AE90               |
            "84 C0 "               // ACC.exe+304E: test al,al                       |
            "74 ? "                // ACC.exe+3050: je acc.140003069                 |
            "E8 ? ? ? ? "          // ACC.exe+3052: call acc.14017C000               |
            "33 C9 "               // ACC.exe+3057: xor ecx,ecx                      |
            "84 C0 "               // ACC.exe+3059: test al,al                       |
            "0F 95 C1 "            // ACC.exe+305B: setne cl                         | <- Steam ID (RU)
            "8D 81 ? ? ? ? "       // ACC.exe+305E: lea eax,qword ptr ds:[rcx+0x4A2] | <- Uplay ID (RU)
            "48 83 C4 28 "         // ACC.exe+3064: add rsp,0x28                     |
            "C3 "                  // ACC.exe+3068: ret                              |
            //"B9 0B 00 00 00 "    // ACC.exe+3069: mov ecx,0xB                      |
            //"E8 ? ? ? ? "        // ACC.exe+306E: call acc.14000AE90               |
            //"84 C0 "             // ACC.exe+3073: test al,al                       |
            //"74 25 "             // ACC.exe+3075: je acc.14000309C                 |
            //"B9 06 00 00 00 "    // ACC.exe+3077: mov ecx,0x6                      |
            //"E8 ? ? ? ? "        // ACC.exe+307C: call acc.14000AE90               |
            //"84 C0 "             // ACC.exe+3081: test al,al                       |
            //"74 ?? "             // ACC.exe+3083: je acc.14000309C                 |
            //"E8 ? ? ? ? "        // ACC.exe+3085: call acc.14017C000               |
            //"33 C9 "             // ACC.exe+308A: xor ecx,ecx                      |
            //"84 C0 "             // ACC.exe+308C: test al,al                       |
            //"0F 95C1 "           // ACC.exe+308E: setne cl                         | <- Steam ID (Asia)
            //"8D 81 7D 06 00 00 " // ACC.exe+3091: lea eax,qword ptr ds:[rcx+0x67D] | <- Uplay ID (Asia)
            //"48 83 C4 28 "       // ACC.exe+3097: add rsp,0x28                     |
            //"C3 "                // ACC.exe+309B: ret                              |
            //"E8 ? ? ? ? "        // ACC.exe+309C: call acc.14017C000               |
            //"B9 7F 03 00 00 "    // ACC.exe+30A1: mov ecx,0x37F                    | <- Uplay ID (WW)
            //"BA A6 03 00 00 "    // ACC.exe+30A6: mov edx,0x3A6                    | <- Steam ID (WW)
            //"84 C0 "             // ACC.exe+30AB: test al,al                       |
            //"0F 45 CA "          // ACC.exe+30AD: cmovne ecx,edx                   |
            //"8B C1 "             // ACC.exe+30B0: mov eax,ecx                      |
            //"48 83 C4 28 "       // ACC.exe+30B2: add rsp,0x28                     |
            //"C3 "                // ACC.exe+30B6: ret                              |
        );
        // clang-format on
        if (!hookGetUplayId.count_hint(1).empty()) {
            static auto hookIsSteam = injector::GetBranchDestination(hookGetUplayId.get_first(18));

            constexpr uintptr_t hook_offset   = 0x0;
            constexpr uintptr_t hook_jmp_size = 0x5;
            constexpr uintptr_t hook_size     = 0x9;
            struct SpoofUplayId {
                void operator()(injector::reg_pack &regs) const {
                    const byte isSteam = injector::fastcall<byte()>::call(hookIsSteam);

                    switch (eACRogueUplayId) {
                        case eACRogueUplayId::UplayWW:
                        case eACRogueUplayId::SteamWW:
                            if (isSteam)
                                regs.rax = static_cast<uint32_t>(eACRogueUplayId::SteamWW);
                            else
                                regs.rax = static_cast<uint32_t>(eACRogueUplayId::UplayWW);
                            break;
                        case eACRogueUplayId::UplayRU:
                        case eACRogueUplayId::SteamRU:
                            if (isSteam)
                                regs.rax = static_cast<uint32_t>(eACRogueUplayId::SteamRU);
                            else
                                regs.rax = static_cast<uint32_t>(eACRogueUplayId::UplayRU);
                            break;
                        case eACRogueUplayId::UplayAsia:
                        case eACRogueUplayId::SteamAsia:
                            if (isSteam)
                                regs.rax = static_cast<uint32_t>(eACRogueUplayId::SteamAsia);
                            else
                                regs.rax = static_cast<uint32_t>(eACRogueUplayId::UplayAsia);
                            break;
                    }
                }
            };
            injector::MakeNOP(hookGetUplayId.get_first(hook_offset), hook_size);
            injector::MakeInline<SpoofUplayId>(hookGetUplayId.get_first(hook_offset));
            injector::MakeRET(hookGetUplayId.get_first(hook_offset + hook_jmp_size));

            OutputDebugString(TEXT("AC: Rogue Patcher -> Uplay ID spoofed\n"));
        }
    }();

    // Patch Black Bars
    [&]() {
        if (!ini.has("Patch") || !ini["Patch"].has("EnableBlackBarsFix") ||
            ini["Patch"]["EnableBlackBarsFix"] != "1")
            return;

        static injector::memory_pointer_raw ptrAspectRatio;
        static injector::memory_pointer_raw ptrAspectRatioInv;
        static injector::memory_pointer_raw ptrTemplateWidth;
        static injector::memory_pointer_raw ptrTemplateHeight;

        {
            // clang-format off
            static auto hookAspectRatio = hook::pattern(GetModuleHandle(nullptr),
                    // Start as: ACC.exe+5447ED
                    "45 0F 2F C1 "             // [0.....3] comiss xmm8,xmm9
                    "41 0F 28 F0 "             // [4.....7] movaps xmm6,xmm8
                    "41 0F 28 F9 "             // [8....11] movaps xmm7,xmm9
                    "76 23 "                   // [12...13] jna ---------------------------------+
                    "41 0F 28 F8 "             // [14...17] movaps xmm7,xmm8                     |
                    "F3 0F 59 3D ? ? ? ? "     // [18...25] mulss xmm7,[ACC.exe+AspectRatioInv]  |
                    "44 0F 2F CF "             // [26...29] comiss xmm9,xmm7                     |
                    "77 04 "                   // [30...31] ja -----------------+                |
                    "41 0F 28 F9 "             // [32...35] movaps xmm7,xmm9    |                |
                    "0F 28 E7 "                // [36...38] movaps xmm4,xmm7 <--+                |
                    "F3 0F 59 25 ? ? ? ? "     // [39...46] mulss xmm4,[ACC.exe+ScreenWidthInv]  |
                    "EB 21 "                   // [47...48] jmp ACC.exe+54483F ------------------+--+
                    "41 0F 28 F1 "             // [49...52] movaps xmm6,xmm9 <-------------------+  |
                    "F3 0F 59 35 ? ? ? ? "     // [53...60] mulss xmm6,[ACC.exe+AspectRatio]        |
                    "44 0F 2F C6 "             // [61...64] comiss xmm8,xmm6                        |
                    "77 04 "                   // [65...66] ja -----------------+                   |
                    "41 0F 28 F0 "             // [67...70] movaps xmm6,xmm8    |                   |
                    "0F 28 E6 "                // [71...73] movaps xmm4,xmm6 <--+                   |
                    "F3 0F 59 25 ? ? ? ? "     // [74...81] mulss xmm4,[ACC.exe+ScreenHeightInv]    |
                    "48 8B 4B 20 "             // [82...85] mov rcx,[rbx+20] <----------------------+
                    "0F 28 C4 "                // [86...88] movaps xmm0,xmm4
                    "F3 0F 59 25 ? ? ? ? "     // [89...96] mulss xmm4,[ACC.exe+ScreenHeight]
                    "41 0F 28 C8 "             // [97..100] movaps xmm1,xmm8
                    "48 8D 94 24 D8 00 00 00 " // [101.108] lea rdx,[rsp+000000D8]
                    "4C 8D 8C 24 D0 00 00 00 " // [109.116] lea r9,[rsp+000000D0]
                    "F3 0F 59 05 ? ? ? ? "     // [117.124] mulss xmm0,[ACC.exe+ScreenWidth]
                    // End as: ACC.exe+544862
                );
            // clang-format on
            if (!hookAspectRatio.count_hint(1).empty()) {
                ptrAspectRatio    = injector::ReadRelativeOffset(hookAspectRatio.get_first(0x39));
                ptrAspectRatioInv = injector::ReadRelativeOffset(hookAspectRatio.get_first(0x16));

                ptrTemplateWidth  = injector::ReadRelativeOffset(hookAspectRatio.get_first(0x79));
                ptrTemplateHeight = injector::ReadRelativeOffset(hookAspectRatio.get_first(0x5D));

                OutputDebugString(
                    TEXT("AC: Rogue Patcher -> Removing Black Bars (1/3) -> Gathering Pointers\n"));
            }
        }

        {
            // clang-format off
            static auto hookAspectRatio = hook::pattern(GetModuleHandle(nullptr),
                    "F3 0F 5E C2 " // ACC.exe+5A24A7: divss xmm0,xmm2
                    "F3 0F 11 02 " // ACC.exe+5A24AB: movss [rdx],xmm0
                    "0F 28 C3 "    // ACC.exe+5A24AF: movaps xmm0,xmm3
                    "F3 0F 5C C5 " // ACC.exe+5A24B2: subss xmm0,xmm5
                    "F3 0F 5E EB " // ACC.exe+5A24b6: divss xmm5,xmm3
                );
            // clang-format on
            if (!hookAspectRatio.count_hint(1).empty()) {
                constexpr uintptr_t hook_offset = 0x8;
                constexpr uintptr_t hook_size   = 0x7;

                struct PatchAspectRatio {
                    void operator()(injector::reg_pack &regs) const {
                        // movss xmm4,dword ptr ds:[rax+0x10]
                        // movss xmm5,dword ptr ds:[rax+0x14]
                        const float screenWidth  = *reinterpret_cast<float *>(regs.rax + 0x10);
                        const float screenHeight = *reinterpret_cast<float *>(regs.rax + 0x14);

                        const float     fAspectRatio    = screenWidth / screenHeight;
                        const float     fAspectRatioInv = 1.f / fAspectRatio;
                        const float     templateWidth   = 1280.f * (fAspectRatio / (16.f / 9.f));
                        constexpr float templateHeight  = 720.f;

                        injector::WriteMemory(ptrAspectRatio, fAspectRatio, true);
                        injector::WriteMemory(ptrAspectRatioInv, fAspectRatioInv, true);
                        injector::WriteMemory(ptrTemplateWidth, templateWidth, true);
                        injector::WriteMemory(ptrTemplateHeight, templateHeight, true);

                        // Part of the original code
                        regs.xmm0 = regs.xmm3;
                        regs.xmm0.f32[0] -= regs.xmm5.f32[0];
                    }
                };
                injector::MakeNOP(hookAspectRatio.get_first(hook_offset), hook_size);
                injector::MakeInline<PatchAspectRatio>(hookAspectRatio.get_first(hook_offset));

                OutputDebugString(TEXT(
                    "AC: Rogue Patcher -> Removing Black Bars (2/3) -> Applying Aspect Ratio\n"));
            }
        }

        {
            static float desiredFov = 90.f; // Horizontal FOV
            if (ini["Patch"].has("DesiredFov")) {
                desiredFov = std::stof(ini["Patch"]["DesiredFov"]);
            }

            // clang-format off
            static auto hookFov = hook::pattern(GetModuleHandle(nullptr),
                    "48 89 53 18 "       // ACC.exe+345C59: mov [rbx+18],rdx
                    "48 89 53 20 "       // ACC.exe+345C5D: mov [rbx+20],rdx
                    "48 8B 03 "          // ACC.exe+345C61: mov rax,[rbx]
                    "F3 0F 10 00 "       // ACC.exe+345C64: movss xmm0,[rax]
                    "F3 0F 11 44 24 30 " // ACC.exe+345C68: movss [rsp+30],xmm0
                );
            // clang-format on
            if (!hookFov.count_hint(1).empty()) {
                constexpr uintptr_t hook_offset = 0xF;
                constexpr uintptr_t hook_size   = 0x6;

                struct PatchFov {
                    void operator()(injector::reg_pack &regs) const {
                        static float multiplier = 1.f;

                        static float fLastAspectRatio = 16.f / 9.f;
                        const float  fAspectRatio     = injector::ReadMemory<float>(ptrAspectRatio);
                        if (fAspectRatio != fLastAspectRatio) {
                            fLastAspectRatio = fAspectRatio;
                            // clang-format off
                            static const float fDefaultFov =
                                std::atan(
                                    std::tan(
                                        desiredFov * std::numbers::pi_v<float> / 360.f
                                    ) / (16.f / 9.f)
                                ) * 2;

                            multiplier =
                                std::atan(
                                    std::tan(
                                        desiredFov * std::numbers::pi_v<float> / 360.f
                                    ) / fAspectRatio
                                ) * 2 / fDefaultFov;
                            // clang-format on
                        }

                        // Part of the original code
                        *reinterpret_cast<float *>(regs.rsp + 0x30) = regs.xmm0.f32[0] * multiplier;
                    }
                };
                injector::MakeNOP(hookFov.get_first(hook_offset), hook_size);
                injector::MakeInline<PatchFov>(hookFov.get_first(hook_offset));

                OutputDebugString(
                    TEXT("AC: Rogue Patcher -> Removing Black Bars (2/3) -> Applying FOV\n"));
            }
        }
    }();
}

extern "C" BOOL APIENTRY DllMain(HMODULE CONST hModule,
                                 CONST DWORD   ul_reason_for_call,
                                 LPVOID CONST  lpReserved) {
    // Mark all unused parameters
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);

            LoadOriginalLibrary(hModule);

            if (GetSelfName(nullptr) == L"ACC.exe") {
                PatchACRogue();
            }

            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        default:
            break;
    }

    return TRUE;
}
