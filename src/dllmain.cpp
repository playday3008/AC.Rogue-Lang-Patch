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

        OutputDebugString(TEXT("AC: Rogue Patcher -> Removing Black Bars...\n"));

        static hook::pattern hookScreenConfigPtr;
        static hook::pattern hookTargetAspectRatioPtr;
        static hook::pattern hookScreenConfig;
        static hook::pattern hookAspectRatio;
        static hook::pattern hookScreenHeight;
        static hook::pattern hookScreenHeightInv;
        static hook::pattern hookFov;
        static hook::pattern hookIsGameUnpausedPtr;
        static hook::pattern hookIsGamePausedPtr;

        static injector::memory_pointer_raw ptrAspectRatio;
        static injector::memory_pointer_raw ptrAspectRatioInv;
        static injector::memory_pointer_raw ptrScreenWidth;
        static injector::memory_pointer_raw ptrScreenWidthInv;
        static injector::memory_pointer_raw ptrScreenHeight;
        static injector::memory_pointer_raw ptrScreenHeightInv;
        static injector::memory_pointer_raw ptrTargetAspectRatio;

        // In-game values
        static const float fStockScreenWidth  = 1280.f;
        static const float fStockScreenHeight = 720.f;

        static float fAspectRatio    = fStockScreenWidth / fStockScreenHeight; // Placeholder Value
        static float fAspectRatioInv = 1.f / fAspectRatio;                     // Placeholder Value

        static float fScreenWidth     = fStockScreenWidth;
        static float fScreenWidthInv  = 1.f / fScreenWidth;
        static float fScreenHeight    = fStockScreenHeight;
        static float fScreenHeightInv = 1.f / fScreenHeight;

        static float desiredFov = 90.f; // Horizontal FOV

        static bool isInGame = false;

        // Patterns
        {
            // clang-format off
            hookScreenConfigPtr = hook::pattern(GetModuleHandle(nullptr),
                "45 0F 2F C1 "             // [0.....3] ACC.exe+5447ED - comiss xmm8,xmm9
                "41 0F 28 F0 "             // [4.....7] ACC.exe+5447F1 - movaps xmm6,xmm8
                "41 0F 28 F9 "             // [8....11] ACC.exe+5447F5 - movaps xmm7,xmm9
                "76 23 "                   // [12...13] ACC.exe+5447F9 - jna ---------------------------------+
                "41 0F 28 F8 "             // [14...17] ACC.exe+5447FB - movaps xmm7,xmm8                     |
                "F3 0F 59 3D ? ? ? ? "     // [18...25] ACC.exe+5447FF - mulss xmm7,[ACC.exe+AspectRatioInv]  |
                "44 0F 2F CF "             // [26...29] ACC.exe+544807 - comiss xmm9,xmm7                     |
                "77 04 "                   // [30...31] ACC.exe+54480B - ja -----------------+                |
                "41 0F 28 F9 "             // [32...35] ACC.exe+54480D - movaps xmm7,xmm9    |                |
                "0F 28 E7 "                // [36...38] ACC.exe+544811 - movaps xmm4,xmm7 <--+                |
                "F3 0F 59 25 ? ? ? ? "     // [39...46] ACC.exe+544814 - mulss xmm4,[ACC.exe+ScreenWidthInv]  |
                "EB 21 "                   // [47...48] ACC.exe+54481C - jmp ACC.exe+54483F ------------------+--+
                "41 0F 28 F1 "             // [49...52] ACC.exe+54481E - movaps xmm6,xmm9 <-------------------+  |
                "F3 0F 59 35 ? ? ? ? "     // [53...60] ACC.exe+544822 - mulss xmm6,[ACC.exe+AspectRatio]        |
                "44 0F 2F C6 "             // [61...64] ACC.exe+54482A - comiss xmm8,xmm6                        |
                "77 04 "                   // [65...66] ACC.exe+54482E - ja -----------------+                   |
                "41 0F 28 F0 "             // [67...70] ACC.exe+544830 - movaps xmm6,xmm8    |                   |
                "0F 28 E6 "                // [71...73] ACC.exe+544834 - movaps xmm4,xmm6 <--+                   |
                "F3 0F 59 25 ? ? ? ? "     // [74...81] ACC.exe+544837 - mulss xmm4,[ACC.exe+ScreenHeightInv]    |
                "48 8B 4B 20 "             // [82...85] ACC.exe+54483F - mov rcx,[rbx+20] <----------------------+
                "0F 28 C4 "                // [86...88] ACC.exe+544843 - movaps xmm0,xmm4
                "F3 0F 59 25 ? ? ? ? "     // [89...96] ACC.exe+544846 - mulss xmm4,[ACC.exe+ScreenHeight]
                "41 0F 28 C8 "             // [97..100] ACC.exe+54484E - movaps xmm1,xmm8
                "48 8D 94 24 D8 00 00 00 " // [101.108] ACC.exe+544852 - lea rdx,[rsp+000000D8]
                "4C 8D 8C 24 D0 00 00 00 " // [109.116] ACC.exe+54485A - lea r9,[rsp+000000D0]
                "F3 0F 59 05 ? ? ? ? "     // [117.124] ACC.exe+544862 - mulss xmm0,[ACC.exe+ScreenWidth]
            );
            hookTargetAspectRatioPtr = hook::pattern(GetModuleHandle(nullptr),
                "8B 41 1C "            // ACC.exe+544060 - mov eax,[rcx+1C]
                "F3 0F 10 79 10 "      // ACC.exe+544063 - movss xmm7,[rcx+10]
                "66 0F EF C0 "         // ACC.exe+544068 - pxor xmm0,xmm0
                "F3 48 0F 2A C0 "      // ACC.exe+54406C - cvtsi2ss xmm0,rax
                "F3 0F 5E F8 "         // ACC.exe+544071 - divss xmm7,xmm0
                "F3 0F 10 76 40 "      // ACC.exe+544075 - movss xmm6,[rsi+40]
                "F3 0F 59 3D ? ? ? ? " // ACC.exe+54407A - mulss xmm7,[targetAspectRatio]
                "48 8B CE "            // ACC.exe+544082 - mov rcx,rsi
            );
            hookScreenConfig = hook::pattern(GetModuleHandle(nullptr),
                "F3 0F 5E C2 " // ACC.exe+5A24A7 - divss xmm0,xmm2
                "F3 0F 11 02 " // ACC.exe+5A24AB - movss [rdx],xmm0
                "0F 28 C3 "    // ACC.exe+5A24AF - movaps xmm0,xmm3
                "F3 0F 5C C5 " // ACC.exe+5A24B2 - subss xmm0,xmm5
                "F3 0F 5E EB " // ACC.exe+5A24b6 - divss xmm5,xmm3
            );
            hookAspectRatio = hook::pattern(GetModuleHandle(nullptr),
                "F3 0F 5E C1 "         // ACC.exe+5A243E - divss xmm0,xmm1
                "F3 0F 59 C4 "         // ACC.exe+5A2442 - mulss xmm0,xmm4
                "0F 2F E8 "            // ACC.exe+5A2446 - comiss xmm5,xmm0
                "76 ? "                // ACC.exe+5A2449 - jna ACC.exe+5A2476
                "0F 28 E8 "            // ACC.exe+5A244B - movaps xmm5,xmm0
                "EB ? "                // ACC.exe+5A244E - jmp ACC.exe+5A2485
                "F3 0F 10 05 ? ? ? ? " // ACC.exe+5A2450 - movss xmm0,[aspectRatioInv]
                "F3 0F 5E C1 "         // ACC.exe+5A2458 - divss xmm0,xmm1
                "F3 0F 59 C4 "         // ACC.exe+5A245C - mulss xmm0,xmm4
                "0F 2F E8 "            // ACC.exe+5A2460 - comiss xmm5,xmm0
            );
            hookScreenHeight = hook::pattern(GetModuleHandle(nullptr),
                "48 8B 4B 20 "         // ACC.exe+54483F - mov rcx,[rbx+20]
                "0F 28 C4 "            // ACC.exe+544843 - movaps xmm0,xmm4
                "F3 0F 59 25 ? ? ? ? " // ACC.exe+544846 - mulss xmm4,[screenHeight]
                "41 0F 28 C8 "         // ACC.exe+54484E - movaps xmm1,xmm8
                "48 8D 94 24 ? ? ? ? " // ACC.exe+544852 - lea rdx,[rsp+000000D8]
                "4C 8D 8C 24 ? ? ? ? " // ACC.exe+54485A - lea r9,[rsp+000000D0]
            );
            hookScreenHeightInv = hook::pattern(GetModuleHandle(nullptr),
                "F3 0F 59 35 ? ? ? ? "       // ACC.exe+5448BE - mulss xmm6,[screenWidthInv]
                "F3 44 0F 10 94 24 ? ? ? ? " // ACC.exe+5448C6 - movss xmm10,[rsp+000000D0]
                "F3 0F 59 3D ? ? ? ? "       // ACC.exe+5448D0 - mulss xmm7,[screenHeightInv]
                "F3 45 0F 5E D0 "            // ACC.exe+5448D8 - divss xmm10,xmm8
                "44 0F 28 84 24 ? ? ? ? "    // ACC.exe+5448DD - movaps xmm8,[rsp+00000080]
                "F3 44 0F 59 D6 "            // ACC.exe+5448E6 - mulss xmm10,xmm6
                "F3 0F 10 B4 24 ? ? ? ? "    // ACC.exe+5448EB - movss xmm6,[rsp+000000D8]
                "F3 41 0F 5E F1 "            // ACC.exe+5448F4 - divss xmm6,xmm9
                "44 0F 28 4C 24 70 "         // ACC.exe+5448F9 - movaps xmm9,[rsp+70]
                "F3 0F 59 F7 "               // ACC.exe+5448FF - mulss xmm6,xmm7
                "0F 28 7C 24 30 "            // ACC.exe+544903 - movaps xmm7,[rsp+30]
            );
            hookFov = hook::pattern(GetModuleHandle(nullptr),
                "48 89 53 18 "       // ACC.exe+345C59 - mov [rbx+18],rdx
                "48 89 53 20 "       // ACC.exe+345C5D - mov [rbx+20],rdx
                "48 8B 03 "          // ACC.exe+345C61 - mov rax,[rbx]
                "F3 0F 10 00 "       // ACC.exe+345C64 - movss xmm0,[rax]
                "F3 0F 11 44 24 30 " // ACC.exe+345C68 - movss [rsp+30],xmm0
            );
            hookIsGameUnpausedPtr = hook::pattern(GetModuleHandle(nullptr),
                "C6 81 C0 02 00 00 00 " // ACC.exe+28D472 - mov byte ptr [rcx+000002C0],00
                "48 8B 91 90 02 00 00 " // ACC.exe+28D479 - mov rdx,[rcx+00000290]
                "48 8B D9 "             // ACC.exe+28D480 - mov rbx,rcx
                "83 C8 FF "             // ACC.exe+28D483 - or eax,-01
                "F0 0F C1 42 08 "       // ACC.exe+28D486 - lock xadd [rdx+08],eax
                "FF C8 "                // ACC.exe+28D48B - dec eax
            );
            hookIsGamePausedPtr = hook::pattern(GetModuleHandle(nullptr),
                "48 C1 E1 20 "             // ACC.exe+292CB7 - shl rcx,20
                "48 C1 F9 3F "             // ACC.exe+292CBB - sar rcx,3F
                "48 23 08 "                // ACC.exe+292CBF - and rcx,[rax]
                "48 39 4A 18 "             // ACC.exe+292CC2 - cmp [rdx+18],rcx
                "75 08 "                   // ACC.exe+292CC6 - jne ACC.exe+292CD0
                "41 C6 80 C0 02 00 00 01 " // ACC.exe+292CC8 - mov byte ptr [r8+000002C0],01
                "F3 C3 "                   // ACC.exe+292CD0 - repe ret
            );
            // clang-format on
        }

        // Get pointers (1/2)
        if (!hookScreenConfigPtr.count_hint(1).empty()) {
            ptrAspectRatio    = injector::ReadRelativeOffset(hookScreenConfigPtr.get_first(0x39));
            ptrAspectRatioInv = injector::ReadRelativeOffset(hookScreenConfigPtr.get_first(0x16));

            ptrScreenWidth    = injector::ReadRelativeOffset(hookScreenConfigPtr.get_first(0x79));
            ptrScreenWidthInv = injector::ReadRelativeOffset(hookScreenConfigPtr.get_first(0x2B));

            ptrScreenHeight    = injector::ReadRelativeOffset(hookScreenConfigPtr.get_first(0x5D));
            ptrScreenHeightInv = injector::ReadRelativeOffset(hookScreenConfigPtr.get_first(0x4E));

            OutputDebugString(TEXT("\tGattering Pointers...(1/2)\n"));
        }

        // Get pointers (2/2)
        if (!hookTargetAspectRatioPtr.count_hint(1).empty()) {
            ptrTargetAspectRatio =
                injector::ReadRelativeOffset(hookTargetAspectRatioPtr.get_first(0x1E));

            OutputDebugString(TEXT("\tGattering Pointers...(2/2)\n"));
        }

        // Setup triggers (1/2)
        if (!hookIsGameUnpausedPtr.count_hint(1).empty()) {
            constexpr uintptr_t hook_offset = 0x0;
            constexpr uintptr_t hook_size   = 0x7;

            struct PatchIsGameRunning {
                void operator()(injector::reg_pack &regs) const {
                    isInGame = true;

                    // Part of the original code
                    *reinterpret_cast<byte *>(regs.rcx + 0x2C0) = 0;
                }
            };
            injector::MakeNOP(hookIsGameUnpausedPtr.get_first(hook_offset), hook_size);
            injector::MakeInline<PatchIsGameRunning>(hookIsGameUnpausedPtr.get_first(hook_offset));

            OutputDebugString(TEXT("\tSetting up triggers...(1/2)\n"));
        }

        // Setup triggers (2/2) (TODO: Improve this part)
        if (!hookIsGamePausedPtr.count_hint(1).empty()) {
            constexpr uintptr_t hook_offset = 0x11;
            constexpr uintptr_t hook_size   = 0x8;

            struct PatchIsGameRunning {
                void operator()(injector::reg_pack &regs) const {
                    isInGame = false;

                    // Part of the original code
                    *reinterpret_cast<byte *>(regs.r8 + 0x2C0) = 1;
                }
            };
            injector::MakeNOP(hookIsGamePausedPtr.get_first(hook_offset), hook_size);
            injector::MakeInline<PatchIsGameRunning>(hookIsGamePausedPtr.get_first(hook_offset));

            OutputDebugString(TEXT("\tSetting up triggers...(2/2)\n"));
        }

        // Patch Screen Config
        if (!hookScreenConfig.count_hint(1).empty()) {
            constexpr uintptr_t hook_offset = 0x8;
            constexpr uintptr_t hook_size   = 0x7;

            struct PatchScreenConfig {
                void operator()(injector::reg_pack &regs) const {
                    // movss xmm4,dword ptr ds:[rax+0x10]
                    // movss xmm5,dword ptr ds:[rax+0x14]
                    const float _fScreenWidth  = *reinterpret_cast<float *>(regs.rax + 0x10);
                    const float _fScreenHeight = *reinterpret_cast<float *>(regs.rax + 0x14);

                    if (isInGame) {
                        fAspectRatio = _fScreenWidth / _fScreenHeight;
                        // fScreenWidth     = _fScreenWidth;
                        // fScreenHeight    = _fScreenHeight;
                    } else {
                        fAspectRatio = fStockScreenWidth / fStockScreenHeight;
                        // fScreenWidth     = fStockScreenWidth;
                        // fScreenHeight    = fStockScreenHeight;
                    }
                    fAspectRatioInv = 1.f / fAspectRatio;
                    // fScreenWidthInv  = 1.f / fScreenWidth;
                    // fScreenHeightInv = 1.f / fScreenHeight;

                    injector::WriteMemory(ptrAspectRatio, fAspectRatio, true);
                    // injector::WriteMemory(ptrAspectRatioInv, fAspectRatioInv, true);
                    // injector::WriteMemory(ptrScreenWidth, fScreenWidth, true);
                    // injector::WriteMemory(ptrScreenWidthInv, fScreenWidthInv, true);
                    // injector::WriteMemory(ptrScreenHeight, fScreenHeight, true); // HUD Stretch
                    // injector::WriteMemory(ptrScreenHeightInv, fScreenHeightInv, true);
                    injector::WriteMemory(ptrTargetAspectRatio, fAspectRatio, true);

                    // Part of the original code
                    regs.xmm0 = regs.xmm3;
                    regs.xmm0.f32[0] -= regs.xmm5.f32[0];
                }
            };
            injector::MakeNOP(hookScreenConfig.get_first(hook_offset), hook_size);
            injector::MakeInline<PatchScreenConfig>(hookScreenConfig.get_first(hook_offset));

            OutputDebugString(TEXT("\tApplying Screen Config...\n"));
        }

        // Patch Aspect Ratio
        if (!hookAspectRatio.count_hint(1).empty()) {
            constexpr uintptr_t hook_offset = 0x12;
            constexpr uintptr_t hook_size   = 0x8;

            struct PatchAspectRatio {
                void operator()(injector::reg_pack &regs) const {
                    regs.xmm0.f32[0] = fAspectRatioInv;
                }
            };
            injector::MakeNOP(hookAspectRatio.get_first(hook_offset), hook_size);
            injector::MakeInline<PatchAspectRatio>(hookAspectRatio.get_first(hook_offset));

            OutputDebugString(TEXT("\tApplying Target Aspect Ratio...\n"));
        }

        // Patch Screen Height
        if (!hookScreenHeight.count_hint(1).empty()) {
            constexpr uintptr_t hook_offset = 0x7;
            constexpr uintptr_t hook_size   = 0x8;

            struct PatchScreenHeight {
                void operator()(injector::reg_pack &regs) const {
                    regs.xmm4.f32[0] *= fScreenHeight;
                }
            };
            injector::MakeNOP(hookScreenHeight.get_first(hook_offset), hook_size);
            injector::MakeInline<PatchScreenHeight>(hookScreenHeight.get_first(hook_offset));

            OutputDebugString(TEXT("\tApplying Screen Height...\n"));
        }

        // Patch Screen Height Inv
        if (!hookScreenHeightInv.count_hint(1).empty()) {
            constexpr uintptr_t hook_offset = 0x12;
            constexpr uintptr_t hook_size   = 0x8;

            static bool bIsStretchHUD = false;

            if (ini["Patch"].has("StretchHUD") && ini["Patch"]["StretchHUD"] == "1") {
                bIsStretchHUD = true;
            }

            struct PatchScreenHeightInv {
                void operator()(injector::reg_pack &regs) const {
                    fScreenHeight    = bIsStretchHUD ? fStockScreenWidth / fAspectRatio
                                                     : fStockScreenHeight;
                    fScreenHeightInv = 1.f / (2 * fStockScreenHeight - fScreenHeight);
                    regs.xmm7.f32[0] *= fScreenHeightInv;
                }
            };
            injector::MakeNOP(hookScreenHeightInv.get_first(hook_offset), hook_size);
            injector::MakeInline<PatchScreenHeightInv>(hookScreenHeightInv.get_first(hook_offset));

            OutputDebugString(TEXT("\tApplying HUD Stretch...\n"));
        }

        // Patch FOV
        if (!hookFov.count_hint(1).empty()) {
            if (ini["Patch"].has("DesiredFov")) {
                desiredFov = std::stof(ini["Patch"]["DesiredFov"]);
            }

            constexpr uintptr_t hook_offset = 0xF;
            constexpr uintptr_t hook_size   = 0x6;

            struct PatchFov {
                void operator()(injector::reg_pack &regs) const {
                    static float multiplier = 1.f;

                    static float fLastAspectRatio = fStockScreenWidth / fStockScreenHeight;
                    if (fAspectRatio != fLastAspectRatio) {
                        fLastAspectRatio = fAspectRatio;
                        // clang-format off
                            static const float fDefaultFov =
                                std::atan(
                                    std::tan(
                                        desiredFov * std::numbers::pi_v<float> / 360.f
                                    ) / (fStockScreenWidth / fStockScreenHeight)
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
                    *reinterpret_cast<float *>(regs.rsp + 0x30) =
                        regs.xmm0.f32[0] * (isInGame ? multiplier : 1.f);
                }
            };
            injector::MakeNOP(hookFov.get_first(hook_offset), hook_size);
            injector::MakeInline<PatchFov>(hookFov.get_first(hook_offset));

            OutputDebugString(TEXT("\tApplying FOV...\n"));
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
