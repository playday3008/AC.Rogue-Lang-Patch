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
    mINI::INIFile      file("patch_config.ini");
    mINI::INIStructure ini;
    file.read(ini);

    if (!ini.has("Spoof"))
        return;

    // Spoof Uplay ID
    [&]() {
        static enum class eACRogueUplayId {
            UplayWW   = 0x37F,
            UplayRU   = 0x4A2,
            UplayAsia = 0x67D,
            SteamWW   = 0x3A6,
            SteamRU   = UplayRU + 1,
            SteamAsia = UplayAsia + 1,
        } eACRogueUplayId;

        if (ini["Spoof"].has("Region")) {
            const auto uplay_id = ini["Spoof"]["Region"];
            if (uplay_id == "WW")
                eACRogueUplayId = eACRogueUplayId::UplayWW;
            else if (uplay_id == "RU")
                eACRogueUplayId = eACRogueUplayId::UplayRU;
            else if (uplay_id == "Asia")
                eACRogueUplayId = eACRogueUplayId::UplayAsia;
            else
                return;
        } else {
            return;
        }

        /**
         * 0000000140003040 | 48:83EC 28     | sub rsp,0x28                     |
         * 0000000140003044 | B9 0C000000    | mov ecx,0xC                      |
         * 0000000140003049 | E8 427E0000    | call acc.14000AE90               |
         * 000000014000304E | 84C0           | test al,al                       |
         * 0000000140003050 | 74 17          | je acc.140003069                 |
         * 0000000140003052 | E8 A98F1700    | call acc.14017C000               |
         * 0000000140003057 | 33C9           | xor ecx,ecx                      |
         * 0000000140003059 | 84C0           | test al,al                       |
         * 000000014000305B | 0F95C1         | setne cl                         | <- Steam ID (RU)
         * 000000014000305E | 8D81 A2040000  | lea eax,qword ptr ds:[rcx+0x4A2] | <- Uplay ID (RU)
         * 0000000140003064 | 48:83C4 28     | add rsp,0x28                     |
         * 0000000140003068 | C3             | ret                              |
         * 0000000140003069 | B9 0B000000    | mov ecx,0xB                      |
         * 000000014000306E | E8 1D7E0000    | call acc.14000AE90               |
         * 0000000140003073 | 84C0           | test al,al                       |
         * 0000000140003075 | 74 25          | je acc.14000309C                 |
         * 0000000140003077 | B9 06000000    | mov ecx,0x6                      |
         * 000000014000307C | E8 0F7E0000    | call acc.14000AE90               |
         * 0000000140003081 | 84C0           | test al,al                       |
         * 0000000140003083 | 74 17          | je acc.14000309C                 |
         * 0000000140003085 | E8 768F1700    | call acc.14017C000               |
         * 000000014000308A | 33C9           | xor ecx,ecx                      |
         * 000000014000308C | 84C0           | test al,al                       |
         * 000000014000308E | 0F95C1         | setne cl                         | <- Steam ID (Asia)
         * 0000000140003091 | 8D81 7D060000  | lea eax,qword ptr ds:[rcx+0x67D] | <- Uplay ID (Asia)
         * 0000000140003097 | 48:83C4 28     | add rsp,0x28                     |
         * 000000014000309B | C3             | ret                              |
         * 000000014000309C | E8 5F8F1700    | call acc.14017C000               |
         * 00000001400030A1 | B9 7F030000    | mov ecx,0x37F                    | <- Uplay ID (WW)
         * 00000001400030A6 | BA A6030000    | mov edx,0x3A6                    | <- Steam ID (WW)
         * 00000001400030AB | 84C0           | test al,al                       |
         * 00000001400030AD | 0F45CA         | cmovne ecx,edx                   |
         * 00000001400030B0 | 8BC1           | mov eax,ecx                      |
         * 00000001400030B2 | 48:83C4 28     | add rsp,0x28                     |
         * 00000001400030B6 | C3             | ret                              |
         */
        auto hookGetUplayId = hook::pattern(
            "48 83 EC 28 B9 ? ? ? ? E8 ? ? ? ? 84 C0 74 ? E8 ? ? ? ? 33 C9 84 C0 0F 95 C1 8D 81 ? ? ? ? 48 83 C4 28 C3");
        if (!hookGetUplayId.count_hint(1).empty()) {
            static auto hookIsSteam = injector::GetBranchDestination(hookGetUplayId.get_first(18));
            
            constexpr uintptr_t hook_offset   = 0x0;
            constexpr uintptr_t hook_jmp_size = 0x5;
            struct SpoofUplayId {
                void operator()(injector::reg_pack &regs) const {
                    byte isSteam = injector::fastcall<byte(void)>::call(hookIsSteam);

                    switch (eACRogueUplayId) {
                        case eACRogueUplayId::UplayWW:
                            if (isSteam)
                                regs.rax = static_cast<uint32_t>(eACRogueUplayId::SteamWW);
                            else
                                regs.rax = static_cast<uint32_t>(eACRogueUplayId::UplayWW);
                            break;
                        case eACRogueUplayId::UplayRU:
                            if (isSteam)
                                regs.rax = static_cast<uint32_t>(eACRogueUplayId::SteamRU);
                            else
                                regs.rax = static_cast<uint32_t>(eACRogueUplayId::UplayRU);
                            break;
                        case eACRogueUplayId::UplayAsia:
                            if (isSteam)
                                regs.rax = static_cast<uint32_t>(eACRogueUplayId::SteamAsia);
                            else
                                regs.rax = static_cast<uint32_t>(eACRogueUplayId::UplayAsia);
                            break;
                        default:
                            break;
                    }
                }
            };
            injector::MakeInline<SpoofUplayId>(hookGetUplayId.get_first(hook_offset));
            injector::MakeRET(hookGetUplayId.get_first(hook_offset + hook_jmp_size));
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

            PatchACRogue();

            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        default:
            break;
    }

    return TRUE;
}
