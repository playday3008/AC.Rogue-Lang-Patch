# AC Rogue Language Patcher

## Description / Theory

### tl;dr

Patch for the AC: Rogue to force change the language of the game.

### Theory

AC: Rogue has a region lock for the language. It means that you can't change the language of the game to the one that is not supported by your region.

Examples:

- If you have a WorldWide version of the game, you can't change the language to Russian.
- If you have a Russian version of the game, you can't change the language to English (only for UI).

#### localization.lang

Structure of the `localization.lang` was unknown (at least publicly), until now. So it wasn't easy to add missing languages to the game.

Simplified structure of the `localization.lang`:

```cpp
struct LocalizationLang
{
  char    language[4];                // "LANG"
  byte    preffered_subtitle_index;   // 0x1
  int32_t subtitle_language_bitfield; // 0b...0110 Means English and French is supported
  int32_t audio_language_bitfield;    // 0b...0010 Means English is supported
  byte    preffered_audio_index;      // 0x1
};
```

Check `tools\LocLangGenerator\localization.lang.struct.hexpat` for the complete structure. (Use [ImHex](https://github.com/WerWolv/ImHex) to view and use the file)

#### Inner Logic

Game utilizes the `localization.lang` file to determine the language of the game. But depends on inner logic, it can also change game id.

Here's that inner logic:

```cpp
int GetGameId(void)
{  
  if (DoesHaveRussian()) {
    return 0x4a2 + IsSteam(); // 0x4a2 + 0x1 = 0x4a3
  }
  
  if (DoesHaveKorean()) {
    if (DoesHaveChinese()) {
      return 0x67d + IsSteam(); // 0x67d + 0x1 = 0x67e
    }
  }

  // WorldWide
  if (IsSteam()) {
    return 0x3a6;
  } else {
    return 0x37f;
  }
}
```

#### Conclusion

As we can see, game can report 6 different game ids, but probably you only own one version of the game, so, that's the problem. Patch allows to report the desired game id, so you can change the language to the desired one.

## Usage / Installation

Just take `ACRogueLangPatcher.dll`, rename it to `version.dll`, then copy it and `patch_config.ini` to the game directory. Change `Region` field in the `patch_config.ini` to the desired region.

Also you can use `loc-lang-gen.exe`, to enable/disable particular localization. Just load `localization.lang` change stuff and save it.

Don't forget to download language files used by chosen language (audio and video files). You can find them in the internet.

## Credits

- [**@ThirteenAG**](https://github.com/ThirteenAG)
  - For the [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)
    - Basically ***Ultimate*** Proxy DLL implementation
  - For the [injector](https://github.com/ThirteenAG/injector)
    - Easy to use memory injection library
  - For the [Hooking.Patterns](https://github.com/ThirteenAG/Hooking.Patterns)
    - Easy to use pattern scanning library

- [**@metayeti**](https://github.com/metayeti)
  - For the [mINI](https://github.com/metayeti/mINI)
    - Easy to use INI reader/writer library

- [**@fyne-io**](https://github.com/fyne-io)
  - For the [Fyne](https://fyne.io)
    - "Easy" to use GUI library

- [**@WerWolv**](https://github.com/WerWolv)
  - For the [ImHex](https://github.com/WerWolv/ImHex)
    - Best hex editor ever (IMO)

- [**@NationalSecurityAgency**](https://github.com/NationalSecurityAgency)
  - For the [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
    - Best decompiler ever (IMO)
    - Scariest debugger ever (IMO)

- [x64dbg Contributors](https://x64dbg.com/#credits)
  - For the [x64dbg](https://x64dbg.com)
    - Powerful yet simple to use debugger
