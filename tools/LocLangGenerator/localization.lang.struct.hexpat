#include <std/core.pat>
#include <std/io.pat>
#include <type/magic.pat>

bitfield Language {
    None        : 1;
    English     : 1;
    French      : 1;
    Spanish     : 1;
    Polish      : 1;
    German      : 1;
    ChineseTrad : 1;
    Hungarian   : 1;
    Italian     : 1;
    Japanese    : 1;
    Czech       : 1;
    Korean      : 1;
    Russian     : 1;
    Dutch       : 1;
    Danish      : 1;
    Norwegian   : 1;
    Swedish     : 1;
    Portuguese  : 1;
    Brazil      : 1;
    Finnish     : 1;
    Arabic      : 1;
    Mexican     : 1;
    LocTest     : 1;
    padding     : 9;
} [[bitfield_order(std::core::BitfieldOrder::LeastToMostSignificant, 32)]];

struct Lang {
    type::Magic<"LANG">;
    u8 subtitle_idx;
    be Language subtitle;
    be Language audio;
    u8 audio_idx;
};


Lang lang @ 0x00;
