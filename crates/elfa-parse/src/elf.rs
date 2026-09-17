//! ELF constants and their names.
//!
//! Only what the parser and the CLI need to render a file legibly. Names are returned as
//! `Option<&'static str>` so an unknown value prints as a number rather than as a lie.

pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;

pub const EHDR64_SIZE: u64 = 64;
pub const PHDR64_SIZE: u64 = 56;
pub const SHDR64_SIZE: u64 = 64;
pub const SYM64_SIZE: u64 = 24;
pub const RELA64_SIZE: u64 = 24;
pub const REL64_SIZE: u64 = 16;
pub const DYN64_SIZE: u64 = 16;
pub const RELR64_SIZE: u64 = 8;

/// `e_phnum` sentinel: the real count lives in `shdr[0].sh_info`.
pub const PN_XNUM: u16 = 0xffff;

pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_PREINIT_ARRAY: u32 = 16;
pub const SHT_RELR: u32 = 19;
pub const SHT_GNU_HASH: u32 = 0x6fff_fff6;
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
pub const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;

pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_STRTAB: u64 = 5;
pub const DT_SONAME: u64 = 14;
pub const DT_RPATH: u64 = 15;
pub const DT_RUNPATH: u64 = 29;
pub const DT_INIT: u64 = 12;
pub const DT_INIT_ARRAY: u64 = 25;
pub const DT_INIT_ARRAYSZ: u64 = 27;
pub const DT_FLAGS: u64 = 30;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
pub const DF_BIND_NOW: u64 = 0x8;

#[must_use]
pub fn et_name(v: u16) -> Option<&'static str> {
    Some(match v {
        0 => "ET_NONE",
        1 => "ET_REL",
        2 => "ET_EXEC",
        3 => "ET_DYN",
        4 => "ET_CORE",
        _ => return None,
    })
}

#[must_use]
pub fn em_name(v: u16) -> Option<&'static str> {
    Some(match v {
        3 => "EM_386",
        40 => "EM_ARM",
        62 => "EM_X86_64",
        183 => "EM_AARCH64",
        243 => "EM_RISCV",
        _ => return None,
    })
}

#[must_use]
pub fn pt_name(v: u32) -> Option<&'static str> {
    Some(match v {
        0 => "PT_NULL",
        1 => "PT_LOAD",
        2 => "PT_DYNAMIC",
        3 => "PT_INTERP",
        4 => "PT_NOTE",
        6 => "PT_PHDR",
        7 => "PT_TLS",
        0x6474_e550 => "PT_GNU_EH_FRAME",
        0x6474_e551 => "PT_GNU_STACK",
        0x6474_e552 => "PT_GNU_RELRO",
        0x6474_e553 => "PT_GNU_PROPERTY",
        _ => return None,
    })
}

#[must_use]
pub fn sht_name(v: u32) -> Option<&'static str> {
    Some(match v {
        SHT_NULL => "SHT_NULL",
        SHT_PROGBITS => "SHT_PROGBITS",
        SHT_SYMTAB => "SHT_SYMTAB",
        SHT_STRTAB => "SHT_STRTAB",
        SHT_RELA => "SHT_RELA",
        SHT_HASH => "SHT_HASH",
        SHT_DYNAMIC => "SHT_DYNAMIC",
        SHT_NOTE => "SHT_NOTE",
        SHT_NOBITS => "SHT_NOBITS",
        SHT_REL => "SHT_REL",
        SHT_DYNSYM => "SHT_DYNSYM",
        SHT_INIT_ARRAY => "SHT_INIT_ARRAY",
        SHT_FINI_ARRAY => "SHT_FINI_ARRAY",
        SHT_PREINIT_ARRAY => "SHT_PREINIT_ARRAY",
        SHT_RELR => "SHT_RELR",
        SHT_GNU_HASH => "SHT_GNU_HASH",
        SHT_GNU_VERDEF => "SHT_GNU_VERDEF",
        SHT_GNU_VERNEED => "SHT_GNU_VERNEED",
        SHT_GNU_VERSYM => "SHT_GNU_VERSYM",
        _ => return None,
    })
}

#[must_use]
pub fn dt_name(v: u64) -> Option<&'static str> {
    Some(match v {
        0 => "DT_NULL",
        1 => "DT_NEEDED",
        2 => "DT_PLTRELSZ",
        3 => "DT_PLTGOT",
        4 => "DT_HASH",
        5 => "DT_STRTAB",
        6 => "DT_SYMTAB",
        7 => "DT_RELA",
        8 => "DT_RELASZ",
        9 => "DT_RELAENT",
        10 => "DT_STRSZ",
        11 => "DT_SYMENT",
        12 => "DT_INIT",
        13 => "DT_FINI",
        14 => "DT_SONAME",
        15 => "DT_RPATH",
        16 => "DT_SYMBOLIC",
        17 => "DT_REL",
        18 => "DT_RELSZ",
        19 => "DT_RELENT",
        20 => "DT_PLTREL",
        21 => "DT_DEBUG",
        22 => "DT_TEXTREL",
        23 => "DT_JMPREL",
        24 => "DT_BIND_NOW",
        25 => "DT_INIT_ARRAY",
        26 => "DT_FINI_ARRAY",
        27 => "DT_INIT_ARRAYSZ",
        28 => "DT_FINI_ARRAYSZ",
        29 => "DT_RUNPATH",
        30 => "DT_FLAGS",
        32 => "DT_PREINIT_ARRAY",
        33 => "DT_PREINIT_ARRAYSZ",
        35 => "DT_RELRSZ",
        36 => "DT_RELR",
        37 => "DT_RELRENT",
        0x6fff_fef5 => "DT_GNU_HASH",
        0x6fff_fffb => "DT_FLAGS_1",
        0x6fff_fffe => "DT_VERNEED",
        0x6fff_ffff => "DT_VERNEEDNUM",
        0x6fff_fff0 => "DT_VERSYM",
        _ => return None,
    })
}

/// x86-64 relocation types. Other architectures land in phase 5; until then an
/// unrecognised type prints as a number, which is honest.
#[must_use]
pub fn r_x86_64_name(v: u32) -> Option<&'static str> {
    Some(match v {
        0 => "R_X86_64_NONE",
        1 => "R_X86_64_64",
        5 => "R_X86_64_COPY",
        6 => "R_X86_64_GLOB_DAT",
        7 => "R_X86_64_JUMP_SLOT",
        8 => "R_X86_64_RELATIVE",
        9 => "R_X86_64_GOTPCREL",
        16 => "R_X86_64_DTPMOD64",
        17 => "R_X86_64_DTPOFF64",
        18 => "R_X86_64_TPOFF64",
        36 => "R_X86_64_TLSDESC",
        37 => "R_X86_64_IRELATIVE",
        _ => return None,
    })
}

#[must_use]
pub fn st_type_name(info: u8) -> Option<&'static str> {
    Some(match info & 0xf {
        0 => "NOTYPE",
        1 => "OBJECT",
        2 => "FUNC",
        3 => "SECTION",
        4 => "FILE",
        6 => "TLS",
        10 => "GNU_IFUNC",
        _ => return None,
    })
}
