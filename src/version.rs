// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms
use super::interface::*;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const fn parse_major_minor(version: &str) -> (u8, u8) {
    let bytes = version.as_bytes();
    let mut major = 0u8;
    let mut minor = 0u8;
    let mut i = 0;

    // Parse major version
    while i < bytes.len() && bytes[i] != b'.' {
        major = major * 10 + (bytes[i] - b'0');
        i += 1;
    }

    i += 1; // skip '.'

    // Parse minor version
    while i < bytes.len() && bytes[i] != b'.' {
        minor = minor * 10 + (bytes[i] - b'0');
        i += 1;
    }

    (major, minor)
}

pub const fn make_slot_description() -> [CK_UTF8CHAR; 64] {
    // Build the base string at compile time
    let s =
        const_format::concatcp!(env!("CARGO_PKG_NAME"), " v", VERSION, " Slot");
    let bytes = s.as_bytes();

    let mut buf = [b' '; 64];
    let mut i = 0;
    while i < bytes.len() && i < 64 {
        buf[i] = bytes[i];
        i += 1;
    }
    buf
}

pub static MAJOR: u8 = parse_major_minor(VERSION).0;
pub static MINOR: u8 = parse_major_minor(VERSION).1;
