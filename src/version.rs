// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms
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

pub static MAJOR: u8 = parse_major_minor(VERSION).0;
pub static MINOR: u8 = parse_major_minor(VERSION).1;
