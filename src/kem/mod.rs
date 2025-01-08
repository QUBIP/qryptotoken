use super::attribute;
use crate::attribute::{from_bool, from_bytes, from_ulong};
use crate::error::*;
use crate::interface::*;
use crate::mechanism::*;
use crate::object::*;
use crate::session;
use crate::session::*;
use crate::slot;
use crate::token;
use crate::token::Token;
use crate::{attr_element, bytes_attr_not_empty, err_rv};
use libcrux::kem::*;
use rand::rngs::OsRng;

use crate::error;

use once_cell::sync::Lazy;
use std::fmt::Debug;

use std::collections::HashMap;

pub mod mlkem;

#[derive(Debug, Clone)]
pub struct Handles {
    map: HashMap<CK_OBJECT_HANDLE, String>,
    rev: HashMap<String, CK_OBJECT_HANDLE>,
    next: CK_OBJECT_HANDLE,
}

impl Handles {
    pub fn new() -> Handles {
        Handles {
            map: HashMap::new(),
            rev: HashMap::new(),
            next: 1,
        }
    }

    pub fn get(&self, handle: CK_OBJECT_HANDLE) -> Option<&String> {
        self.map.get(&handle)
    }

    pub fn next(&mut self) -> CK_OBJECT_HANDLE {
        let next = self.next;
        self.next += 1;
        next
    }
}
