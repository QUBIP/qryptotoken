// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms
#![allow(unused_imports)]

use super::super::error;
use super::super::interface;
use super::super::object;
use std::collections::HashMap;

use super::Storage;

use super::super::{err_not_found, err_rv};
use error::{KError, KResult};
use interface::*;
use object::Object;

use std::fmt::Debug;

#[derive(Debug)]
struct MemoryStorage {
    objects: HashMap<String, Object>,
}

impl Storage for MemoryStorage {
    fn open(&mut self, _filename: &String) -> KResult<()> {
        return err_rv!(CKR_GENERAL_ERROR);
    }
    fn reinit(&mut self) -> KResult<()> {
        self.objects.clear();
        Ok(())
    }
    fn flush(&mut self) -> KResult<()> {
        Ok(())
    }
    fn fetch_by_uid(&self, uid: &String) -> KResult<Object> {
        match self.objects.get(uid) {
            Some(o) => Ok(o.clone()),
            None => err_not_found! {uid.clone()},
        }
    }
    fn store(&mut self, uid: &String, obj: Object) -> KResult<()> {
        self.objects.insert(uid.clone(), obj);
        Ok(())
    }
    fn search(&self, template: &[CK_ATTRIBUTE]) -> KResult<Vec<Object>> {
        let mut ret = Vec::<Object>::new();
        for (_, o) in self.objects.iter() {
            if o.match_template(template) {
                ret.push(o.clone());
            }
        }
        Ok(ret)
    }
    fn remove_by_uid(&mut self, uid: &String) -> KResult<()> {
        self.objects.remove(uid);
        Ok(())
    }
}

pub fn memory() -> Box<dyn Storage> {
    Box::new(MemoryStorage {
        objects: HashMap::new(),
    })
}
