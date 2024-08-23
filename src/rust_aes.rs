use aes_gcm::{aead::{Aead, KeyInit, OsRng}, AeadCore, Aes256Gcm, Key, Nonce};
use zeroize::Zeroize;

use crate::attribute;
use crate::error;
use crate::interface;
use crate::object;
use crate::{attr_element, err_rv};

use crate::attribute::{from_bytes, from_bool, from_ulong};
use crate::error::{KError, KResult};
use interface::*;
use crate::object::{
    CommonKeyFactory, OAFlags, Object, ObjectAttr, ObjectFactories,
    ObjectFactory, ObjectType, SecretKeyFactory,
};

use crate::mechanism;
use mechanism::*;