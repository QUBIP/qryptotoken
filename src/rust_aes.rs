use aes_gcm::{aead::{Aead, KeyInit, OsRng}, AeadCore, Aes128Gcm, Aes256Gcm, Key, Nonce};
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

use once_cell::sync::Lazy;
use std::fmt::Debug;

pub const MIN_AES_SIZE_BYTES: usize = 16; /* 128 bits */
pub const MID_AES_SIZE_BYTES: usize = 24; /* 192 bits */
pub const MAX_AES_SIZE_BYTES: usize = 32; /* 256 bits */
pub const AES_BLOCK_SIZE: usize = 16;

fn check_key_len(len: usize) -> KResult<()> {
    match len {
        16 | 24 | 32 => Ok(()),
        _ => err_rv!(CKR_KEY_SIZE_RANGE),
    }
}

#[derive(Debug)]
pub struct AesKeyFactory {
    attributes: Vec<ObjectAttr>,
}

impl AesKeyFactory {
    fn new() -> AesKeyFactory {
        let mut data: AesKeyFactory = AesKeyFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes.append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes.append(&mut data.init_common_secret_key_attrs());
        data.attributes.push(attr_element!(CKA_VALUE; OAFlags::Defval | OAFlags::Sensitive | OAFlags::RequiredOnCreate | OAFlags::SettableOnlyOnCreate; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_VALUE_LEN; OAFlags::RequiredOnGenerate; from_bytes; val Vec::new()));

        /* default to private */
        let private = attr_element!(CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy; from_bool; val true);
        match data
            .attributes
            .iter()
            .position(|x| x.get_type() == CKA_PRIVATE)
        {
            Some(idx) => data.attributes[idx] = private,
            None => data.attributes.push(private),
        }

        data
    }
}

impl ObjectFactory for AesKeyFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> { todo!()}

    fn get_attributes(&self) -> &Vec<ObjectAttr> {todo!()}

    fn export_for_wrapping(&self, key: &Object) -> KResult<Vec<u8>> {todo!()}

    fn import_from_wrapped(
        &self,
        mut data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {todo!()}

    fn default_object_derive(
            &self,
            template: &[CK_ATTRIBUTE],
            origin: &Object,
        ) -> KResult<Object> {todo!()}

    fn as_secret_key_factory(&self) -> KResult<&dyn SecretKeyFactory> {todo!()}
}

impl CommonKeyFactory for AesKeyFactory {}

impl SecretKeyFactory for AesKeyFactory {
    fn default_object_unwrap(
            &self,
            template: &[CK_ATTRIBUTE],
        ) -> KResult<Object> {todo!()}

    fn set_key(&self, obj: &mut Object, key: Vec<u8>) -> KResult<()> {todo!()}

    fn recommend_key_size(&self, _: usize) -> KResult<usize> {todo!()}
}

static AES_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(AesKeyFactory::new()));

#[derive(Debug)]
struct AesMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for AesMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {todo!()}

    fn encryption_new(
            &self,
            _: &CK_MECHANISM,
            _: &object::Object,
        ) -> KResult<Box<dyn Encryption>> {todo!()}

    fn decryption_new(
            &self,
            _: &CK_MECHANISM,
            _: &object::Object,
        ) -> KResult<Box<dyn Decryption>> {todo!()}
    
    fn generate_key(
            &self,
            _: &CK_MECHANISM,
            _: &[CK_ATTRIBUTE],
            _: &Mechanisms,
            _: &ObjectFactories,
        ) -> KResult<Object> {todo!()}

    fn wrap_key(
            &self,
            _: &CK_MECHANISM,
            _: &object::Object,
            _: &object::Object,
            _: CK_BYTE_PTR,
            _: CK_ULONG_PTR,
            _: &Box<dyn ObjectFactory>,
        ) -> KResult<()> {todo!()}

    fn unwrap_key(
            &self,
            _: &CK_MECHANISM,
            _: &object::Object,
            _: &[u8],
            _: &[CK_ATTRIBUTE],
            _: &Box<dyn ObjectFactory>,
        ) -> KResult<Object> {todo!()}
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    AesOperation::register_mechanisms(mechs);

    ot.add_factory(ObjectType::new(CKO_SECRET_KEY, CKK_AES), &AES_KEY_FACTORY);
}

#[derive(Debug)]
struct AesKey {
    raw: Vec<u8>,
}

impl Drop for AesKey {
    fn drop(&mut self) {
        self.raw.zeroize()
    }
}


fn new_mechanism(flags: CK_FLAGS) -> Box<dyn Mechanism> {
    Box::new(AesMechanism {
        info: CK_MECHANISM_INFO {
            ulMinKeySize: MIN_AES_SIZE_BYTES as CK_ULONG,
            ulMaxKeySize: MAX_AES_SIZE_BYTES as CK_ULONG,
            flags: flags,
        },
    })
}


#[derive(Debug)]
struct AesParams {
    iv: Vec<u8>,
    aad: Vec<u8>,
    taglen: usize,
}

#[derive(Debug)]
struct AesOperation {
    mech: CK_MECHANISM_TYPE,
    key: AesKey,
    params: AesParams,
    finalized: bool,
    in_use: bool,
    finalbuf: Vec<u8>,
}

impl Drop for AesOperation {
    fn drop(&mut self) {
        self.finalbuf.zeroize()
    }
}

enum AesGcmCipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

impl AesOperation {
    fn register_mechanisms(mechs: &mut Mechanisms) {todo!()}

    fn init_params(mech: &CK_MECHANISM) -> KResult<AesParams> {todo!()}

    fn init_cipher(
        mech: CK_MECHANISM_TYPE,
        key: &[u8],
    ) -> KResult<AesGcmCipher> {todo!()}

    fn encrypt_initialize(&mut self) -> KResult<()> {todo!()}
    
    fn decrypt_initialize(&mut self) -> KResult<()> {todo!()}

    fn encrypt_new(mech: &CK_MECHANISM, key: &Object) -> KResult<AesOperation> {todo!()} 

    fn decrypt_new(mech: &CK_MECHANISM, key: &Object) -> KResult<AesOperation> {todo!()} 

    fn wrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        mut keydata: Vec<u8>,
        output: CK_BYTE_PTR,
        output_len: CK_ULONG_PTR,
    ) -> KResult<()> {todo!()}
    
    fn unwrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        data: &[u8],
    ) -> KResult<Vec<u8>> {todo!()}
}

impl MechOperation for AesOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Encryption for AesOperation {
    fn encrypt(
        &mut self,
        plain: &[u8],
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {todo!()}

    fn encrypt_update(
            &mut self,
            _plain: &[u8],
            _cipher: CK_BYTE_PTR,
            _cipher_len: CK_ULONG_PTR,
        ) -> KResult<()> {todo!()}

    fn encrypt_final(
            &mut self,
            _cipher: CK_BYTE_PTR,
            _cipher_len: CK_ULONG_PTR,
        ) -> KResult<()> {todo!()}

    fn encryption_len(&self, _data_len: CK_ULONG) -> KResult<usize> {todo!()}
}

impl Decryption for AesOperation {
    fn decrypt(
            &mut self,
            _cipher: &[u8],
            _plain: CK_BYTE_PTR,
            _plain_len: CK_ULONG_PTR,
        ) -> KResult<()> {todo!()}

    fn decrypt_update(
            &mut self,
            _cipher: &[u8],
            _plain: CK_BYTE_PTR,
            _plain_len: CK_ULONG_PTR,
        ) -> KResult<()> {todo!()}

    fn decrypt_final(
            &mut self,
            _plain: CK_BYTE_PTR,
            _plain_len: CK_ULONG_PTR,
        ) -> KResult<()> {todo!()}

    fn decryption_len(&self, _data_len: CK_ULONG) -> KResult<usize> {todo!()}
}