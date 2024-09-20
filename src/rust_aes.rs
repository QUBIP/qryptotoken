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
pub const MID_AES_SIZE_BYTES: usize = 32; /* 192 bits -> 256 as there is no 192 rust implementation */
pub const MAX_AES_SIZE_BYTES: usize = 32; /* 256 bits */
pub const AES_BLOCK_SIZE: usize = 16;

fn check_key_len(len: usize) -> KResult<()> {
    match len {
        16 | 32 => Ok(()),
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
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template)?;
        let len = self.get_key_buffer_len(&obj)?;
        check_key_len(len)?;
        if !obj.check_or_set_attr(from_ulong(CKA_VALUE_LEN, len as CK_ULONG))? {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    fn export_for_wrapping(&self, key: &Object) -> KResult<Vec<u8>> {
        SecretKeyFactory::export_for_wrapping(self, key)
    }

    fn import_from_wrapped(
        &self,
        mut data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        /* AES keys can only be 16, (not for Rust implementation 24), 32 bytes long,
         * ensure we allow only these sizes */
         match template.iter().position(|x| x.type_ == CKA_VALUE_LEN) {
            Some(idx) => {
                let len = template[idx].to_ulong()? as usize;
                if len > data.len() {
                    data.zeroize();
                    return err_rv!(CKR_KEY_SIZE_RANGE);
                }
                if len < data.len() {
                    unsafe { data.set_len(len) };
                }
            }
            None => (),
        }
        match check_key_len(data.len()) {
            Ok(_) => (),
            Err(e) => {
                data.zeroize();
                return Err(e);
            }
        }
        SecretKeyFactory::import_from_wrapped(self, data, template)
    }

    fn default_object_derive(
            &self,
            template: &[CK_ATTRIBUTE],
            origin: &Object,
        ) -> KResult<Object> {
            let obj = self.internal_object_derive(template, origin)?;

            let key_len = self.get_key_len(&obj);
            if key_len != 0 {
                if check_key_len(key_len).is_err() {
                    return err_rv!(CKR_TEMPLATE_INCONSISTENT);
                }
            }
            Ok(obj)
        }

    fn as_secret_key_factory(&self) -> KResult<&dyn SecretKeyFactory> {
        Ok(self)
    }
}

impl CommonKeyFactory for AesKeyFactory {}

impl SecretKeyFactory for AesKeyFactory {
    fn default_object_unwrap(
            &self,
            template: &[CK_ATTRIBUTE],
        ) -> KResult<Object> {
            ObjectFactory::default_object_unwrap(self, template)
        }

    fn set_key(&self, obj: &mut Object, key: Vec<u8>) -> KResult<()> {
        let keylen = key.len();
        check_key_len(keylen)?;
        obj.set_attr(from_bytes(CKA_VALUE, key))?;
        self.set_key_len(obj, keylen)?;
        Ok(())
    }

    fn recommend_key_size(&self, max: usize) -> KResult<usize> {
        if max >= MAX_AES_SIZE_BYTES {
            Ok(MAX_AES_SIZE_BYTES)
        } else if max > MID_AES_SIZE_BYTES {
            Ok(MID_AES_SIZE_BYTES)
        } else if max > MIN_AES_SIZE_BYTES {
            Ok(MIN_AES_SIZE_BYTES)
        } else {
            err_rv!(CKR_KEY_SIZE_RANGE)
        }
    }
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