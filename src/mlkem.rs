// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms
use libcrux_kem::*;

use crate::attribute::from_bytes;
use crate::error::*;
use crate::interface::*;
use crate::mechanism::*;
use crate::object::*;
use crate::{attr_element, err_rv};

use once_cell::sync::Lazy;
use std::fmt::Debug;

#[derive(Debug)]
pub struct MlKemPubFactory {
    attributes: Vec<ObjectAttr>,
}

impl MlKemPubFactory {
    pub fn new() -> MlKemPubFactory {
        let mut data = MlKemPubFactory {
            attributes: Vec::new(),
        };
        data.attributes.push(attr_element!(CKA_PUBLIC_KEY_INFO; OAFlags::RequiredOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data
    }
}

impl ObjectFactory for MlKemPubFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let obj = self.default_object_create(template)?;
        if obj.get_attr(CKA_PUBLIC_KEY_INFO).is_none() {
            return err_rv!(CKR_TEMPLATE_INCOMPLETE);
        }
        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyFactory for MlKemPubFactory {}
impl PubKeyFactory for MlKemPubFactory {}

#[derive(Debug)]
pub struct MlKemPrivFactory {
    attributes: Vec<ObjectAttr>,
}

impl MlKemPrivFactory {
    pub fn new() -> MlKemPrivFactory {
        let mut data = MlKemPrivFactory {
            attributes: Vec::new(),
        };
        data.attributes.push(attr_element!(CKA_VALUE; OAFlags::Sensitive | OAFlags::RequiredOnCreate; from_bytes; val Vec::new()));
        data
    }
}

impl ObjectFactory for MlKemPrivFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let obj = self.default_object_create(template)?;
        if obj.get_attr(CKA_VALUE).is_none() {
            return err_rv!(CKR_TEMPLATE_INCOMPLETE);
        }
        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    fn export_for_wrapping(&self, key: &Object) -> KResult<Vec<u8>> {
        PrivKeyFactory::export_for_wrapping(self, key)
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        PrivKeyFactory::import_from_wrapped(self, data, template)
    }
}

impl CommonKeyFactory for MlKemPrivFactory {}
impl PrivKeyFactory for MlKemPrivFactory {}

static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlKemPubFactory::new()));

static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlKemPrivFactory::new()));

#[derive(Debug)]
pub struct MlKemMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for MlKemMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn wrap_key(
        &self,
        _mech: &CK_MECHANISM,
        wrapping_key: &Object,
        _key: &Object,
        data: CK_BYTE_PTR,
        data_len: CK_ULONG_PTR,
        _key_template: &Box<dyn ObjectFactory>,
    ) -> KResult<()> {
        let pk_bytes = wrapping_key.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO)?;
        let public_key = PublicKey::decode(Algorithm::MlKem768, &pk_bytes)
            .expect("Failed to decode public key");

        let mut rng = crate::rng::RNG::new().expect("RNG instantiation failed");
        let (_ss, ct) = public_key
            .encapsulate(&mut rng)
            .expect("Failed to encapsulate key");
        let ct_bytes = ct.encode();

        if data.is_null() {
            unsafe { *data_len = ct_bytes.len() as CK_ULONG };
            return Ok(());
        }

        if unsafe { *data_len as usize } < ct_bytes.len() {
            unsafe { *data_len = ct_bytes.len() as CK_ULONG };
            return err_rv!(CKR_BUFFER_TOO_SMALL);
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                ct_bytes.as_ptr(),
                data,
                ct_bytes.len(),
            )
        };
        Ok(())
    }

    fn unwrap_key(
        &self,
        _mech: &CK_MECHANISM,
        unwrapping_key: &Object,
        data: &[u8],
        template: &[CK_ATTRIBUTE],
        key_template: &Box<dyn ObjectFactory>,
    ) -> KResult<Object> {
        let sk_bytes = unwrapping_key.get_attr_as_bytes(CKA_VALUE)?;
        let private_key = PrivateKey::decode(Algorithm::MlKem768, &sk_bytes)
            .expect("Failed to decode private key");
        let ct = Ct::decode(Algorithm::MlKem768, data)
            .expect("Failed to decode ciphertext");
        let ss = ct
            .decapsulate(&private_key)
            .expect("Failed to decapsulate shared secret");

        let mut key_object = key_template.create(template)?;
        key_object.set_attr(from_bytes(CKA_VALUE, ss.encode()))?;

        Ok(key_object)
    }

    fn generate_keypair(
        &self,
        _mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> KResult<(Object, Object)> {
        let mut rng = crate::rng::RNG::new().expect("RNG instantiation failed");
        let (sk, pk) = key_gen(Algorithm::MlKem768, &mut rng)
            .expect("Key generation failed");

        let mut pubkey =
            PUBLIC_KEY_FACTORY.default_object_generate(pubkey_template)?;
        pubkey.set_attr(from_bytes(CKA_PUBLIC_KEY_INFO, pk.encode()))?;

        let mut privkey =
            PRIVATE_KEY_FACTORY.default_object_generate(prikey_template)?;
        privkey.set_attr(from_bytes(CKA_VALUE, sk.encode()))?;

        Ok((pubkey, privkey))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    /* mechs.add_mechanism(
            CKM_ML_KEM,
            Box::new(MlKemMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: 0,
                    flags: CKF_WRAP | CKF_UNWRAP,
                },
            }),
        );
    */
    mechs.add_mechanism(
        CKM_ML_KEM_KEYGEN,
        Box::new(MlKemMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    );

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_ML_KEM),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_ML_KEM),
        &PRIVATE_KEY_FACTORY,
    );
}
