#![allow(dead_code)]
//use rand::rngs::OsRng;

//use ml_dsa::*;

use crate::attribute::from_bytes;
use crate::error::*;
use crate::interface::*;
use crate::mechanism::*;
use crate::object::*;
use crate::{attr_element, err_rv};

use once_cell::sync::Lazy;
use std::fmt::Debug;

#[derive(Debug)]
pub struct MlDsaPubFactory {
    attributes: Vec<ObjectAttr>,
}

impl MlDsaPubFactory {
    pub fn new() -> MlDsaPubFactory {
        let mut data = MlDsaPubFactory {
            attributes: Vec::new(),
        };
        data.attributes.push(attr_element!(CKA_PUBLIC_KEY_INFO; OAFlags::RequiredOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data
    }
}

impl ObjectFactory for MlDsaPubFactory {
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

impl CommonKeyFactory for MlDsaPubFactory {}
impl PubKeyFactory for MlDsaPubFactory {}

#[derive(Debug)]
pub struct MlDsaPrivFactory {
    attributes: Vec<ObjectAttr>,
}

impl MlDsaPrivFactory {
    pub fn new() -> MlDsaPrivFactory {
        let mut data = MlDsaPrivFactory {
            attributes: Vec::new(),
        };
        data.attributes.push(attr_element!(CKA_VALUE; OAFlags::Sensitive | OAFlags::RequiredOnCreate; from_bytes; val Vec::new()));
        data
    }
}

impl ObjectFactory for MlDsaPrivFactory {
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

impl CommonKeyFactory for MlDsaPrivFactory {}
impl PrivKeyFactory for MlDsaPrivFactory {}

static SIGNING_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlDsaPubFactory::new()));

static VERIFYING_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlDsaPrivFactory::new()));

#[derive(Debug)]
pub struct MlDsaMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for MlDsaMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn sign_new(
        &self,
        _: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        match key.check_key_ops(
            CKO_VENDOR_DEFINED,
            CKK_VENDOR_DEFINED,
            CKA_SIGN,
        ) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }

        //TODO: Implement this function

        err_rv!(CKR_MECHANISM_INVALID)
    }

    fn verify_new(
        &self,
        _: &CK_MECHANISM,
        _: &crate::object::Object,
    ) -> KResult<Box<dyn Verify>> {
        //TODO: Implement this function

        err_rv!(CKR_MECHANISM_INVALID)
    }

    fn generate_keypair(
        &self,
        _: &CK_MECHANISM,
        _pubkey_template: &[CK_ATTRIBUTE],
        _prikey_template: &[CK_ATTRIBUTE],
    ) -> KResult<(Object, Object)> {
        //TODO: Implement this function
        todo!()
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(
        CKM_ML_KEM,
        Box::new(MlDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );

    mechs.add_mechanism(
        CKM_ML_KEM_KEYGEN,
        Box::new(MlDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    );

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_ML_KEM),
        &SIGNING_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_ML_KEM),
        &VERIFYING_KEY_FACTORY,
    );
}
