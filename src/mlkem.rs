use libcrux::kem::*;
use rand::rngs::OsRng;

// Import PKCS#11 structures and utilities
use crate::attribute::*;
use crate::error::*;
use crate::interface::*;
use crate::object::*;
use crate::{attr_element, bytes_attr_not_empty, err_rv};
use crate::mechanism::*;
use attribute::{from_bool, from_bytes, from_ulong};

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
        let mut obj = self.default_object_create(template)?;
        // Ensure public key attribute is valid
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
        let mut obj = self.default_object_create(template)?;
        // Ensure private key value is valid
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
    mech: &CK_MECHANISM,
    wrapping_key: &Object,
    key: &Object,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG_PTR,
    key_template: &Box<dyn ObjectFactory>,
) -> KResult<()> {
    let pk_bytes = wrapping_key.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO)?;
    let public_key = PublicKey::decode(Algorithm::MlKem768, &pk_bytes)
    .expect("Failed to decode public key");

    let mut rng = OsRng;
    let (_ss, ct) = public_key.encapsulate(&mut rng).expect("Failed to encapsulate key");
    let ct_bytes = ct.encode();

    // Handle the output buffer for the wrapped key (ciphertext)
    if data.is_null() {
        unsafe { *data_len = ct_bytes.len() as CK_ULONG };
        return Ok(());
    }

    if unsafe { *data_len as usize } < ct_bytes.len() {
        unsafe { *data_len = ct_bytes.len() as CK_ULONG };
        return err_rv!(CKR_BUFFER_TOO_SMALL);
    }

    unsafe { std::ptr::copy_nonoverlapping(ct_bytes.as_ptr(), data, ct_bytes.len()) };
    Ok(())
}

    fn unwrap_key(
    &self,
    mech: &CK_MECHANISM,
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
    let ss = ct.decapsulate(&private_key)
    .expect("Failed to decapsulate shared secret");


    // Create the unwrapped key object
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
        let mut rng = OsRng;
        let (sk, pk) = key_gen(Algorithm::MlKem768, &mut rng).map_err(|_| CKR_GENERAL_ERROR)?;

        let mut pubkey = PUBLIC_KEY_FACTORY.default_object_generate(pubkey_template)?;
        pubkey.set_attr(from_bytes(CKA_PUBLIC_KEY_INFO, pk.encode()))?;


        let mut privkey = PRIVATE_KEY_FACTORY.default_object_generate(prikey_template)?;
        privkey.set_attr(from_bytes(CKA_VALUE, sk.encode()))?;


        Ok((pubkey, privkey))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(
        CKM_ML_KEM,
        Box::new(MlKemMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 768,
                ulMaxKeySize: 768,
                flags: CKF_ENCRYPT | CKF_DECRYPT,
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
