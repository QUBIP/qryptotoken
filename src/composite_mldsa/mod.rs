// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms
use crate::adapters::libcrux::mldsa65ed25519::{
    generate_key_pair, sizes::*, PrivKey, PubKey, Signature,
};
use crate::attribute::{from_bool, from_bytes, from_ulong};
use crate::error::*;
use crate::interface::*;
use crate::log::*;
use crate::mechanism::*;
use crate::object::*;
use crate::{attr_element, err_rv};
use once_cell::sync::Lazy;
use signature::{Signer, Verifier};
use std::fmt::Debug;

const MIN_MLDSA65_ED25519_KEY_SIZE_BITS: CK_ULONG =
    (MLDSA65_ED25519_PK_SIZE as CK_ULONG) << 3;
const MAX_MLDSA65_ED25519_KEY_SIZE_BITS: CK_ULONG =
    (MLDSA65_ED25519_SK_SIZE as CK_ULONG) << 3;

/// The MLDSA65-Ed25519 Public Key Factory.
///
/// It helps creating MLDSA65-Ed25519 public key objects.
#[derive(Debug)]
pub struct MlDsa65Ed25519PubFactory {
    attributes: Vec<ObjectAttr>,
}

impl MlDsa65Ed25519PubFactory {
    pub fn new() -> MlDsa65Ed25519PubFactory {
        let mut data = MlDsa65Ed25519PubFactory {
            attributes: Vec::new(),
        };
        /* Common attributes */
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_public_key_attrs());

        data.attributes.push(attr_element!(
            CKA_VALUE;
            OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            from_bytes;
            val Vec::new()
        ));

        /* Ensure the CKA_PRIVATE attribute is set to true as default */
        let private = attr_element!(
            CKA_PRIVATE;
            OAFlags::Defval | OAFlags::ChangeOnCopy;
            from_bool;
            val true
        );

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

impl ObjectFactory for MlDsa65Ed25519PubFactory {
    /// Creates a MLDSA65-Ed25519 public key object using a given template
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template)?;
        /* Always validate MLDSA65-Ed25519 imported attributes */
        mldsa65_ed25519_check_pub_import(&mut obj)?;

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyFactory for MlDsa65Ed25519PubFactory {}
impl PubKeyFactory for MlDsa65Ed25519PubFactory {}

/// The MLDSA65-Ed25519 Private Key Factory.
///
/// It helps creating MLDSA65-Ed25519 private key objects.
#[derive(Debug)]
pub struct MlDsa65Ed25519PrivFactory {
    attributes: Vec<ObjectAttr>,
}

impl MlDsa65Ed25519PrivFactory {
    /// Initialize a new `MlDsa65Ed25519MlDsaPrivFactory` with pre-defined
    /// attributes
    pub fn new() -> MlDsa65Ed25519PrivFactory {
        let mut data = MlDsa65Ed25519PrivFactory {
            attributes: Vec::new(),
        };

        /* Common attributes */
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_private_key_attrs());

        data.attributes.push(attr_element!(
            CKA_VALUE;
            OAFlags::Sensitive
            | OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable;
            from_bytes;
            val Vec::new()
        ));

        /* Ensure the CKA_PRIVATE attribute is set to true as default */
        let private = attr_element!(
            CKA_PRIVATE;
            OAFlags::Defval | OAFlags::ChangeOnCopy;
            from_bool;
            val true
        );

        match data
            .attributes
            .iter()
            .position(|x| x.get_type() == CKA_PRIVATE)
        {
            Some(idx) => data.attributes[idx] = private,
            None => data.attributes.push(private),
        }

        crate::trace!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 {}::new() data={:?}",
            std::any::type_name::<Self>(),
            data
        );

        data
    }
}

impl ObjectFactory for MlDsa65Ed25519PrivFactory {
    /// Creates a MLDSA65-Ed25519 private key object using a given template
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        crate::trace!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 {}::create({template:?}) called",
            std::any::type_name::<Self>()
        );

        let mut obj = self.default_object_create(template)?;

        /* Always validate MLDSA65-Ed25519 imported attributes */
        mldsa65_ed25519_check_priv_import(&mut obj)?;

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

impl CommonKeyFactory for MlDsa65Ed25519PrivFactory {}

impl PrivKeyFactory for MlDsa65Ed25519PrivFactory {}

/// Lazily-initialized, static Public Key factory.
///
/// This factory is created once at runtime on first access and is
/// intended to remain immutable for the lifetime of the process.
static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlDsa65Ed25519PubFactory::new()));

/// Lazily-initialized, static Public Key factory.
///
/// This factory is created once at runtime on first access and is
/// intended to remain immutable for the lifetime of the process.
static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlDsa65Ed25519PrivFactory::new()));

/// Object that represents Composite-ML-DSA mechanism and its supported
/// operations
#[derive(Debug)]
pub struct MlDsa65Ed25519Mechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for MlDsa65Ed25519Mechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_MLDSA65_ED25519, CKA_SIGN)
        {
            Ok(_) => (),
            Err(e) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "️🦀 Some error checking key ops: {e:?}"
                );
                return Err(e);
            }
        }

        let ret =
            Box::new(MlDsa65Ed25519Operation::sign_new(mech, key, &self.info)?);

        crate::trace!(
            target: crate::QRYPTOTOKEN_TARGET,
            "️🦀 {}::sign_new() DONE 👍",
            std::any::type_name::<Self>()
        );

        return Ok(ret);
    }

    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Verify>> {
        crate::trace!(
            target: crate::QRYPTOTOKEN_TARGET,
            "⭐️🦀 {}::verify_new() called",
            std::any::type_name::<Self>()
        );

        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            crate::error!(
                target: crate::QRYPTOTOKEN_TARGET,
                "️🦀 CKR_MECHANISM_INVALID"
            );
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        /* Match against the actual key type */
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_MLDSA65_ED25519, CKA_VERIFY)
        {
            Ok(_) => (),
            Err(e) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "️🦀 Some error checking key ops: {e:?}"
                );
                return Err(e);
            }
        }

        let ret = Box::new(MlDsa65Ed25519Operation::verify_new(
            mech, key, &self.info,
        )?);

        crate::trace!(
            target: crate::QRYPTOTOKEN_TARGET,
            "️🦀 {}::verify_new() DONE 👍",
            std::any::type_name::<Self>()
        );

        return Ok(ret);
    }

    fn generate_keypair(
        &self,
        mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> KResult<(Object, Object)> {
        /* Create a default public key object from the template */
        let mut public_key =
            PUBLIC_KEY_FACTORY.default_object_generate(pubkey_template)?;

        /* Ensure the CKA_CLASS atribute is set to CKO_PUBLIC_KEY*/
        if !public_key
            .check_or_set_attr(from_ulong(CKA_CLASS, CKO_PUBLIC_KEY))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        /* Ensure the CKA_KEY_TYPE attribute is set to CKK_MLDSA65_ED25519 */
        if !public_key
            .check_or_set_attr(from_ulong(CKA_KEY_TYPE, CKK_MLDSA65_ED25519))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        /* Create a default private key object from the template */
        let mut private_key =
            PRIVATE_KEY_FACTORY.default_object_generate(prikey_template)?;

        /* Ensure the CKA_CLASS atribute is set to CKO_PUBLIC_KEY*/
        if !private_key
            .check_or_set_attr(from_ulong(CKA_CLASS, CKO_PRIVATE_KEY))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        /* Ensure the CKA_KEY_TYPE attribute is set to CKK_MLDSA65_ED25519 */
        if !private_key
            .check_or_set_attr(from_ulong(CKA_KEY_TYPE, CKK_MLDSA65_ED25519))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        let (sk, pk) = match generate_key_pair() {
            Ok((a, b)) => (a, b),
            Err(e) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "🦀 Error while generating a new MLDSA65-Ed25519 \
                        keypair {e:?}"
                );
                return err_rv!(CKR_DEVICE_ERROR);
            }
        };

        /* Encode the public keys */
        let encoded_sk = sk.encode();

        /* Encode the private keys */
        let encoded_pk = pk.encode();

        public_key.set_attr(from_bytes(CKA_VALUE, encoded_pk))?;
        private_key.set_attr(from_bytes(CKA_VALUE, encoded_sk))?;

        default_key_attributes(&mut private_key, mech.mechanism)?;
        default_key_attributes(&mut public_key, mech.mechanism)?;
        Ok((public_key, private_key))
    }
}

/// This function registers all MLDSA65-Ed25519 related mechanism and
/// PubKey/PrivKey factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(
        CKM_MLDSA65_ED25519,
        Box::new(MlDsa65Ed25519Mechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_MLDSA65_ED25519_KEY_SIZE_BITS,
                ulMaxKeySize: MAX_MLDSA65_ED25519_KEY_SIZE_BITS,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_MLDSA65_ED25519_KEYGEN,
        Box::new(MlDsa65Ed25519Mechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_MLDSA65_ED25519_KEY_SIZE_BITS,
                ulMaxKeySize: MAX_MLDSA65_ED25519_KEY_SIZE_BITS,
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    );

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_MLDSA65_ED25519),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_MLDSA65_ED25519),
        &PRIVATE_KEY_FACTORY,
    );
}

/// Helper function that validates a MLDSA65-ED25519 private key object
/// during import.
///
/// This function ensures that the attribute holding the private value is
/// present and valid.
///
/// Returns an error if the required attribute is missing or invalid.
fn mldsa65_ed25519_check_priv_import(obj: &mut Object) -> KResult<()> {
    crate::trace!(
        target: crate::QRYPTOTOKEN_TARGET,
        "🦀 mldsa65_ed25519_check_priv_import({obj:?}) called"
    );
    /* Ensure CKA_VALUE is present */
    let private_value = match obj.get_attr_as_bytes(CKA_VALUE) {
        Ok(v) => v,
        Err(_) => {
            crate::error!(
                target: crate::QRYPTOTOKEN_TARGET,
                "🦀 CKR_TEMPLATE_INCOMPLETE: missing CKA_VALUE"
            );
            return err_rv!(CKR_TEMPLATE_INCOMPLETE);
        }
    };

    /* Bail out if the CKA_VALUE is empty */
    if private_value.is_empty() {
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    /*
     * Bail out if the size of the size of the serialized public key doesn't
     * match the expected size.
     */
    if private_value.len() != MLDSA65_ED25519_SK_SIZE {
        crate::error!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 CKR_ATTRIBUTE_VALUE_INVALID: The private value size doesn't \
                match the expected size. Expected {}: got {}",
            MLDSA65_ED25519_SK_SIZE,
            private_value.len()
        );
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    Ok(())
}

/// Helper function that validates a MLDSA65-ED25519 public key object during
/// import.
///
/// This function ensures that the attribute holding the public value is
/// present and valid.
///
/// Returns an error if the required attribute is missing or invalid.
fn mldsa65_ed25519_check_pub_import(obj: &mut Object) -> KResult<()> {
    crate::trace!(
        target: crate::QRYPTOTOKEN_TARGET,
        "🦀 mldsa65_ed25519_check_pub_import({obj:?}) called"
    );
    /* Ensure CKA_VALUE is present */
    let public_value = match obj.get_attr_as_bytes(CKA_VALUE) {
        Ok(v) => v,
        Err(_) => {
            crate::error!(
                target: crate::QRYPTOTOKEN_TARGET,
                "🦀 CKR_TEMPLATE_INCOMPLETE: missing CKA_VALUE"
            );
            return err_rv!(CKR_TEMPLATE_INCOMPLETE);
        }
    };

    /* Bail out if the CKA_VALUE is empty */
    if public_value.is_empty() {
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    /*
     * Bail out if the size of the size of the serialized public key doesn't
     * match the expected size.
     */
    if public_value.len() != MLDSA65_ED25519_PK_SIZE {
        crate::error!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 CKR_ATTRIBUTE_VALUE_INVALID: The public value size doesn't \
                match the expected size. Expected: {}, got {}",
            MLDSA65_ED25519_PK_SIZE,
            public_value.len()
        );
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    Ok(())
}

#[derive(Debug)]
struct MlDsa65Ed25519Operation {
    output_len: usize,
    public_key: Option<PubKey>,
    private_key: Option<PrivKey>,
    finalized: bool,
    data: Vec<u8>,
    in_use: bool,
}
impl MlDsa65Ed25519Operation {
    pub fn sign_new(
        _mech: &CK_MECHANISM,
        key: &Object,
        _info: &CK_MECHANISM_INFO,
    ) -> KResult<Self> {
        let output_len = MLDSA65_ED25519_SIG_SIZE;

        let private_key = match key.get_attr_as_bytes(CKA_VALUE) {
            Ok(v) => v,
            Err(_) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "🦀 CKR_TEMPLATE_INCOMPLETE: missing CKA_VALUE"
                );
                return err_rv!(CKR_TEMPLATE_INCOMPLETE);
            }
        };

        let sk = match PrivKey::decode(private_key) {
            Ok(v) => v,
            Err(e) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "🦀 Failure while deserializing the private key: {e:?}"
                );
                return err_rv!(CKR_FUNCTION_FAILED);
            }
        };

        Ok(MlDsa65Ed25519Operation {
            output_len,
            public_key: None,
            private_key: Some(sk),
            finalized: false,
            data: Vec::new(),
            in_use: false,
        })
    }

    pub fn verify_new(
        _mech: &CK_MECHANISM,
        key: &Object,
        _info: &CK_MECHANISM_INFO,
    ) -> KResult<Self> {
        let output_len = MLDSA65_ED25519_SIG_SIZE;

        let public_key = match key.get_attr_as_bytes(CKA_VALUE) {
            Ok(v) => v,
            Err(_) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "🦀 CKR_TEMPLATE_INCOMPLETE: missing CKA_VALUE"
                );
                return err_rv!(CKR_TEMPLATE_INCOMPLETE);
            }
        };

        let pk = match PubKey::decode(public_key) {
            Ok(v) => v,
            Err(e) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "🦀 Failure while deserializing the public key: {e:?}"
                );
                return err_rv!(CKR_FUNCTION_FAILED);
            }
        };

        Ok(MlDsa65Ed25519Operation {
            output_len,
            public_key: Some(pk),
            private_key: None,
            finalized: false,
            data: Vec::new(),
            in_use: false,
        })
    }
}

impl MechOperation for MlDsa65Ed25519Operation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for MlDsa65Ed25519Operation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }

        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.sign_update(data)?;
        self.sign_final(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }

        if !self.in_use {
            self.in_use = true;

            if self.private_key.is_none() {
                return err_rv!(CKR_KEY_HANDLE_INVALID);
            }
        }

        self.data.extend_from_slice(data);
        Ok(())
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        let sk = self
            .private_key
            .as_ref()
            .expect("Private Key must not be empty");

        let sig = match sk.try_sign(&self.data) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "🦀 Error while perfoming the signature: {e:?}"
                );
                return err_rv!(CKR_FUNCTION_FAILED);
            }
        };

        /* Encode the composite signature */
        let encoded_sig = sig.encode();

        signature[..encoded_sig.len()].copy_from_slice(&encoded_sig);

        Ok(())
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

impl Verify for MlDsa65Ed25519Operation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.verify_update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            self.in_use = true;

            if self.public_key.is_none() {
                return err_rv!(CKR_KEY_HANDLE_INVALID);
            }
        }
        self.data.extend_from_slice(data);
        Ok(())
    }

    fn verify_final(&mut self, signature: &[u8]) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        let sig = match Signature::decode(signature) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "🦀 Error while deserializing the signature: {e:?}"
                );
                return err_rv!(CKR_SIGNATURE_INVALID);
            }
        };

        let pk = self
            .public_key
            .as_ref()
            .expect("Public Key must not be empty");

        let res = match pk.verify(&self.data, &sig) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "🦀 Error while verifying the signature: {e:?}"
                );
                return err_rv!(CKR_SIGNATURE_INVALID);
            }
        };

        Ok(res)
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}
