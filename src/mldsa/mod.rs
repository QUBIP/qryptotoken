// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms
use crate::attribute::{from_bool, from_bytes, from_ulong};
use crate::error::*;
use crate::interface::*;
use crate::log::*;
use crate::mechanism::*;
use crate::object::*;
use crate::{attr_element, err_rv, to_rv};
use once_cell::sync::Lazy;
use signature::{Signer, Verifier};
use std::fmt::Debug;

#[cfg(test)]
mod tests;

#[cfg(feature = "libcrux")]
use crate::adapters::libcrux::mldsa::{generate_key_pair, PrivKey, PubKey};

/*
 * Public constants defining key and signature sizes for each ML-DSA
 * parameter set, according to FIPS-204, section 4, Parameter Sets.
 */
pub mod sizes {
    #![allow(dead_code)]
    use super::*;

    pub(crate) const ML_DSA_44_PK_SIZE: usize = 1312;
    pub(crate) const ML_DSA_44_SK_SIZE: usize = 2560;
    pub(crate) const ML_DSA_44_SIG_SIZE: usize = 2420;

    pub(crate) const ML_DSA_65_PK_SIZE: usize = 1952;
    pub(crate) const ML_DSA_65_SK_SIZE: usize = 4032;
    pub(crate) const ML_DSA_65_SIG_SIZE: usize = 3309;

    pub(crate) const ML_DSA_87_PK_SIZE: usize = 2592;
    pub(crate) const ML_DSA_87_SK_SIZE: usize = 4896;
    pub(crate) const ML_DSA_87_SIG_SIZE: usize = 4627;

    pub(crate) const MIN_ML_DSA_SIZE_BITS: CK_ULONG =
        (ML_DSA_44_PK_SIZE as CK_ULONG) << 3;
    pub(crate) const MAX_ML_DSA_SIZE_BITS: CK_ULONG =
        (ML_DSA_87_SK_SIZE as CK_ULONG) << 3;
    pub(crate) const ML_DSA_SIGNATURE_SIZE_BITS: CK_ULONG =
        (ML_DSA_87_SIG_SIZE as CK_ULONG) << 3;
}
use sizes::*;

/// The ML-DSA Public Key Factory.
///
/// It helps creating ML-DSA public key objects.
#[derive(Debug)]
pub struct MlDsaPubFactory {
    attributes: Vec<ObjectAttr>,
}

impl MlDsaPubFactory {
    /// Initialize a new `MlDsaPubFactory` with pre-defined attributes
    pub fn new() -> MlDsaPubFactory {
        crate::trace!(
            target: crate::QRYPTOTOKEN_TARGET,
            "⭐️🦀 {}::new() called",
            std::any::type_name::<Self>()
        );

        let mut data = MlDsaPubFactory {
            attributes: Vec::new(),
        };

        /* Common attributes */
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_public_key_attrs());

        /* ML-DSA specific attributes */
        data.attributes.push(attr_element!(
            CKA_PARAMETER_SET;
            OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            from_ulong;
            val 0
        ));
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

        crate::trace!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 {}::new() data={:?}",
            std::any::type_name::<Self>(),
            data
        );

        data
    }
}

impl ObjectFactory for MlDsaPubFactory {
    /// Creates a ML-DSA public key object using a given template
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        crate::trace!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 {}::create({template:?}) called",
            std::any::type_name::<Self>()
        );

        let mut obj = self.default_object_create(template)?;

        /* Always validate ML-DSA imported attributes */
        mldsa_check_pub_import(&mut obj)?;

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyFactory for MlDsaPubFactory {}

impl PubKeyFactory for MlDsaPubFactory {}

/// The ML-DSA Private Key Factory.
///
/// It helps creating ML-DSA private key objects.
#[derive(Debug)]
pub struct MlDsaPrivFactory {
    attributes: Vec<ObjectAttr>,
}

impl MlDsaPrivFactory {
    /// Initialize a new `MlDsaPrivFactory` with pre-defined attributes
    pub fn new() -> MlDsaPrivFactory {
        let mut data = MlDsaPrivFactory {
            attributes: Vec::new(),
        };

        /* Common attributes */
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_private_key_attrs());

        /* ML-DSA specific attributes */
        data.attributes.push(attr_element!(
            CKA_PARAMETER_SET;
            OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable;
            from_ulong;
            val 0
        ));
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

impl ObjectFactory for MlDsaPrivFactory {
    /// Creates a ML-DSA private key object using a given template
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        crate::trace!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 {}::create({template:?}) called",
            std::any::type_name::<Self>()
        );

        let mut obj = self.default_object_create(template)?;

        /* Always validate ML-DSA imported attributes */
        mldsa_check_priv_import(&mut obj)?;

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

/// Lazily-initialized, static Public Key factory.
///
/// This factory is created once at runtime on first access and is
/// intended to remain immutable for the lifetime of the process.
static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlDsaPubFactory::new()));

/// Lazily-initialized, static Public Key factory.
///
/// This factory is created once at runtime on first access and is
/// intended to remain immutable for the lifetime of the process.
static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlDsaPrivFactory::new()));

/// Object that represents ML-DSA mechanism and its supported operations
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
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_ML_DSA, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }

        let _mech = mech.mechanism;
        Ok(Box::new(MlDsaOperation {
            output_len: make_output_length_from_obj(key)?,
            public_key: None,
            private_key: Some(PrivKey::try_from(key)?),
            data: Vec::new(),
            finalized: false,
            in_use: false,
        }))
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
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_ML_DSA, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "️🦀 Some error checking key ops: {e:?}"
                );
                return Err(e);
            }
        }

        let ret = Box::new(MlDsaOperation::verify_new(mech, key, &self.info)?);

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

        /* Ensure the CKA_KEY_TYPE attribute is set to CKK_ML_DSA */
        if !public_key
            .check_or_set_attr(from_ulong(CKA_KEY_TYPE, CKK_ML_DSA))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        /* Extract the parameter set and ensure that is a valid one */
        let param_set = match public_key.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => match p {
                CKP_ML_DSA_44 | CKP_ML_DSA_65 | CKP_ML_DSA_87 => p,
                _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
            },
            Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };

        /* Create a default private key object from the template */
        let mut private_key =
            PRIVATE_KEY_FACTORY.default_object_generate(prikey_template)?;

        /* Ensure the CKA_CLASS atribute is set to CKO_PUBLIC_KEY*/
        if !private_key
            .check_or_set_attr(from_ulong(CKA_CLASS, CKO_PRIVATE_KEY))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        /* Ensure the CKA_KEY_TYPE attribute is set to CKK_ML_DSA */
        if !private_key
            .check_or_set_attr(from_ulong(CKA_KEY_TYPE, CKK_ML_DSA))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        // TODO: We should check the param_set for the private key too.

        let (sk, pk) = generate_key_pair(param_set)?;

        public_key.set_attr(from_ulong(CKA_PARAMETER_SET, param_set))?;
        public_key.set_attr(from_bytes(CKA_VALUE, pk.as_ref().to_vec()))?;

        private_key.set_attr(from_ulong(CKA_PARAMETER_SET, param_set))?;
        private_key.set_attr(from_bytes(CKA_VALUE, sk.as_ref().to_vec()))?;

        default_key_attributes(&mut private_key, mech.mechanism)?;
        default_key_attributes(&mut public_key, mech.mechanism)?;

        Ok((public_key, private_key))
    }
}

/// This function registers all ML-DSA related mechanism and PubKey/PrivKey
/// factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(
        CKM_ML_DSA,
        Box::new(MlDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_ML_DSA_SIZE_BITS,
                ulMaxKeySize: MAX_ML_DSA_SIZE_BITS,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_ML_DSA_KEYGEN,
        Box::new(MlDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_ML_DSA_SIZE_BITS,
                ulMaxKeySize: MAX_ML_DSA_SIZE_BITS,
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    );

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_ML_DSA),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_ML_DSA),
        &PRIVATE_KEY_FACTORY,
    );
}

/// Helper function that validates a ML-DSA private key object during import.
///
/// This function ensures that required attributes are present and consistent
/// with the selected ML-DSA parameter set. It checks that the private key
/// value size matches the declared ML-DSA parameter set.
///
/// Returns an error if any attribute is missing or invalid.
fn mldsa_check_priv_import(obj: &mut Object) -> KResult<()> {
    crate::trace!(
        target: crate::QRYPTOTOKEN_TARGET,
        "🦀 mldsa_check_priv_import({obj:?}) called"
    );

    /* Ensure CKA_PARAMETER_SET is present */
    let param_set = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
        Ok(p) => p,
        Err(_) => {
            crate::error!(
                target: crate::QRYPTOTOKEN_TARGET,
                "🦀 CKR_TEMPLATE_INCOMPLETE: missing CKA_PARAMETER_SET"
            );
            return err_rv!(CKR_TEMPLATE_INCOMPLETE);
        }
    };

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
     * Ensure that the length of CKA_VALUE matches the expected
     * length for the given CKA_PARAMETER_SET.
     */
    let expected_len = match param_set {
        CKP_ML_DSA_44 => ML_DSA_44_SK_SIZE,
        CKP_ML_DSA_65 => ML_DSA_65_SK_SIZE,
        CKP_ML_DSA_87 => ML_DSA_87_SK_SIZE,
        _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
    };

    if private_value.len() != expected_len {
        crate::error!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 mldsa_check_priv_import(): the CKA_VALUE length doesn't match \
             the expected length for the given CKA_PARAMETER_SET",
        );
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    // TODO: waaaaay later, add support for SEED
    Ok(())
}

/// Helper function that validates a ML-DSA public key object during import.
///
/// This function ensures that required attributes are present and consistent
/// with the selected ML-DSA parameter set. It checks that the public key value
/// size matches the declared ML-DSA parameter set.
///
/// Returns an error if any attribute is missing or invalid.
fn mldsa_check_pub_import(obj: &mut Object) -> KResult<()> {
    crate::trace!(
        target: crate::QRYPTOTOKEN_TARGET,
        "🦀 mldsa_check_pub_import({obj:?}) called"
    );

    /* Ensure CKA_PARAMETER_SET is present */
    let param_set = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
        Ok(p) => p,
        Err(_) => {
            crate::error!(
                target: crate::QRYPTOTOKEN_TARGET,
                "🦀 CKR_TEMPLATE_INCOMPLETE: missing CKA_PARAMETER_SET"
            );
            return err_rv!(CKR_TEMPLATE_INCOMPLETE);
        }
    };

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
     * Ensure that the length of CKA_VALUE matches the expected
     * length for the given CKA_PARAMETER_SET.
     */
    let expected_len = match param_set {
        CKP_ML_DSA_44 => ML_DSA_44_PK_SIZE,
        CKP_ML_DSA_65 => ML_DSA_65_PK_SIZE,
        CKP_ML_DSA_87 => ML_DSA_87_PK_SIZE,
        _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
    };

    if public_value.len() != expected_len {
        crate::error!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 mldsa_check_pub_import(): the CKA_VALUE length doesn't match \
            the expected length for the given CKA_PARAMETER_SET",
        );
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    Ok(())
}

#[derive(Debug)]
struct MlDsaOperation {
    output_len: usize,
    public_key: Option<PubKey>,
    private_key: Option<PrivKey>,
    finalized: bool,
    data: Vec<u8>,
    in_use: bool,
}
impl MlDsaOperation {
    pub fn verify_new(
        _mech: &CK_MECHANISM,
        key: &Object,
        _info: &CK_MECHANISM_INFO,
    ) -> KResult<Self> {
        let output_len = match make_output_length_from_obj(key) {
            Ok(l) => l,
            Err(e) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "️🦀 Error retrieving output length from object: {e:?}"
                );
                return Err(e);
            }
        };
        let private_key: Option<PrivKey> = None;
        let public_key = match PubKey::try_from(key) {
            Ok(pk) => Some(pk),
            Err(e) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "️🦀 Error converting from object to PubKey: {e:?}"
                );
                return Err(e);
            }
        };
        Ok(MlDsaOperation {
            output_len,
            public_key,
            private_key,
            finalized: false,
            data: Vec::new(),
            in_use: false,
        })
    }
}

impl MechOperation for MlDsaOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for MlDsaOperation {
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

        let signlen = signature.len();

        let private_key = match self.private_key.as_ref() {
            Some(PrivKey::MlDsa44(sk)) => PrivKey::MlDsa44(sk.clone()),
            Some(PrivKey::MlDsa65(sk)) => PrivKey::MlDsa65(sk.clone()),
            Some(PrivKey::MlDsa87(sk)) => PrivKey::MlDsa87(sk.clone()),
            _ => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };

        let signed_data = private_key
            .try_sign(&self.data)
            .map_err(|_| to_rv!(CKR_FUNCTION_FAILED))?;

        let encoded_signature: &[u8] = signed_data.as_ref();

        if encoded_signature.len() != signlen {
            return err_rv!(CKR_BUFFER_TOO_SMALL);
        }
        signature.copy_from_slice(encoded_signature);
        Ok(())
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

impl Verify for MlDsaOperation {
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

        let public_key = match self.public_key.as_ref() {
            Some(PubKey::MlDsa44(pk)) => PubKey::MlDsa44(pk.clone()),
            Some(PubKey::MlDsa65(pk)) => PubKey::MlDsa65(pk.clone()),
            Some(PubKey::MlDsa87(pk)) => PubKey::MlDsa87(pk.clone()),
            _ => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };
        let message = self.data.clone();
        let signature = signature.to_vec();

        let handle = std::thread::Builder::new()
            .name("mldsa_verify_thread".into())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let result = public_key
                    .verify(&message, &signature)
                    .map_err(|_| to_rv!(CKR_SIGNATURE_INVALID));
                result
            })
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread spawn failed during verification"
                );
                to_rv!(CKR_FUNCTION_FAILED)
            })?;

        let ret = handle
            .join()
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread panicked during verification"
                );
                to_rv!(CKR_FUNCTION_FAILED)
            })?
            .map_err(|e| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Verification failed: {e:?}"
                );
                to_rv!(CKR_SIGNATURE_INVALID)
            });

        if ret.is_err() {
            error!(
                target: crate::QRYPTOTOKEN_TARGET,
                "Internal verification failure"
            );
            return ret;
        }

        debug!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 👌👌👌 Verification succesful!"
        );

        Ok(())
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

/// Determines the expected signature output length based on the provided
/// public key object.
///
/// # Parameters
///
/// - `obj`: A reference to a PKCS#11 `Object`.
///
/// # Returns
///
/// - `Ok(usize)`: The expected signature length in bytes for the given key
///                type.
/// - `Err(CK_RV)`: Returns `CKR_ATTRIBUTE_VALUE_INVALID` if the parameter set
///                 is invalid.
///                 Returns `CKR_TEMPLATE_INCONSISTENT` if an attribute is
///                 missing.
fn make_output_length_from_obj(obj: &Object) -> KResult<usize> {
    let param_set = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
        Ok(p) => match p {
            CKP_ML_DSA_44 | CKP_ML_DSA_65 | CKP_ML_DSA_87 => p,
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        },
        Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
    };

    let output_len = match param_set {
        CKP_ML_DSA_44 => ML_DSA_44_SIG_SIZE as usize,
        CKP_ML_DSA_65 => ML_DSA_65_SIG_SIZE as usize,
        CKP_ML_DSA_87 => ML_DSA_87_SIG_SIZE as usize,
        _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
    };

    Ok(output_len)
}
