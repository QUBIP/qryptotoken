//// Copyright (C) 2023-2025 Tampere University
//// See LICENSE.txt file for terms
mod keymgmt;

use crate::attribute::{from_bool, from_bytes, from_ulong};
use crate::interface::*;
use crate::log::*;
use crate::mechanism::*;
use crate::object::*;
use crate::slhdsa::keymgmt::{
    generate_key_pair, sizes::*, PrivKey, PubKey, Signature,
};
use crate::{attr_element, err_rv, to_rv};
use crate::{bytes_to_vec, cast_params, error::*};
use once_cell::sync::Lazy;
use std::fmt::Debug;
use std::sync::Arc;

const MAX_CTX_LEN: CK_ULONG = 255;

/// The SLH-DSA Public Key Factory
///
/// It helps creating SLH-DSA public key objects.
#[derive(Debug)]
pub struct SlhDsaPubFactory {
    attributes: Vec<ObjectAttr>,
}

impl SlhDsaPubFactory {
    /// Initialize a new `SlhDsaPubFactory` with pre-defined attributes
    pub fn new() -> SlhDsaPubFactory {
        crate::trace!(
            target: crate::QRYPTOTOKEN_TARGET,
            "⭐️🦀 {}::new() called",
            std::any::type_name::<Self>()
        );

        let mut data = SlhDsaPubFactory {
            attributes: Vec::new(),
        };

        /* Common attributes */
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_public_key_attrs());

        /* SLH-DSA specific attributes */
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

impl ObjectFactory for SlhDsaPubFactory {
    /// Creates a SLH-DSA public key object using a given template
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        crate::trace!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 {}::create({template:?}) called",
            std::any::type_name::<Self>()
        );

        let mut obj = self.default_object_create(template)?;

        /* Always validate SLH-DSA imported attributes */
        slhdsa_check_pub_import(&mut obj)?;

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyFactory for SlhDsaPubFactory {}

impl PubKeyFactory for SlhDsaPubFactory {}

/// The SLH-DSA Private Key Factory.
///
/// It helps creating SLH-DSA private key objects.
#[derive(Debug)]
pub struct SlhDsaPrivFactory {
    attributes: Vec<ObjectAttr>,
}

impl SlhDsaPrivFactory {
    /// Initialize a new `SlhDsaPrivFactory` with pre-defined attributes
    pub fn new() -> SlhDsaPrivFactory {
        let mut data = SlhDsaPrivFactory {
            attributes: Vec::new(),
        };

        /* Common attributes */
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_private_key_attrs());

        /* SLH-DSA specific attributes */
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

impl ObjectFactory for SlhDsaPrivFactory {
    /// Creates a SLH-DSA private key object using a given template
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        crate::trace!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 {}::create({template:?}) called",
            std::any::type_name::<Self>()
        );

        let mut obj = self.default_object_create(template)?;

        /* Always validate SLH-DSA imported attributes */
        slhdsa_check_priv_import(&mut obj)?;

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

impl CommonKeyFactory for SlhDsaPrivFactory {}

impl PrivKeyFactory for SlhDsaPrivFactory {}

/// Lazily-initialized, static Public Key factory.
///
/// This factory is created once at runtime on first access and is
/// intended to remain immutable for the lifetime of the process.
static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(SlhDsaPubFactory::new()));

/// Lazily-initialized, static Public Key factory.
///
/// This factory is created once at runtime on first access and is
/// intended to remain immutable for the lifetime of the process.
static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(SlhDsaPrivFactory::new()));

/// Object that represents SLH-DSA mechanism and its supported operations
#[derive(Debug)]
pub struct SlhDsaMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for SlhDsaMechanism {
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

        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_SLH_DSA, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }

        let ret = Box::new(SlhDsaOperation::sign_new(mech, key, &self.info)?);

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
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_SLH_DSA, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "️🦀 Some error checking key ops: {e:?}"
                );
                return Err(e);
            }
        }

        let ret = Box::new(SlhDsaOperation::verify_new(mech, key, &self.info)?);

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

        /* Ensure the CKA_KEY_TYPE attribute is set to CKK_SLH_DSA */
        if !public_key
            .check_or_set_attr(from_ulong(CKA_KEY_TYPE, CKK_SLH_DSA))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        /* Extract the parameter set and ensure that is a valid one */
        let param_set = match public_key.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => match p {
                CKP_SLH_DSA_SHAKE_128S
                | CKP_SLH_DSA_SHAKE_128F
                | CKP_SLH_DSA_SHAKE_192S
                | CKP_SLH_DSA_SHAKE_192F
                | CKP_SLH_DSA_SHAKE_256S
                | CKP_SLH_DSA_SHAKE_256F => p,
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

        /* Ensure the CKA_KEY_TYPE attribute is set to CKK_SLH_DSA */
        if !private_key
            .check_or_set_attr(from_ulong(CKA_KEY_TYPE, CKK_SLH_DSA))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        /* Ensure the parameter set is set and the same for the private key */
        if !private_key
            .check_or_set_attr(from_ulong(CKA_PARAMETER_SET, param_set))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        let (sk, pk) = generate_key_pair(param_set)?;

        public_key.set_attr(from_ulong(CKA_PARAMETER_SET, param_set))?;
        public_key.set_attr(from_bytes(CKA_VALUE, pk.encode()))?;

        private_key.set_attr(from_ulong(CKA_PARAMETER_SET, param_set))?;
        private_key.set_attr(from_bytes(CKA_VALUE, sk.encode()))?;

        default_key_attributes(&mut private_key, mech.mechanism)?;
        default_key_attributes(&mut public_key, mech.mechanism)?;

        Ok((public_key, private_key))
    }
}

/// This function registers all SLH-DSA related mechanism and PubKey/PrivKey
/// factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(
        CKM_SLH_DSA,
        Box::new(SlhDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_SLH_DSA_SIZE_BITS,
                ulMaxKeySize: MAX_SLH_DSA_SIZE_BITS,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_SLH_DSA_KEY_PAIR_GEN,
        Box::new(SlhDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_SLH_DSA_SIZE_BITS,
                ulMaxKeySize: MAX_SLH_DSA_SIZE_BITS,
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    );

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_SLH_DSA),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_SLH_DSA),
        &PRIVATE_KEY_FACTORY,
    );
}

/// Helper function that validates a SLH-DSA private key object during import.
///
/// This function ensures that required attributes are present and consistent
/// with the selected SLH-DSA parameter set. It checks that the private key
/// value size matches the declared SLH-DSA parameter set.
///
/// Returns an error if any attribute is missing or invalid.
fn slhdsa_check_priv_import(obj: &mut Object) -> KResult<()> {
    crate::trace!(
        target: crate::QRYPTOTOKEN_TARGET,
        "🦀 slhdsa_check_priv_import({obj:?}) called"
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
    let expected_len = PrivKey::output_len(param_set)?;
    if private_value.len() != expected_len {
        crate::error!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 slhdsa_check_priv_import(): the CKA_VALUE length doesn't \
             match the expected length for the given CKA_PARAMETER_SET",
        );
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    Ok(())
}

/// Helper function that validates a SLH-DSA public key object during import.
///
/// This function ensures that required attributes are present and consistent
/// with the selected SLH-DSA parameter set. It checks that the public key
/// value size matches the declared SLH-DSA parameter set.
///
/// Returns an error if any attribute is missing or invalid.
fn slhdsa_check_pub_import(obj: &mut Object) -> KResult<()> {
    crate::trace!(
        target: crate::QRYPTOTOKEN_TARGET,
        "🦀 slhdsa_check_pub_import({obj:?}) called"
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
    let expected_len = PubKey::output_len(param_set)?;
    if public_value.len() != expected_len {
        crate::error!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 slhdsa_check_pub_import(): the CKA_VALUE length doesn't match \
            the expected length for the given CKA_PARAMETER_SET",
        );
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct SlhDsaSignAddCtx {
    hedge: CK_HEDGE_TYPE,
    ctx: Option<Vec<u8>>,
}
impl SlhDsaSignAddCtx {
    pub fn new(mech: &CK_MECHANISM) -> KResult<SlhDsaSignAddCtx> {
        let mut sign_ctx = SlhDsaSignAddCtx {
            hedge: CKH_HEDGE_PREFERRED,
            ctx: None,
        };

        if !mech.pParameter.is_null() {
            match mech.mechanism {
                CKM_SLH_DSA => {
                    let params = cast_params!(mech, CK_SIGN_ADDITIONAL_CONTEXT);
                    match params.hedgeVariant {
                        CKH_HEDGE_PREFERRED
                        | CKH_HEDGE_REQUIRED
                        | CKH_DETERMINISTIC_REQUIRED => {
                            sign_ctx.hedge = params.hedgeVariant;
                        }
                        _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
                    }

                    if params.ulContextLen > 0 {
                        if params.ulContextLen > MAX_CTX_LEN {
                            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                        }
                        sign_ctx.ctx = Some(bytes_to_vec!(
                            params.pContext,
                            params.ulContextLen
                        ));
                    }
                }
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            }
        }

        Ok(sign_ctx)
    }
}

#[derive(Debug)]
struct SlhDsaOperation {
    output_len: usize,
    public_key: Option<Arc<PubKey>>,
    private_key: Option<PrivKey>,
    sign_ctx: SlhDsaSignAddCtx,
    finalized: bool,
    data: Vec<u8>,
    in_use: bool,
}
impl SlhDsaOperation {
    #[allow(dead_code)]
    pub fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _info: &CK_MECHANISM_INFO,
    ) -> KResult<Self> {
        let sign_ctx = SlhDsaSignAddCtx::new(mech)?;

        let param_set = match key.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => p,
            Err(_) => {
                return err_rv!(CKR_TEMPLATE_INCOMPLETE);
            }
        };

        let sk = PrivKey::decode(key)?;
        let output_len = PrivKey::signature_len(param_set)?;

        Ok(SlhDsaOperation {
            output_len: output_len,
            public_key: None,
            private_key: Some(sk),
            sign_ctx: sign_ctx,
            finalized: false,
            data: Vec::new(),
            in_use: false,
        })
    }

    pub fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _info: &CK_MECHANISM_INFO,
    ) -> KResult<Self> {
        let sign_ctx = SlhDsaSignAddCtx::new(mech)?;

        let param_set = match key.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => p,
            Err(_) => {
                return err_rv!(CKR_TEMPLATE_INCOMPLETE);
            }
        };

        let pk = PubKey::decode(key)?;
        let output_len = PrivKey::signature_len(param_set)?;

        Ok(SlhDsaOperation {
            output_len: output_len,
            public_key: Some(pk.into()),
            private_key: None,
            sign_ctx: sign_ctx,
            finalized: false,
            data: Vec::new(),
            in_use: false,
        })
    }
}

impl MechOperation for SlhDsaOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for SlhDsaOperation {
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

        let private_key = match self.private_key.as_ref() {
            Some(PrivKey::SlhDsaShake128s(sk)) => {
                PrivKey::SlhDsaShake128s(sk.clone())
            }
            Some(PrivKey::SlhDsaShake128f(sk)) => {
                PrivKey::SlhDsaShake128f(sk.clone())
            }
            Some(PrivKey::SlhDsaShake192s(sk)) => {
                PrivKey::SlhDsaShake192s(sk.clone())
            }
            Some(PrivKey::SlhDsaShake192f(sk)) => {
                PrivKey::SlhDsaShake192f(sk.clone())
            }
            Some(PrivKey::SlhDsaShake256s(sk)) => {
                PrivKey::SlhDsaShake256s(sk.clone())
            }
            Some(PrivKey::SlhDsaShake256f(sk)) => {
                PrivKey::SlhDsaShake256f(sk.clone())
            }
            _ => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };

        let sig = private_key
            .try_sign_with_params(&self.data, &self.sign_ctx)
            .map_err(|_| to_rv!(CKR_FUNCTION_FAILED))?;

        let encoded_sig = sig.encode();
        signature[..encoded_sig.len()].copy_from_slice(&encoded_sig);

        Ok(())
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

impl Verify for SlhDsaOperation {
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

        let message = self.data.clone();
        let sig_buf = signature.to_vec();
        let sign_ctx = self.sign_ctx.clone();

        let public_key = match &self.public_key {
            Some(pk) => Arc::clone(pk),
            _ => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };

        let handle = std::thread::Builder::new()
            .name("slhdsa_verify_thread".into())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let sig = Signature::decode(&sig_buf)
                    .map_err(|_| to_rv!(CKR_SIGNATURE_LEN_RANGE))?;
                let result = public_key
                    .verify_with_params(&message, &sig, &sign_ctx)
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

        /* Propagate err_rv returned from thread */
        handle.join().map_err(|_| {
            error!(
                target: crate::QRYPTOTOKEN_TARGET,
                "Thread panicked during signature decoding or verification"
            );
            to_rv!(CKR_FUNCTION_FAILED)
        })??;

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
