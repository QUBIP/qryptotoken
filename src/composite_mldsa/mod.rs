// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms
use crate::adapters::libcrux::eddsa::{
    generate_key_pair as ed25519_generate_key_pair, Ed25519PrivKey,
    Ed25519PubKey, PrivKey as EdPrivKey, PubKey as EdPubKey,
};
use crate::adapters::libcrux::mldsa::{
    generate_key_pair as mldsa_generate_key_pair, PrivKey as MlDsaPrivKey,
    PrivKeyMlDsa65, PubKey as MlDsaPubKey, PubKeyMlDsa65,
};
use crate::attribute::{from_bool, from_bytes, from_ulong};
use crate::error::*;
use crate::interface::*;
use crate::log::*;
use crate::mechanism::*;
use crate::mldsa::sizes::*;
use crate::object::*;
use crate::{attr_element, err_rv, to_rv};
use once_cell::sync::Lazy;
use rand_core::{OsRng, TryRngCore};
use sha2::{Digest, Sha512};
use signature::{Signer, Verifier};
use std::fmt::Debug;

/* FIX: the sizes should not be handlded here */
const ED25519_PK_SIZE: usize = 32;
const ED25519_SK_SIZE: usize = 32;
const ED25519_SIG_SIZE: usize = 64;
const SHA512_DIGEST_SIZE: usize = 64;

pub(crate) const MIN_MLDSA65_ED25519_KEY_SIZE_BITS: CK_ULONG =
    ((ML_DSA_65_PK_SIZE + ED25519_PK_SIZE) as CK_ULONG) << 3;
pub(crate) const MAX_MLDSA65_ED25519_KEY_SIZE_BITS: CK_ULONG =
    ((ML_DSA_65_SK_SIZE + ED25519_SK_SIZE) as CK_ULONG) << 3;
pub(crate) const MLDSA65_ED25519_SIGNATURE_SIZE_BITS: CK_ULONG =
    ((ML_DSA_65_SIG_SIZE + ED25519_SIG_SIZE) as CK_ULONG) << 3;

/*
 * Implementation specifications of composite ML-DSA are described at
 * https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/06/
 *
 * When constructing the to-be-signed message representative M', several
 * domain separator values are pre-pended to the message pre-hash prior
 * to signing.
 *
 * M' :=  Prefix || Domain || len(ctx) || ctx || r || PH( M )
 */

/*
 * The fixed prefix string is the byte encoding of the following ASCII string.
 */
const PREFIX: &[u8; 32] = b"CompositeAlgorithmSignatures2025";

/* Domain separator for id-MLDSA65-Ed25519-SHA512 */
const DOMAIN_SEPARATOR_MLDSA65_ED25519_SHA512: &[u8] = &[
    0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x09, 0x01,
    0x0B,
];

/*
 * The application context `ctx` has a maximum length of 255 bytes.
 * This byte encodes the length of the `ctx` field.
 */
const CTX_LENGTH_SIZE: usize = 1;

/* The signature randomizer r is a 32 byte value. */
const RANDOMIZER_SIZE: usize = 32;

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

        let (mldsa65_sk, mldsa65_pk) = mldsa_generate_key_pair(CKP_ML_DSA_65)?;
        let (ed25519_sk, ed25519_pk) = ed25519_generate_key_pair()?;

        /* Serialize both public keys */
        let pk = serialize_public_key(&mldsa65_pk, &ed25519_pk)?;

        /* Serialize both private keys */
        let sk = serialize_private_key(&mldsa65_sk, &ed25519_sk)?;

        public_key.set_attr(from_bytes(CKA_VALUE, pk))?;
        private_key.set_attr(from_bytes(CKA_VALUE, sk))?;

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

    let len = private_value.len();
    if len != (ML_DSA_65_SK_SIZE + ED25519_SK_SIZE) {
        crate::error!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 CKR_ATTRIBUTE_VALUE_INVALID: The private value size doesn't \
                match the expected size."
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

    let len = public_value.len();
    if len != (ML_DSA_65_PK_SIZE + ED25519_PK_SIZE) {
        crate::error!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 CKR_ATTRIBUTE_VALUE_INVALID: The public value size doesn't \
                match the expected size."
        );
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    Ok(())
}

#[derive(Debug)]
struct MlDsa65Ed25519Operation {
    output_len: usize,
    mldsa65_pk: Option<MlDsaPubKey>,
    ed25519_pk: Option<EdPubKey>,
    mldsa65_sk: Option<MlDsaPrivKey>,
    ed25519_sk: Option<EdPrivKey>,
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
        let output_len = MLDSA65_ED25519_SIGNATURE_SIZE_BITS as usize;

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

        let (mldsa65_sk, ed25519_sk) =
            match deserialize_private_key(&private_key) {
                Ok((v1, v2)) => (v1, v2),
                Err(_) => {
                    crate::error!(
                        target: crate::QRYPTOTOKEN_TARGET,
                        "🦀 Error while deserializing the public key"
                    );
                    return err_rv!(CKR_PUBLIC_KEY_INVALID);
                }
            };

        Ok(MlDsa65Ed25519Operation {
            output_len,
            mldsa65_pk: None,
            mldsa65_sk: Some(mldsa65_sk),
            ed25519_pk: None,
            ed25519_sk: Some(ed25519_sk),
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
        let output_len = MLDSA65_ED25519_SIGNATURE_SIZE_BITS as usize;

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

        let (mldsa65_pk, ed25519_pk) =
            match deserialize_mldsa65_ed25519_public_key(&public_key) {
                Ok((v1, v2)) => (v1, v2),
                Err(_) => {
                    crate::error!(
                        target: crate::QRYPTOTOKEN_TARGET,
                        "🦀 Error while deserializing the public key"
                    );
                    return err_rv!(CKR_PUBLIC_KEY_INVALID);
                }
            };

        Ok(MlDsa65Ed25519Operation {
            output_len,
            mldsa65_pk: Some(mldsa65_pk),
            mldsa65_sk: None,
            ed25519_pk: Some(ed25519_pk),
            ed25519_sk: None,
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

            if self.mldsa65_sk.is_none() || self.ed25519_sk.is_none() {
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

        /* Generate a 32-byte random value that will act as a randomizer */
        let mut randomizer = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut randomizer)
            .map_err(|_| to_rv!(CKR_FUNCTION_FAILED))?;

        /* Construct the to-be-signed message representative M′ */
        let msg = compute_message(
            PREFIX,
            DOMAIN_SEPARATOR_MLDSA65_ED25519_SHA512,
            &randomizer,
            &self.data,
        )?;

        /*
         * `msg` is moved into the first thread (`mldsa_try_sign_thread`),
         * so we clone it for reuse in the second thread
         * (`ed25519_try_sign_thread`) to avoid ownership issues.
         */
        let msg_copy = msg.clone();

        let mldsa65_sk = match self.mldsa65_sk.as_ref() {
            Some(MlDsaPrivKey::MlDsa65(sk)) => {
                MlDsaPrivKey::MlDsa65(sk.clone())
            }
            _ => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };

        let ed25519_sk = match self.ed25519_sk.as_ref() {
            Some(EdPrivKey::Ed25519(sk)) => EdPrivKey::Ed25519(sk.clone()),
            _ => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };

        let mldsa_handle = std::thread::Builder::new()
            .name("mldsa_try_sign_thread".into())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let result = mldsa65_sk
                    .try_sign(&msg)
                    .map_err(|_| to_rv!(CKR_DEVICE_ERROR));
                result
            })
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread spawn failed during signing"
                );
                to_rv!(CKR_FUNCTION_FAILED)
            })?;

        let mldsa65_sig = mldsa_handle
            .join()
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread panicked during signing"
                );
                to_rv!(CKR_FUNCTION_FAILED)
            })?
            .map_err(|e| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "ML-DSA-65 signing failed: {e:?}"
                );
                to_rv!(CKR_DEVICE_ERROR)
            })?;

        debug!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 👌👌👌 ML-DSA-65 Signing succesful!"
        );

        let ed25519_handle = std::thread::Builder::new()
            .name("ed25519_try_sign_thread".into())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let result = ed25519_sk
                    .try_sign(&msg_copy)
                    .map_err(|_| to_rv!(CKR_DEVICE_ERROR));
                result
            })
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread spawn failed during Ed25519 signing"
                );
                to_rv!(CKR_FUNCTION_FAILED)
            })?;

        let ed25519_sig = ed25519_handle
            .join()
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread panicked during signing"
                );
                to_rv!(CKR_FUNCTION_FAILED)
            })?
            .map_err(|e| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Ed25519 Signing failed: {e:?}"
                );
                to_rv!(CKR_DEVICE_ERROR)
            })?;

        debug!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 👌👌👌 Ed25519 Signing succesful!"
        );

        /* Serialize the composite signature */
        let serialized_sig =
            serialize_signature_value(&randomizer, &mldsa65_sig, &ed25519_sig);

        signature[..serialized_sig.len()].copy_from_slice(&serialized_sig);

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

            if self.mldsa65_pk.is_none() || self.ed25519_pk.is_none() {
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

        let (rand, mldsa_sig, ed_sig) =
            match deserialize_signature_value(signature) {
                Ok(v) => v,
                Err(_) => return err_rv!(CKR_SIGNATURE_INVALID),
            };

        let randomizer: &[u8; 32] = match rand.as_slice().try_into() {
            Ok(r) => r,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        /* Construct the to-be-signed message representative M′ */
        let msg = compute_message(
            PREFIX,
            DOMAIN_SEPARATOR_MLDSA65_ED25519_SHA512,
            randomizer,
            &self.data,
        )?;

        /*
         * `msg` is moved into the first thread (`mldsa_verify_thread`), so
         * we clone it for reuse in the second thread (`ed25519_verify_thread`)
         * to avoid ownership issues.
         */
        let msg_copy = msg.clone();

        let mldsa65_pk = match self.mldsa65_pk.as_ref() {
            Some(MlDsaPubKey::MlDsa65(pk)) => MlDsaPubKey::MlDsa65(pk.clone()),
            _ => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };

        let ed25519_pk = match self.ed25519_pk.as_ref() {
            Some(EdPubKey::Ed25519(pk)) => EdPubKey::Ed25519(pk.clone()),
            _ => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };

        let mldsa_handle = std::thread::Builder::new()
            .name("mldsa_verify_thread".into())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let result = mldsa65_pk
                    .verify(&msg, &mldsa_sig)
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

        let ret = mldsa_handle
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
            "🦀 👌👌👌 ML-DSA-65 Verification succesful!"
        );

        let ed25519_handle = std::thread::Builder::new()
            .name("ed25519_verify_thread".into())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let result = ed25519_pk
                    .verify(&msg_copy, &ed_sig)
                    .map_err(|_| to_rv!(CKR_SIGNATURE_INVALID));
                result
            })
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread spawn failed during Ed25519 verification"
                );
                to_rv!(CKR_FUNCTION_FAILED)
            })?;

        let ret = ed25519_handle
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
                "Internal Ed25519 verification failure"
            );
            return ret;
        }

        debug!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 👌👌👌 Ed25519 Verification succesful!"
        );

        Ok(())
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

/// Deserialize a composite private key into its component parts:
/// an ML‑DSA‑65 private key and an Ed25519 private key.
///
/// Note: This does **not** strictly follow Section 5.2
/// (`DeserializePrivateKey`) of the draft which expects only the
/// **ML-DSA seed** (32 bytes) to be stored and reconstructed
/// deterministically.
///
/// In this implementation, the full ML‑DSA private key is stored directly
/// instead of deriving it from the seed. The remaining bytes are interpreted
/// as the Ed25519 private key.
///
/// # Returns
///
/// A tuple `(mldsa65_sk, ed25519_sk)` on success:
/// - `mldsa65_sk`: An `MlDsaPrivKey` containing the deserialized ML-DSA-65 key
/// - `ed25519_sk`: An `EdPrivKey` containing the deserialized Ed25519 key
///
/// Returns an error if the input length is incorrect or if either key fails
/// deserialization.
pub fn deserialize_private_key(
    key: &[u8],
) -> Result<(MlDsaPrivKey, EdPrivKey), KError> {
    if key.len() != ML_DSA_65_SK_SIZE + ED25519_SK_SIZE {
        error!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 The key size does not match the expected size of a \
                serialized MLDSA65-Ed25519 key: {} != {}",
            key.len(),
            ML_DSA_65_SK_SIZE + ED25519_SIG_SIZE
        );
        return err_rv!(CKR_DATA_INVALID);
    }

    /* Split the key into ML-DSA-65 and Ed25519 components */
    let (mldsa65_bytes, ed25519_bytes) = key.split_at(ML_DSA_65_SK_SIZE);

    let sk = match PrivKeyMlDsa65::try_from(mldsa65_bytes) {
        Ok(sk) => sk,
        Err(e) => {
            crate::error!(
                target: crate::QRYPTOTOKEN_TARGET,
                "️🦀 Error converting ML-DSA-65 encoded key to PrivKey: {e:?}"
            );
            return Err(e);
        }
    };
    let mldsa65_sk = MlDsaPrivKey::MlDsa65(sk);

    let sk = match Ed25519PrivKey::try_from(ed25519_bytes) {
        Ok(sk) => sk,
        Err(e) => {
            crate::error!(
                target: crate::QRYPTOTOKEN_TARGET,
                "️🦀 Error converting Ed25519 encoded key to PrivKey: {e:?}"
            );
            return Err(e);
        }
    };
    let ed25519_sk = EdPrivKey::Ed25519(sk);

    Ok((mldsa65_sk, ed25519_sk))
}

/// This function desrializes a composite public key (MLDSA65-Ed25519) into
/// its components. It parses each constituent encoded public key and
/// initializes each respective PubKey type.
///
/// Composite-ML-DSA<OID>.DeserializePublicKey(bytes) → (mldsaPK, tradPK)
///
/// # Returns
///
/// - `Ok(MlDsaPubKey, EdPubKey)`: A tuple with initialized PubKey types for
///                                for each endoded public key component.
pub fn deserialize_mldsa65_ed25519_public_key(
    key: &[u8],
) -> Result<(MlDsaPubKey, EdPubKey), KError> {
    if key.len() != ML_DSA_65_PK_SIZE + ED25519_PK_SIZE {
        error!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 The key size does not match the expected size of a \
                serialized MLDSA65-Ed25519 key: {} != {}",
            key.len(),
            ML_DSA_65_PK_SIZE + ED25519_PK_SIZE
        );
        return err_rv!(CKR_DATA_INVALID);
    }

    /* Split the key into ML-DSA-65 and Ed25519 components */
    let (mldsa65_bytes, ed25519_bytes) = key.split_at(ML_DSA_65_PK_SIZE);

    let pk = match PubKeyMlDsa65::try_from(mldsa65_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            crate::error!(
                target: crate::QRYPTOTOKEN_TARGET,
                "️🦀 Error converting ML-DSA-65 encoded key to PubKey: {e:?}"
            );
            return Err(e);
        }
    };
    let mldsa65_pk = MlDsaPubKey::MlDsa65(pk);

    let pk = match Ed25519PubKey::try_from(ed25519_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            crate::error!(
                target: crate::QRYPTOTOKEN_TARGET,
                "️🦀 Error converting Ed25519 encoded key to PubKey: {e:?}"
            );
            return Err(e);
        }
    };
    let ed25519_pk = EdPubKey::Ed25519(pk);

    Ok((mldsa65_pk, ed25519_pk))
}

/// Deserializes a composite signature that is encoded as
/// `r || mldsaSig || tradSig
///
/// - `r`: 32-byte randomizer
/// - `mldsaSig`: ML-DSA signature
/// - `tradSig`: Traditional signature
///
/// # Returns
///
/// ``KResult<(Vec<u8>, Vec<u8>, Vec<u8>)>: A triple containg the deserialized
///                                         fields of the compsoite signature:
///                                         - `randomizer`
///                                         - `mldsaSig`
///                                         - `tradSig`
pub fn deserialize_signature_value(
    composite_sig: &[u8],
) -> KResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    /* Check that the composite signature length matches the expected length */
    let expected_len = RANDOMIZER_SIZE + ML_DSA_65_SIG_SIZE + ED25519_SIG_SIZE;
    let sig_len = composite_sig.len();
    if sig_len != expected_len {
        crate::error!(
            target: crate::QRYPTOTOKEN_TARGET,
            "️🦀 The composite signature length doesn't match the expected \
                length. Composite sig length {} != expected sig length {}",
            sig_len,
            expected_len
        );
        return err_rv!(CKR_SIGNATURE_LEN_RANGE);
    }

    /* First split the randomizer r */
    let (r, sigs) = composite_sig.split_at(RANDOMIZER_SIZE);

    /* Split ML-DSA-65 and Ed25519 signatures */
    let (mldsa_sig, ed_sig) = sigs.split_at(ML_DSA_65_SIG_SIZE);

    Ok((r.to_vec(), mldsa_sig.to_vec(), ed_sig.to_vec()))
}

/// Serializes a composite signature by concatenating:
/// - `r`: the 32-byte randomizer
/// - `mldsaSig`: the ML-DSA signature (fixed-size)
/// - `tradSig`: the traditional signature (Ed25519, etc.)
///
/// # Returns
///
/// `Vec<u8>`: Serialized composite signature in the format:
///            `randomizer || mldsa65_sig || ed25519_sig`.
pub fn serialize_signature_value(
    randomizer: &[u8; 32],
    mldsa65_sig: &[u8],
    ed25519_sig: &[u8],
) -> Vec<u8> {
    let mut serialized_sig = Vec::with_capacity(
        RANDOMIZER_SIZE + mldsa65_sig.len() + ed25519_sig.len(),
    );
    serialized_sig.extend_from_slice(randomizer);
    serialized_sig.extend_from_slice(mldsa65_sig);
    serialized_sig.extend_from_slice(ed25519_sig);

    serialized_sig
}

/// Serializes a composite public key
///
/// Composite-ML-DSA.SerializePublicKey(mldsaPK, tradPK) -> bytes
///
/// Output format: mldsaPK || ed25519PK
///
/// # Returns
///
/// `Vec<u8>` with the serialized public key bytes on success
/// `KError` on failure.
pub fn serialize_public_key(
    mldsa65_pk: &MlDsaPubKey,
    ed25519_pk: &EdPubKey,
) -> Result<Vec<u8>, KError> {
    let mut serialized_pk = Vec::new();

    let mldsa65_bytes = mldsa65_pk.as_ref();
    serialized_pk.extend_from_slice(&mldsa65_bytes);

    let ed25519_bytes = ed25519_pk.as_ref();
    serialized_pk.extend_from_slice(&ed25519_bytes);

    Ok(serialized_pk)
}

/// Serializes a composite private key.
///
/// Composite-ML-DSA.SerializePrivateKey(mldsaSeed, tradSK) -> bytes
///
/// This implementation deviates from the IETF draft by serializing the **full
/// ML-DSA-65 private key** rather than the 32-byte seed. The Ed25519
/// private key is appended as-is.
///
/// Output format: mldsa_sk || ed25519_sk
///
/// # Returns
///
/// `Vec<u8>` with the serialized private key bytes on success
/// `KError` on failure.
pub fn serialize_private_key(
    mldsa65_sk: &MlDsaPrivKey,
    ed25519_sk: &EdPrivKey,
) -> Result<Vec<u8>, KError> {
    let mut serialized_sk = Vec::new();

    let mldsa65_bytes = mldsa65_sk.as_ref();
    serialized_sk.extend_from_slice(&mldsa65_bytes);

    let ed25519_bytes = ed25519_sk.as_ref();
    serialized_sk.extend_from_slice(&ed25519_bytes);

    Ok(serialized_sk)
}

/// Constructs the to-be-signed message representative M'.
///
/// M' := Prefix || Domain || len(ctx) || ctx || r || PH(M)
///
/// This function constructs the final message buffer to be signed by both
/// ML-DSA and the traditional signature algorithm.
///
/// # Returns:
///
/// `KResult<Vec<u8>>`: The final message representative M' encoded as raw
///                     bytes
pub fn compute_message(
    prefix: &[u8],
    domain: &[u8],
    randomizer: &[u8; 32],
    message: &[u8],
) -> KResult<Vec<u8>> {
    let mut to_be_signed = Vec::with_capacity(
        prefix.len()
            + domain.len()
            + CTX_LENGTH_SIZE
            + RANDOMIZER_SIZE
            + SHA512_DIGEST_SIZE,
    );

    to_be_signed.extend_from_slice(prefix);
    to_be_signed.extend_from_slice(domain);
    /* ctx is assumed to be empty */
    to_be_signed.push(0);
    to_be_signed.extend_from_slice(randomizer);
    let digest = Sha512::digest(message);

    /* Fail early if the SHA-512 digest is entirely zero */
    if digest.iter().all(|&b| b == 0) {
        return err_rv!(CKR_FUNCTION_FAILED);
    }

    to_be_signed.extend_from_slice(&digest);

    Ok(to_be_signed)
}
