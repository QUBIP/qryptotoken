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
use sha2::{Digest, Sha512};
use signature::Verifier;
use std::fmt::Debug;

/* Imports from libcrux::eddsa */
use crate::adapters::libcrux::eddsa::{
    PrivKey as EdPrivKey, PubKey as EdPubKey, ED25519_PK_SIZE,
    ED25519_SIG_SIZE, ED25519_SK_SIZE,
};

// Imports from libcrux::mldsa
use crate::adapters::libcrux::mldsa::{
    PrivKey as MlDsaPrivKey, PubKey as MlDsaPubKey,
};

// Imports for ML-DSA size constants
use crate::mldsa::sizes::*;

/// 32-byte randomizer used in M' to prevent mixed-key forgery attacks.
/// See: https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-06.html#name-implications-of-signature-r
const RANDOMIZER_SIZE: usize = 32;

/*  Composite public key sizes in bits */
pub(crate) const MIN_COMPOSITE_KEY_SIZE_BITS: CK_ULONG =
    ((ML_DSA_44_PK_SIZE + ED25519_PK_SIZE) as CK_ULONG) << 3;
pub(crate) const MAX_COMPOSITE_KEY_SIZE_BITS: CK_ULONG =
    ((ML_DSA_87_SK_SIZE + ED25519_SK_SIZE) as CK_ULONG) << 3;
pub(crate) const _ML_DSA_SIGNATURE_SIZE_BITS: CK_ULONG =
    ((ML_DSA_87_SIG_SIZE + ED25519_SIG_SIZE) as CK_ULONG) << 3;
/// Domain separation prefix for composite signature binding.
/// See: Section 3.2 & 10.4 of https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-06.html
const COMPOSITE_PREFIX: &[u8; 32] = b"CompositeAlgorithmSignatures2025";

/// Application context string used in signature binding.
/// Currently empty (`b""`) as no application-specific context is required.
/// This may be set to a byte string to bind the signature to a specific use-case.
///
/// Example:
///   let ctx = 0813061205162623;
const COMPOSITE_CTX: &[u8] = b"";

/// Output size of SHA-512 in bytes.
const SHA512_DIGEST_SIZE: usize = 64;

/// Context length prefix size, always 1 byte as defined in
/// https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-06.html#name-pre-hashing-and-randomizer
/// This byte encodes the length of the `ctx` field (max 255), even if ctx is empty.
const CTX_LENGTH_PREFIX_SIZE: usize = 1;

/// Domain separator for id-MLDSA65-Ed25519-SHA512
const DOMAIN_SEPARATOR_MLDSA65_ED25519_SHA512: &[u8] = &[
    0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x09, 0x01,
    0x0B,
];

/// The Composite Public Key Factory for ML-DSA + Ed25519.
///
/// It helps creating ML-DSA + Ed25519 public key objects.
#[derive(Debug)]
pub struct CompositeMlDsaPubFactory {
    attributes: Vec<ObjectAttr>,
}

impl CompositeMlDsaPubFactory {
    pub fn new() -> CompositeMlDsaPubFactory {
        let mut data = CompositeMlDsaPubFactory {
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

impl ObjectFactory for CompositeMlDsaPubFactory {
    /// Creates a ML-DSA + Ed25519 public key object using a given template
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template)?;
        /* Always validate ML-DSA + Ed25519 imported attributes */
        mldsa_ed25519_check_pub_import(&mut obj)?;

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyFactory for CompositeMlDsaPubFactory {}
impl PubKeyFactory for CompositeMlDsaPubFactory {}

/// The ML-DSA + Ed25519 Private Key Factory.
///
/// It helps creating ML-DSA + Ed25519 private key objects.
#[derive(Debug)]
pub struct CompositeMlDsaPrivFactory {
    attributes: Vec<ObjectAttr>,
}

impl CompositeMlDsaPrivFactory {
    /// Initialize a new `CompositeMlDsaPrivFactory` with pre-defined attributes
    pub fn new() -> CompositeMlDsaPrivFactory {
        let mut data = CompositeMlDsaPrivFactory {
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

        data
    }
}

impl ObjectFactory for CompositeMlDsaPrivFactory {
    /// Creates a ML-DSA + Ed25519 private key object using a given template
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template)?;

        /* Always validate ML-DSA + Ed25519 imported attributes */
        mldsa_ed25519_check_priv_import(&mut obj)?;

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

impl CommonKeyFactory for CompositeMlDsaPrivFactory {}

impl PrivKeyFactory for CompositeMlDsaPrivFactory {}

/// Lazily-initialized, static Public Key factory.
///
/// This factory is created once at runtime on first access and is
/// intended to remain immutable for the lifetime of the process.
static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(CompositeMlDsaPubFactory::new()));

/// Lazily-initialized, static Public Key factory.
///
/// This factory is created once at runtime on first access and is
/// intended to remain immutable for the lifetime of the process.
static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(CompositeMlDsaPrivFactory::new()));

/// Object that represents ML-DSA + Ed25519 mechanism and its supported operations
#[derive(Debug)]
pub struct CompositeMlDsaMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for CompositeMlDsaMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }
    /*
    fn sign_new(
            &self,
            mech: &CK_MECHANISM,
            key: &Object,
        ) -> KResult<Box<dyn Sign>> {
            if self.info.flags & CKF_SIGN != CKF_SIGN {
                return err_rv!(CKR_MECHANISM_INVALID);
            }

            match key.check_key_ops(CKO_PRIVATE_KEY, CKK_MLDSA65_ED25519_SHA512, CKA_SIGN) {
                Ok(_) => (),
                Err(e) => return Err(e),
            }

            let _mech = mech.mechanism;
            let ret =
                Box::new(CompositeMlDsaOperation::sign_new(mech, key, &self.info)?);

            return Ok(ret);
        }
     */
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
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        /* Match against the actual key type */
        match key.check_key_ops(
            CKO_PUBLIC_KEY,
            CKK_MLDSA65_ED25519_SHA512,
            CKA_VERIFY,
        ) {
            Ok(_) => (),
            Err(e) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "️🦀 Some error checking key ops: {e:?}"
                );
                return Err(e);
            }
        }

        let ret = Box::new(CompositeMlDsaOperation::verify_new(
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

        /* Ensure the CKA_KEY_TYPE attribute is set to CKK_MLDSA65_ED25519_SHA512 */
        if !public_key.check_or_set_attr(from_ulong(
            CKA_KEY_TYPE,
            CKK_MLDSA65_ED25519_SHA512,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        /* Extract the parameter set for ML-DSA and ensure that is a valid one */
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

        /* Ensure the CKA_KEY_TYPE attribute is set to CKK_MLDSA65_ED25519_SHA512 */
        if !private_key.check_or_set_attr(from_ulong(
            CKA_KEY_TYPE,
            CKK_MLDSA65_ED25519_SHA512,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        let (mldsa_sk, mldsa_pk) =
            crate::adapters::libcrux::mldsa::generate_key_pair(param_set)?;
        let (eddsa_sk, eddsa_pk) =
            crate::adapters::libcrux::eddsa::generate_key_pair()?;

        // Public key = SerializePublicKey(mldsaPK, tradPK)
        let pk = serialize_public_key(&mldsa_pk, &eddsa_pk)?;

        // Private key = serialize_private_key(mldsaSeed, tradSK)
        let sk = serialize_private_key(&mldsa_sk, &eddsa_sk)?;

        public_key.set_attr(from_ulong(CKA_PARAMETER_SET, param_set))?;
        private_key.set_attr(from_ulong(CKA_PARAMETER_SET, param_set))?;

        /*
         * Set the CKA_VALUE attribute using the serialized public and private keys.
         *
         * Since `serialize_public_key()` and `serialize_private_key()` already return owned `Vec<u8>` values,
         * there's no need to call `.as_ref()` (which would convert to `&[u8]`) or `.clone()` (which would
         * unnecessarily duplicate the data). We pass the owned `Vec<u8>` directly into `from_bytes()`,
         * avoiding redundant conversions and allowing efficient move semantics.
         */
        public_key.set_attr(from_bytes(CKA_VALUE, pk))?;
        private_key.set_attr(from_bytes(CKA_VALUE, sk))?;

        default_key_attributes(&mut private_key, mech.mechanism)?;
        default_key_attributes(&mut public_key, mech.mechanism)?;
        Ok((public_key, private_key))
    }
}

/// This function registers all ML-DSA related mechanism and PubKey/PrivKey
/// factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(
        CKM_MLDSA65_ED25519_SHA512,
        Box::new(CompositeMlDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_COMPOSITE_KEY_SIZE_BITS,
                ulMaxKeySize: MAX_COMPOSITE_KEY_SIZE_BITS,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_MLDSA65_ED25519_SHA512_KEYGEN,
        Box::new(CompositeMlDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_COMPOSITE_KEY_SIZE_BITS,
                ulMaxKeySize: MAX_COMPOSITE_KEY_SIZE_BITS,
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    );

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_MLDSA65_ED25519_SHA512),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_MLDSA65_ED25519_SHA512),
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
fn mldsa_ed25519_check_priv_import(obj: &mut Object) -> KResult<()> {
    crate::trace!(
        target: crate::QRYPTOTOKEN_TARGET,
        "🦀 mldsa_ed25519_check_priv_import({obj:?}) called"
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
    Ok(())
}

fn mldsa_ed25519_check_pub_import(obj: &mut Object) -> KResult<()> {
    crate::trace!(
        target: crate::QRYPTOTOKEN_TARGET,
        "🦀 mldsa_ed25519_check_pub_import({obj:?}) called"
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
    Ok(())
}

#[derive(Debug)]
struct CompositeMlDsaOperation {
    output_len: usize,
    mldsa_pk: Option<MlDsaPubKey>,
    _mldsa_sk: Option<MlDsaPrivKey>,
    eddsa_pk: Option<EdPubKey>,
    _eddsa_sk: Option<EdPrivKey>,
    finalized: bool,
    data: Vec<u8>,
    in_use: bool,
}
impl CompositeMlDsaOperation {
    /*
        pub fn sign_new(
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
            let mldsa_pk: Option<MlDsaPubKey> = None;
            let eddsa_pk: Option<EdPubKey> = None;
            let serialized = match key.get_attr_as_bytes(CKA_VALUE) {
                Ok(v) => v,
                Err(_) => {
                    crate::error!(
                        target: crate::QRYPTOTOKEN_TARGET,
                        "🦀 CKR_TEMPLATE_INCOMPLETE: missing CKA_VALUE"
                    );
                    return err_rv!(CKR_TEMPLATE_INCOMPLETE);
                }
            };
            let (mldsa_sk, eddsa_sk) = deserialize_private_key(&serialized)?;

            Ok(CompositeMlDsaOperation {
                output_len,
                mldsa_pk,
                mldsa_sk: Some(mldsa_sk),
                eddsa_pk,
                eddsa_sk: Some(eddsa_sk),
                finalized: false,
                data: Vec::new(),
                in_use: false,
            })
        }
    */
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
        let _mldsa_sk: Option<MlDsaPrivKey> = None;
        let _eddsa_sk: Option<EdPrivKey> = None;
        let serialized = match key.get_attr_as_bytes(CKA_VALUE) {
            Ok(v) => v,
            Err(_) => {
                crate::error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "🦀 CKR_TEMPLATE_INCOMPLETE: missing CKA_VALUE"
                );
                return err_rv!(CKR_TEMPLATE_INCOMPLETE);
            }
        };
        let (mldsa_pk, eddsa_pk) = deserialize_public_key(&serialized)?;

        Ok(CompositeMlDsaOperation {
            output_len,
            mldsa_pk: Some(mldsa_pk),
            _mldsa_sk,
            eddsa_pk: Some(eddsa_pk),
            _eddsa_sk,
            finalized: false,
            data: Vec::new(),
            in_use: false,
        })
    }
}

impl MechOperation for CompositeMlDsaOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}
/*
impl Sign for CompositeMlDsaOperation {
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

            if self._mldsa_sk.is_none() || self._eddsa_sk.is_none() {
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

        let mldsa_sk = match self._mldsa_sk.as_ref() {
            Some(MlDsaPrivKey::MlDsa44(sk)) => {
                MlDsaPrivKey::MlDsa44(sk.clone())
            }
            Some(MlDsaPrivKey::MlDsa65(sk)) => {
                MlDsaPrivKey::MlDsa65(sk.clone())
            }
            Some(MlDsaPrivKey::MlDsa87(sk)) => {
                MlDsaPrivKey::MlDsa87(sk.clone())
            }
            _ => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };
        let eddsa_sk = match self._eddsa_sk.as_ref() {
            Some(EdPrivKey::Ed25519(sk)) => sk.clone(),
            _ => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };
        let mldsa_sig = mldsa_sk
            .try_sign(&self.data)
            .map_err(|_| to_rv!(CKR_FUNCTION_FAILED))?;

        let eddsa_sig = eddsa_sk
            .try_sign(&self.data)
            .map_err(|_| to_rv!(CKR_FUNCTION_FAILED))?;

        let composite_sig = serialize_signature_value(
            &RANDOMIZER_SIZE,
            mldsa_sig.as_ref(),
            eddsa_sig.as_ref(),
        );
        let encoded_signature: &[u8] = composite_sig.as_ref();
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
*/
impl Verify for CompositeMlDsaOperation {
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

            if self.mldsa_pk.is_none() || self.eddsa_pk.is_none() {
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

        let (randomizer, mldsa_sig, eddsa_sig) =
            match deserialize_signature_value(signature) {
                Ok(v) => v,
                Err(_) => return err_rv!(CKR_SIGNATURE_INVALID),
            };

        let mldsa_pk = match self.mldsa_pk.as_ref() {
            Some(MlDsaPubKey::MlDsa44(pk)) => MlDsaPubKey::MlDsa44(pk.clone()),
            Some(MlDsaPubKey::MlDsa65(pk)) => MlDsaPubKey::MlDsa65(pk.clone()),
            Some(MlDsaPubKey::MlDsa87(pk)) => MlDsaPubKey::MlDsa87(pk.clone()),
            _ => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };
        let eddsa_pk = match self.eddsa_pk.as_ref() {
            Some(EdPubKey::Ed25519(pk)) => EdPubKey::Ed25519((*pk).clone()),
            None => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };

        let domain = DOMAIN_SEPARATOR_MLDSA65_ED25519_SHA512;

        /* Construct the to-be-signed message representative M′ as per Section 3.2 */
        let message = compute_message(
            COMPOSITE_PREFIX,
            &domain,
            COMPOSITE_CTX,
            &randomizer,
            &self.data,
        )?;

        /*
         * `message` is moved into the first thread (`mldsa_verify_thread`), so
         * we clone it for reuse in the second thread (`ed25519_verify_thread`
         * to avoid ownership issues.
         */
        let message2 = message.clone();

        let mldsa_handle = std::thread::Builder::new()
            .name("mldsa_verify_thread".into())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let result = mldsa_pk
                    .verify(&message, &mldsa_sig)
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
            "🦀 👌👌👌 Verification succesful!"
        );

        let eddsa_handle = std::thread::Builder::new()
            .name("ed25519_verify_thread".into())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let result = eddsa_pk
                    .verify(&message2, &eddsa_sig)
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

        let ret = eddsa_handle
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

        Ok(())
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}
/// Serializes a composite public key as specified in Section 5.1
/// of https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-06.html#name-serializepublickey-and-dese.
///
/// Composite-ML-DSA.SerializePublicKey(mldsaPK, tradPK) → bytes
///
/// This implementation assumes a fixed configuration:
/// - ML-DSA parameter set: ML-DSA-65 (1952 bytes)
/// - Traditional key: Ed25519 (32 bytes)
///
/// Output format: mldsaPK || ed25519PK
#[allow(dead_code)]
pub fn serialize_public_key(
    mldsa_pk: &MlDsaPubKey,
    eddsa_pk: &EdPubKey,
) -> Result<Vec<u8>, KError> {
    let mut serialized = Vec::new();

    let mldsa_bytes = mldsa_pk.as_ref().to_vec();
    serialized.extend_from_slice(&mldsa_bytes);

    let eddsa_bytes = eddsa_pk.as_ref().to_vec();
    serialized.extend_from_slice(&eddsa_bytes);

    Ok(serialized)
}
/// Deserializes a composite public key into its ML-DSA-65 and Ed25519
/// components as defined in Section 5.1 of
/// https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-06.html#name-serializepublickey-and-dese,
///
/// Composite-ML-DSA<OID>.DeserializePublicKey(bytes) → (mldsaPK, tradPK)
///
/// - ML-DSA parameter set is fixed to ML-DSA-65 (1952 bytes)
/// - Traditional key is Ed25519 (32 bytes)
pub fn deserialize_public_key(
    key: &[u8],
) -> Result<(MlDsaPubKey, EdPubKey), KError> {
    if key.len() < ML_DSA_65_PK_SIZE + ED25519_PK_SIZE {
        return err_rv!(CKR_GENERAL_ERROR);
    }
    /* Split the key into ML-DSA and Ed25519 components */
    let (mldsa_bytes, eddsa_bytes) = key.split_at(ML_DSA_65_PK_SIZE);

    let mldsa_pk = MlDsaPubKey::MlDsa65(
        crate::adapters::libcrux::mldsa::PubKeyMlDsa65::try_from(mldsa_bytes)?,
    );

    let eddsa_pk = EdPubKey::Ed25519(
        crate::adapters::libcrux::eddsa::Ed25519PubKey::try_from(eddsa_bytes)?,
    );

    Ok((mldsa_pk, eddsa_pk))
}
/// Serializes a composite private key as defined in Section 5.2
/// of https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-06.html#name-serializeprivatekey-and-des,
///
/// Composite-ML-DSA.SerializePrivateKey(mldsaSeed, tradSK) → bytes
///
/// This implementation deviates from the draft by serializing the **full
/// ML-DSA-65 private key** instead of only the 32-byte seed. The Ed25519
/// private key is appended as-is.
///
/// Output format: full_mldsa_sk || ed25519_sk
#[allow(dead_code)]
pub fn serialize_private_key(
    mldsa_sk: &MlDsaPrivKey,
    eddsa_sk: &EdPrivKey,
) -> Result<Vec<u8>, KError> {
    let mut serialized = Vec::new();

    let mldsa_bytes = mldsa_sk.as_ref().to_vec();
    serialized.extend_from_slice(&mldsa_bytes);

    let eddsa_bytes = eddsa_sk.as_ref().to_vec();
    serialized.extend_from_slice(&eddsa_bytes);

    Ok(serialized)
}
/// Deserialize a composite private key into its component parts:
/// an ML‑DSA‑65 private key and an Ed25519 private key.
///
/// Note: This does **not** strictly follow Section 5.2
/// (`DeserializePrivateKey`) of the draft: https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-06.html#name-serializeprivatekey-and-des,
/// which expects only the **ML-DSA seed** (32 bytes) to be stored and
/// reconstructed deterministically.
///
/// In this implementation, the full ML‑DSA private key is stored directly
/// instead of deriving it from the seed. The remaining bytes are interpreted
/// as the Ed25519 private key.
#[allow(dead_code)]
pub fn deserialize_private_key(
    key: &[u8],
) -> Result<(MlDsaPrivKey, EdPrivKey), KError> {
    if key.len() < ML_DSA_65_SK_SIZE + ED25519_SK_SIZE {
        return err_rv!(CKR_GENERAL_ERROR);
    }

    /* Split the key at the ML-DSA private key size */
    let (mldsa_bytes, eddsa_bytes) = key.split_at(ML_DSA_65_SK_SIZE);

    let mldsa_sk = MlDsaPrivKey::MlDsa65(
        crate::adapters::libcrux::mldsa::PrivKeyMlDsa65::try_from(mldsa_bytes)?,
    );

    let eddsa_sk = EdPrivKey::Ed25519(
        crate::adapters::libcrux::eddsa::Ed25519PrivKey::try_from(eddsa_bytes)?,
    );

    Ok((mldsa_sk, eddsa_sk))
}

/// Serializes a composite signature by concatenating:
/// - `r`: the 32-byte randomizer
/// - `mldsaSig`: the ML-DSA signature (fixed-size)
/// - `tradSig`: the traditional signature (Ed25519, etc.)
///
/// Resulting format: `r || mldsaSig || tradSig`
/// Based on Section 5.3 (https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-06.html).
#[allow(dead_code)]
pub fn serialize_signature_value(
    r: &[u8],
    mldsa_sig: &[u8],
    trad_sig: &[u8],
) -> Vec<u8> {
    let mut serialized =
        Vec::with_capacity(r.len() + mldsa_sig.len() + trad_sig.len());
    serialized.extend_from_slice(r);
    serialized.extend_from_slice(mldsa_sig);
    serialized.extend_from_slice(trad_sig);
    serialized
}

/// Deserializes a composite signature in the format
/// `r || mldsaSig || tradSig`.
///
/// - `r`: 32-byte randomizer
/// - `mldsaSig`: ML-DSA signature (length based on parameter set)
/// - `tradSig`: Traditional signature (e.g., Ed25519)
///
/// Uses fixed ML-DSA signature lengths (e.g., 3309 bytes for ML-DSA-65).
/// Based on Section 5.3 (https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-06.html).
pub fn deserialize_signature_value(
    composite_sig: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), &'static str> {
    // Check minimum length
    let expected_len = RANDOMIZER_SIZE + ML_DSA_65_SIG_SIZE + ED25519_SIG_SIZE;
    if composite_sig.len() < expected_len {
        return Err("Composite signature length is too short");
    }
    // Split randomizer and the rest
    let (r, sigs) = composite_sig.split_at(RANDOMIZER_SIZE);

    // Split ML-DSA and Ed25519 signatures
    let (mldsa_sig, ed_sig) = sigs.split_at(ML_DSA_65_SIG_SIZE);

    Ok((r.to_vec(), mldsa_sig.to_vec(), ed_sig.to_vec()))
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

    let mldsa_sig_size = match param_set {
        CKP_ML_DSA_44 => ML_DSA_44_SIG_SIZE as usize,
        CKP_ML_DSA_65 => ML_DSA_65_SIG_SIZE as usize,
        CKP_ML_DSA_87 => ML_DSA_87_SIG_SIZE as usize,
        _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
    };
    Ok(mldsa_sig_size + ED25519_SIG_SIZE)
}
/// Constructs the to-be-signed message representative M' as defined in
/// Section 3.2 of the
/// https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-06.html#name-prefix-domain-separators-an
///
/// M' := Prefix || Domain || len(ctx) || ctx || r || PH(M)
///
/// This function performs length validations and assembles the final message
/// buffer to be signed by both ML-DSA and the traditional signature algorithm.
pub fn compute_message(
    prefix: &[u8],
    domain: &[u8],
    ctx: &[u8],
    randomizer: &[u8],
    message: &[u8],
) -> KResult<Vec<u8>> {
    /* Check that context length fits in u8 (as required by spec) */
    assert!(ctx.len() <= 255, "Context length exceeds 255 bytes");
    /* Check randomizer length */
    assert_eq!(
        randomizer.len(),
        RANDOMIZER_SIZE,
        "Randomizer must be 64 bytes"
    );

    let mut to_be_signed = Vec::with_capacity(
        prefix.len()
            + domain.len()
            + CTX_LENGTH_PREFIX_SIZE
            + ctx.len()
            + RANDOMIZER_SIZE
            + SHA512_DIGEST_SIZE,
    );

    to_be_signed.extend_from_slice(prefix);
    to_be_signed.extend_from_slice(domain);
    to_be_signed.push(ctx.len() as u8);
    to_be_signed.extend_from_slice(ctx);
    to_be_signed.extend_from_slice(randomizer);
    let digest = Sha512::digest(message);

    // Sanity check: fail early if the SHA-512 digest is entirely zero.
    if digest.iter().all(|&b| b == 0) {
        return err_rv!(CKR_FUNCTION_FAILED);
    }

    to_be_signed.extend_from_slice(&digest);

    Ok(to_be_signed)
}
