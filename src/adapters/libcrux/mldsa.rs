use crate::err_rv;
use crate::error::*;
use crate::interface::*;
use crate::log::*;
use crate::mldsa::sizes::*;
use crate::object::*;
use libcrux_ml_dsa::{
    ml_dsa_44::{
        self, MLDSA44Signature, MLDSA44SigningKey, MLDSA44VerificationKey,
    },
    ml_dsa_65::{
        self, MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey,
    },
    ml_dsa_87::{
        self, MLDSA87Signature, MLDSA87SigningKey, MLDSA87VerificationKey,
    },
};
use signature::{Signer, Verifier};

/* Wrapper structs for ML-DSA public key types */
#[derive(Clone)]
pub struct PubKeyMlDsa44(Box<MLDSA44VerificationKey>);
#[derive(Clone)]
pub struct PubKeyMlDsa65(Box<MLDSA65VerificationKey>);
#[derive(Clone)]
pub struct PubKeyMlDsa87(Box<MLDSA87VerificationKey>);

/* Wrapper structs for ML-DSA private key types */
#[derive(Clone)]
pub struct PrivKeyMlDsa44(Box<MLDSA44SigningKey>);
#[derive(Clone)]
pub struct PrivKeyMlDsa65(Box<MLDSA65SigningKey>);
#[derive(Clone)]
pub struct PrivKeyMlDsa87(Box<MLDSA87SigningKey>);

pub enum PubKey {
    MlDsa44(PubKeyMlDsa44),
    MlDsa65(PubKeyMlDsa65),
    MlDsa87(PubKeyMlDsa87),
}

pub enum PrivKey {
    MlDsa44(PrivKeyMlDsa44),
    MlDsa65(PrivKeyMlDsa65),
    MlDsa87(PrivKeyMlDsa87),
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubKey")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivKey")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl PubKey {
    pub fn as_ref(&self) -> &[u8] {
        match self {
            PubKey::MlDsa44(pk) => pk.0.as_ref().as_slice(),
            PubKey::MlDsa65(pk) => pk.0.as_ref().as_slice(),
            PubKey::MlDsa87(pk) => pk.0.as_ref().as_slice(),
        }
    }
}

impl PrivKey {
    pub fn as_ref(&self) -> &[u8] {
        match self {
            PrivKey::MlDsa44(sk) => sk.0.as_ref().as_slice(),
            PrivKey::MlDsa65(sk) => sk.0.as_ref().as_slice(),
            PrivKey::MlDsa87(sk) => sk.0.as_ref().as_slice(),
        }
    }
}

impl Verifier<Vec<u8>> for PubKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &Vec<u8>,
    ) -> Result<(), signature::Error> {
        let result = match self {
            PubKey::MlDsa44(pk) => {
                let sig: [u8; ML_DSA_44_SIG_SIZE] = signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| signature::Error::new())?;
                let sig = MLDSA44Signature::new(sig);

                ml_dsa_44::verify(&pk.0, msg, &[], &sig)
            }
            PubKey::MlDsa65(pk) => {
                let sig: [u8; ML_DSA_65_SIG_SIZE] = signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| signature::Error::new())?;
                let sig = MLDSA65Signature::new(sig);

                ml_dsa_65::verify(&pk.0, msg, &[], &sig)
            }
            PubKey::MlDsa87(pk) => {
                let sig: [u8; ML_DSA_87_SIG_SIZE] = signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| signature::Error::new())?;
                let sig = MLDSA87Signature::new(sig);

                ml_dsa_87::verify(&pk.0, msg, &[], &sig)
            }
        };

        result.map_err(|e| {
            error!("Signature verification failed: {e:?}");
            signature::Error::new()
        })
    }
}

impl Signer<Vec<u8>> for PrivKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        let randomness = [0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];

        let result = match self {
            PrivKey::MlDsa44(sk) => {
                ml_dsa_44::sign(&sk.0, msg, &[], randomness)
                    .map(|sig| sig.as_ref().to_vec())
            }
            PrivKey::MlDsa65(sk) => {
                ml_dsa_65::sign(&sk.0, msg, &[], randomness)
                    .map(|sig| sig.as_ref().to_vec())
            }
            PrivKey::MlDsa87(sk) => {
                ml_dsa_87::sign(&sk.0, msg, &[], randomness)
                    .map(|sig| sig.as_ref().to_vec())
            }
        };

        result.map_err(|e| {
            error!("Signing operation failed: {e:?}");
            signature::Error::new()
        })
    }
}

/// Generates an ML-DSA key pair based on the provided parameter set.
///
/// # Arguments
///
/// * `param_set` - A `CK_ULONG` identifier indicating which ML-DSA parameter
///                 set to use.
///
/// # Returns
///
/// * `Ok((PrivKey, PubKey))` on success, where the keys match the requested
///                           parameter set.
/// * `Err(CK_RV)` if the parameter set is unsupported or key generation fails.
///
/// # Errors
///
/// Returns `CKR_ATTRIBUTE_VALUE_INVALID` if the `param_set` value does not
/// match any known ML-DSA parameter set.
pub fn generate_key_pair(param_set: CK_ULONG) -> KResult<(PrivKey, PubKey)> {
    let rng = [0u8; libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE];

    let ret = match param_set {
        CKP_ML_DSA_44 => {
            let pair = ml_dsa_44::generate_key_pair(rng);
            (
                PrivKey::MlDsa44(PrivKeyMlDsa44(Box::new(pair.signing_key))),
                PubKey::MlDsa44(PubKeyMlDsa44(Box::new(pair.verification_key))),
            )
        }
        CKP_ML_DSA_65 => {
            let pair = ml_dsa_65::generate_key_pair(rng);
            (
                PrivKey::MlDsa65(PrivKeyMlDsa65(Box::new(pair.signing_key))),
                PubKey::MlDsa65(PubKeyMlDsa65(Box::new(pair.verification_key))),
            )
        }
        CKP_ML_DSA_87 => {
            let pair = ml_dsa_87::generate_key_pair(rng);
            (
                PrivKey::MlDsa87(PrivKeyMlDsa87(Box::new(pair.signing_key))),
                PubKey::MlDsa87(PubKeyMlDsa87(Box::new(pair.verification_key))),
            )
        }
        _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
    };

    Ok(ret)
}

impl std::convert::TryFrom<&[u8]> for PubKeyMlDsa44 {
    type Error = KError;

    fn try_from(pk_bytes: &[u8]) -> KResult<Self> {
        let encoded_key: &[u8; ML_DSA_44_PK_SIZE] = match pk_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        let pk =
            PubKeyMlDsa44(Box::new(MLDSA44VerificationKey::new(*encoded_key)));

        Ok(pk)
    }
}

impl std::convert::TryFrom<&[u8]> for PubKeyMlDsa65 {
    type Error = KError;

    fn try_from(pk_bytes: &[u8]) -> KResult<Self> {
        let encoded_key: &[u8; ML_DSA_65_PK_SIZE] = match pk_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        let pk =
            PubKeyMlDsa65(Box::new(MLDSA65VerificationKey::new(*encoded_key)));

        Ok(pk)
    }
}

impl std::convert::TryFrom<&[u8]> for PubKeyMlDsa87 {
    type Error = KError;

    fn try_from(pk_bytes: &[u8]) -> KResult<Self> {
        let encoded_key: &[u8; ML_DSA_87_PK_SIZE] = match pk_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        let pk =
            PubKeyMlDsa87(Box::new(MLDSA87VerificationKey::new(*encoded_key)));

        Ok(pk)
    }
}

impl std::convert::TryFrom<&[u8]> for PrivKeyMlDsa44 {
    type Error = KError;

    fn try_from(sk_bytes: &[u8]) -> KResult<Self> {
        let encoded_key: &[u8; ML_DSA_44_SK_SIZE] = match sk_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        let sk = PrivKeyMlDsa44(Box::new(MLDSA44SigningKey::new(*encoded_key)));

        Ok(sk)
    }
}

impl std::convert::TryFrom<&[u8]> for PrivKeyMlDsa65 {
    type Error = KError;

    fn try_from(sk_bytes: &[u8]) -> KResult<Self> {
        let encoded_key: &[u8; ML_DSA_65_SK_SIZE] = match sk_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        let sk = PrivKeyMlDsa65(Box::new(MLDSA65SigningKey::new(*encoded_key)));

        Ok(sk)
    }
}

impl std::convert::TryFrom<&[u8]> for PrivKeyMlDsa87 {
    type Error = KError;

    fn try_from(sk_bytes: &[u8]) -> KResult<Self> {
        let encoded_key: &[u8; ML_DSA_87_SK_SIZE] = match sk_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        let sk = PrivKeyMlDsa87(Box::new(MLDSA87SigningKey::new(*encoded_key)));

        Ok(sk)
    }
}

impl std::convert::TryFrom<&Object> for PubKey {
    type Error = KError;

    fn try_from(key: &Object) -> KResult<Self> {
        let pk_bytes = match key.get_attr_as_bytes(CKA_VALUE) {
            Ok(val) => val,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };

        let param_set = match key.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => p,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };

        let res = match param_set {
            CKP_ML_DSA_44 => {
                let pk = PubKeyMlDsa44::try_from(pk_bytes.as_slice())?;
                PubKey::MlDsa44(pk)
            }
            CKP_ML_DSA_65 => {
                let pk = PubKeyMlDsa65::try_from(pk_bytes.as_slice())?;
                PubKey::MlDsa65(pk)
            }
            CKP_ML_DSA_87 => {
                let pk = PubKeyMlDsa87::try_from(pk_bytes.as_slice())?;
                PubKey::MlDsa87(pk)
            }
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        };

        Ok(res)
    }
}

impl std::convert::TryFrom<&Object> for PrivKey {
    type Error = KError;

    fn try_from(key: &Object) -> KResult<Self> {
        let sk_bytes = match key.get_attr_as_bytes(CKA_VALUE) {
            Ok(val) => val,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };

        let param_set = match key.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => p,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };

        let res = match param_set {
            CKP_ML_DSA_44 => {
                let sk = PrivKeyMlDsa44::try_from(sk_bytes.as_slice())?;
                PrivKey::MlDsa44(sk)
            }
            CKP_ML_DSA_65 => {
                let sk = PrivKeyMlDsa65::try_from(sk_bytes.as_slice())?;
                PrivKey::MlDsa65(sk)
            }
            CKP_ML_DSA_87 => {
                let sk = PrivKeyMlDsa87::try_from(sk_bytes.as_slice())?;
                PrivKey::MlDsa87(sk)
            }
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        };

        Ok(res)
    }
}
