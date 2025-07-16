use crate::error::*;
use crate::interface::*;
use crate::mldsa::MlDsaSignAddCtx;
use crate::object::*;
use crate::{err_rv, to_rv};
use libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE;
use signature::{Signer, Verifier};

#[cfg(feature = "libcrux")]
use crate::adapters::libcrux::mldsa::{
    mldsa44::{
        generate_key_pair as generate_mldsa44_key_pair, sizes::*,
        PrivKey as MlDsa44PrivKey, PubKey as MlDsa44PubKey,
        Signature as MlDsa44Signature,
    },
    mldsa65::{
        generate_key_pair as generate_mldsa65_key_pair, sizes::*,
        PrivKey as MlDsa65PrivKey, PubKey as MlDsa65PubKey,
        Signature as MlDsa65Signature,
    },
    mldsa87::{
        generate_key_pair as generate_mldsa87_key_pair, sizes::*,
        PrivKey as MlDsa87PrivKey, PubKey as MlDsa87PubKey,
        Signature as MlDsa87Signature,
    },
};

pub mod sizes {
    #![allow(dead_code)]
    use super::*;

    pub(crate) const MIN_ML_DSA_SIZE_BITS: CK_ULONG =
        (ML_DSA_44_PK_SIZE as CK_ULONG) << 3;
    pub(crate) const MAX_ML_DSA_SIZE_BITS: CK_ULONG =
        (ML_DSA_87_SK_SIZE as CK_ULONG) << 3;
    pub(crate) const KEY_GEN_RND_SIZE: usize = KEY_GENERATION_RANDOMNESS_SIZE;
}
use sizes::*;

pub enum PubKey {
    MlDsa44(MlDsa44PubKey),
    MlDsa65(MlDsa65PubKey),
    MlDsa87(MlDsa87PubKey),
}

pub enum PrivKey {
    MlDsa44(MlDsa44PrivKey),
    MlDsa65(MlDsa65PrivKey),
    MlDsa87(MlDsa87PrivKey),
}

pub enum Signature {
    MlDsa44(MlDsa44Signature),
    MlDsa65(MlDsa65Signature),
    MlDsa87(MlDsa87Signature),
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PubKey::MlDsa44(pk) => f
                .debug_struct("PubKey::MlDsa44")
                .field("value", pk)
                .finish(),
            PubKey::MlDsa65(pk) => f
                .debug_struct("PubKey::MlDsa65")
                .field("value", pk)
                .finish(),
            PubKey::MlDsa87(pk) => f
                .debug_struct("PubKey::MlDsa87")
                .field("value", pk)
                .finish(),
        }
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivKey::MlDsa44(sk) => f
                .debug_struct("PrivKey::MlDsa44")
                .field("value", &sk)
                .finish(),
            PrivKey::MlDsa65(sk) => f
                .debug_struct("PrivKey::MlDsa65")
                .field("value", &sk)
                .finish(),
            PrivKey::MlDsa87(sk) => f
                .debug_struct("PrivKey::MlDsa87")
                .field("value", &sk)
                .finish(),
        }
    }
}

impl Signature {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Signature::MlDsa44(sig) => sig.encode(),
            Signature::MlDsa65(sig) => sig.encode(),
            Signature::MlDsa87(sig) => sig.encode(),
        }
    }

    pub fn decode(bytes: &[u8]) -> KResult<Self> {
        let res = match bytes.len() {
            ML_DSA_44_SIG_SIZE => {
                let sig = MlDsa44Signature::decode(bytes).map_err(|e| {
                    log::error!("Decode error: {e:?}");
                    to_rv!(CKR_SIGNATURE_LEN_RANGE)
                })?;
                Signature::MlDsa44(sig)
            }
            ML_DSA_65_SIG_SIZE => {
                let sig = MlDsa65Signature::decode(bytes).map_err(|e| {
                    log::error!("Decode error: {e:?}");
                    to_rv!(CKR_SIGNATURE_LEN_RANGE)
                })?;
                Signature::MlDsa65(sig)
            }
            ML_DSA_87_SIG_SIZE => {
                let sig = MlDsa87Signature::decode(bytes).map_err(|e| {
                    log::error!("Decode error: {e:?}");
                    to_rv!(CKR_SIGNATURE_LEN_RANGE)
                })?;
                Signature::MlDsa87(sig)
            }
            _ => return err_rv!(CKR_SIGNATURE_LEN_RANGE),
        };

        Ok(res)
    }
}

#[allow(dead_code)]
impl PubKey {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PubKey::MlDsa44(pk) => pk.encode(),
            PubKey::MlDsa65(pk) => pk.encode(),
            PubKey::MlDsa87(pk) => pk.encode(),
        }
    }

    pub fn decode(obj: &Object) -> KResult<Self> {
        let pk_bytes = match obj.get_attr_as_bytes(CKA_VALUE) {
            Ok(val) => val,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };

        let param_set = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => p,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };

        let res = match param_set {
            CKP_ML_DSA_44 => {
                let pk = MlDsa44PubKey::decode(pk_bytes).map_err(|e| {
                    log::error!("Decode error: {e:?}");
                    to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                })?;
                PubKey::MlDsa44(pk)
            }
            CKP_ML_DSA_65 => {
                let pk = MlDsa65PubKey::decode(pk_bytes).map_err(|e| {
                    log::error!("Decode error: {e:?}");
                    to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                })?;

                PubKey::MlDsa65(pk)
            }
            CKP_ML_DSA_87 => {
                let pk = MlDsa87PubKey::decode(pk_bytes).map_err(|e| {
                    log::error!("Decode error: {e:?}");
                    to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                })?;

                PubKey::MlDsa87(pk)
            }
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        };

        Ok(res)
    }

    pub const fn output_len(param_set: CK_ULONG) -> KResult<usize> {
        let len = match param_set {
            CKP_ML_DSA_44 => ML_DSA_44_PK_SIZE,
            CKP_ML_DSA_65 => ML_DSA_65_PK_SIZE,
            CKP_ML_DSA_87 => ML_DSA_87_PK_SIZE,
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        };

        Ok(len)
    }

    pub const fn signature_len(param_set: CK_ULONG) -> KResult<usize> {
        let len = match param_set {
            CKP_ML_DSA_44 => ML_DSA_44_SIG_SIZE,
            CKP_ML_DSA_65 => ML_DSA_65_SIG_SIZE,
            CKP_ML_DSA_87 => ML_DSA_87_SIG_SIZE,
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        };

        Ok(len)
    }
}

impl Verifier<Signature> for PubKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &Signature,
    ) -> Result<(), signature::Error> {
        let res = match (self, signature) {
            (PubKey::MlDsa44(pk), Signature::MlDsa44(sig)) => {
                pk.verify(msg, sig)
            }
            (PubKey::MlDsa65(pk), Signature::MlDsa65(sig)) => {
                pk.verify(msg, sig)
            }
            (PubKey::MlDsa87(pk), Signature::MlDsa87(sig)) => {
                pk.verify(msg, sig)
            }
            _ => Err(signature::Error::from_source(
                "Mismatched key and signature types",
            )),
        };

        res.map_err(|e| signature::Error::from_source(e))
    }
}

impl PubKey {
    pub fn verify_with_params(
        &self,
        msg: &[u8],
        signature: &Signature,
        params: &MlDsaSignAddCtx,
    ) -> Result<(), signature::Error> {
        if params.ctx.is_some() {
            let ctx = params.ctx.as_deref().unwrap();
            let res = match (self, signature) {
                (PubKey::MlDsa44(pk), Signature::MlDsa44(sig)) => {
                    pk.verify_with_ctx(msg, sig, ctx)
                }
                (PubKey::MlDsa65(pk), Signature::MlDsa65(sig)) => {
                    pk.verify_with_ctx(msg, sig, ctx)
                }
                (PubKey::MlDsa87(pk), Signature::MlDsa87(sig)) => {
                    pk.verify_with_ctx(msg, sig, ctx)
                }
                _ => Err(signature::Error::from_source(
                    "Mismatched key and signature types",
                )),
            };
            res.map_err(|e| signature::Error::from_source(e))
        } else {
            /* Fallback to default case (no ctx) */
            self.verify(msg, signature)
        }
    }
}

impl PrivKey {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PrivKey::MlDsa44(sk) => sk.encode(),
            PrivKey::MlDsa65(sk) => sk.encode(),
            PrivKey::MlDsa87(sk) => sk.encode(),
        }
    }

    pub fn decode(obj: &Object) -> KResult<Self> {
        let param_set = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => p,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };

        if let Ok(seed) = obj.get_attr_as_bytes(CKA_SEED) {
            let seed: [u8; KEY_GEN_RND_SIZE] = seed
                .as_slice()
                .try_into()
                .map_err(|_| to_rv!(CKR_ATTRIBUTE_VALUE_INVALID))?;
            let (sk, _) = generate_key_pair(param_set, Some(seed))?;
            return Ok(sk);
        }

        let sk_bytes = match obj.get_attr_as_bytes(CKA_VALUE) {
            Ok(val) => val,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };

        let res = match param_set {
            CKP_ML_DSA_44 => {
                let sk = MlDsa44PrivKey::decode(sk_bytes).map_err(|e| {
                    log::error!("Decode error: {e:?}");
                    to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                })?;
                PrivKey::MlDsa44(sk)
            }
            CKP_ML_DSA_65 => {
                let sk = MlDsa65PrivKey::decode(sk_bytes).map_err(|e| {
                    log::error!("Decode error: {e:?}");
                    to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                })?;

                PrivKey::MlDsa65(sk)
            }
            CKP_ML_DSA_87 => {
                let sk = MlDsa87PrivKey::decode(sk_bytes).map_err(|e| {
                    log::error!("Decode error: {e:?}");
                    to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                })?;

                PrivKey::MlDsa87(sk)
            }
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        };

        Ok(res)
    }

    pub const fn output_len(param_set: CK_ULONG) -> KResult<usize> {
        let len = match param_set {
            CKP_ML_DSA_44 => ML_DSA_44_SK_SIZE,
            CKP_ML_DSA_65 => ML_DSA_65_SK_SIZE,
            CKP_ML_DSA_87 => ML_DSA_87_SK_SIZE,
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        };

        Ok(len)
    }

    pub const fn signature_len(param_set: CK_ULONG) -> KResult<usize> {
        let len = match param_set {
            CKP_ML_DSA_44 => ML_DSA_44_SIG_SIZE,
            CKP_ML_DSA_65 => ML_DSA_65_SIG_SIZE,
            CKP_ML_DSA_87 => ML_DSA_87_SIG_SIZE,
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        };

        Ok(len)
    }
}

impl Signer<Signature> for PrivKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        /* By default perform hedged signatures */
        match self {
            PrivKey::MlDsa44(sk) => {
                let sig = sk.try_sign(msg)?;
                Ok(Signature::MlDsa44(sig))
            }
            PrivKey::MlDsa65(sk) => {
                let sig = sk.try_sign(msg)?;
                Ok(Signature::MlDsa65(sig))
            }
            PrivKey::MlDsa87(sk) => {
                let sig = sk.try_sign(msg)?;
                Ok(Signature::MlDsa87(sig))
            }
        }
    }
}

impl PrivKey {
    pub fn try_sign_with_params(
        &self,
        msg: &[u8],
        params: &MlDsaSignAddCtx,
    ) -> Result<Signature, signature::Error> {
        let det = params.hedge == CKH_DETERMINISTIC_REQUIRED;

        if det || params.ctx.is_some() {
            let ctx = params.ctx.as_deref().unwrap_or(&[]);
            match self {
                PrivKey::MlDsa44(sk) => {
                    let sig = sk.try_sign_with_ctx(msg, ctx, det)?;
                    Ok(Signature::MlDsa44(sig))
                }
                PrivKey::MlDsa65(sk) => {
                    let sig = sk.try_sign_with_ctx(msg, ctx, det)?;
                    Ok(Signature::MlDsa65(sig))
                }
                PrivKey::MlDsa87(sk) => {
                    let sig = sk.try_sign_with_ctx(msg, ctx, det)?;
                    Ok(Signature::MlDsa87(sig))
                }
            }
        } else {
            /* Fallback to default case (no ctx and hedged mode) */
            self.try_sign(msg)
        }
    }
}

/// Generates an ML-DSA key pair for the specified parameter set.
///
/// # Parameters
///
/// - `param_set`: The ML-DSA parameter set to use for key generation.
///                Must be one of the supported ones:
///                 - `CKP_ML_DSA_44`
///                 - `CKP_ML_DSA_65`
///                 - `CKP_ML_DSA_87`
///
/// - `rnd`: An optional fixed-size random byte array used as a seed for
///          deterministic key generation. If `None`, a randomness source is
///          used internally to generate the key pair.
///
/// # Returns
///
/// A `KResult(PrivKey, PubKey)` if the key pair is generated successfully.
///
/// # Errors
///
/// Returns:
/// - `CKR_FUNCTION_FAILED` if key generation fails internally for the
///                         selected parameter set.
/// - `CKR_ATTRIBUTE_VALUE_INVALID` if the parameter set is not recognized.
pub fn generate_key_pair(
    param_set: CK_ULONG,
    rnd: Option<[u8; KEY_GEN_RND_SIZE]>,
) -> KResult<(PrivKey, PubKey)> {
    match param_set {
        CKP_ML_DSA_44 => {
            let (sk, pk) = generate_mldsa44_key_pair(rnd).map_err(|e| {
                log::error!("ML-DSA-44 key pair generation error: {e:?}");
                to_rv!(CKR_FUNCTION_FAILED)
            })?;
            Ok((PrivKey::MlDsa44(sk), PubKey::MlDsa44(pk)))
        }
        CKP_ML_DSA_65 => {
            let (sk, pk) = generate_mldsa65_key_pair(rnd).map_err(|e| {
                log::error!("ML-DSA-65 key pair generation error: {e:?}");
                to_rv!(CKR_FUNCTION_FAILED)
            })?;
            Ok((PrivKey::MlDsa65(sk), PubKey::MlDsa65(pk)))
        }
        CKP_ML_DSA_87 => {
            let (sk, pk) = generate_mldsa87_key_pair(rnd).map_err(|e| {
                log::error!("ML-DSA-87 key pair generation error: {e:?}");
                to_rv!(CKR_FUNCTION_FAILED)
            })?;
            Ok((PrivKey::MlDsa87(sk), PubKey::MlDsa87(pk)))
        }
        _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
    }
}
