use crate::error::*;
use crate::interface::*;
use crate::object::*;
use crate::slhdsa::SlhDsaSignAddCtx;
use crate::{err_rv, to_rv};
use signature::{Signer, Verifier};

#[cfg(feature = "rustcrypto")]
use crate::adapters::rustcrypto::slhdsa::{
    slhdsa_shake128f, slhdsa_shake128s, slhdsa_shake192f, slhdsa_shake192s,
    slhdsa_shake256f, slhdsa_shake256s,
};

pub mod sizes {
    #![allow(dead_code)]
    use super::*;

    pub(crate) const MIN_SLH_DSA_SIZE_BITS: CK_ULONG =
        (slhdsa_shake128s::sizes::PK_SIZE as CK_ULONG) << 3;
    pub(crate) const MAX_SLH_DSA_SIZE_BITS: CK_ULONG =
        (slhdsa_shake256f::sizes::SK_SIZE as CK_ULONG) << 3;
}

pub enum PubKey {
    SlhDsaShake128s(slhdsa_shake128s::PubKey),
    SlhDsaShake128f(slhdsa_shake128f::PubKey),
    SlhDsaShake192s(slhdsa_shake192s::PubKey),
    SlhDsaShake192f(slhdsa_shake192f::PubKey),
    SlhDsaShake256s(slhdsa_shake256s::PubKey),
    SlhDsaShake256f(slhdsa_shake256f::PubKey),
}

pub enum PrivKey {
    SlhDsaShake128s(slhdsa_shake128s::PrivKey),
    SlhDsaShake128f(slhdsa_shake128f::PrivKey),
    SlhDsaShake192s(slhdsa_shake192s::PrivKey),
    SlhDsaShake192f(slhdsa_shake192f::PrivKey),
    SlhDsaShake256s(slhdsa_shake256s::PrivKey),
    SlhDsaShake256f(slhdsa_shake256f::PrivKey),
}

pub enum Signature {
    SlhDsaShake128s(slhdsa_shake128s::Signature),
    SlhDsaShake128f(slhdsa_shake128f::Signature),
    SlhDsaShake192s(slhdsa_shake192s::Signature),
    SlhDsaShake192f(slhdsa_shake192f::Signature),
    SlhDsaShake256s(slhdsa_shake256s::Signature),
    SlhDsaShake256f(slhdsa_shake256f::Signature),
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PubKey::SlhDsaShake128s(pk) => f
                .debug_struct("PubKey::SlhDsaShake128s")
                .field("value", pk)
                .finish(),
            PubKey::SlhDsaShake128f(pk) => f
                .debug_struct("PubKey::SlhDsaShake128f")
                .field("value", pk)
                .finish(),
            PubKey::SlhDsaShake192s(pk) => f
                .debug_struct("PubKey::SlhDsaShake192s")
                .field("value", pk)
                .finish(),
            PubKey::SlhDsaShake192f(pk) => f
                .debug_struct("PubKey::SlhDsaShake192f")
                .field("value", pk)
                .finish(),
            PubKey::SlhDsaShake256s(pk) => f
                .debug_struct("PubKey::SlhDsaShake256s")
                .field("value", pk)
                .finish(),
            PubKey::SlhDsaShake256f(pk) => f
                .debug_struct("PubKey::SlhDsaShake256f")
                .field("value", pk)
                .finish(),
        }
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivKey::SlhDsaShake128s(sk) => f
                .debug_struct("PrivKey::SlhDsaShake128s")
                .field("value", sk)
                .finish(),
            PrivKey::SlhDsaShake128f(sk) => f
                .debug_struct("PrivKey::SlhDsaShake128f")
                .field("value", sk)
                .finish(),
            PrivKey::SlhDsaShake192s(sk) => f
                .debug_struct("PrivKey::SlhDsaShake192s")
                .field("value", sk)
                .finish(),
            PrivKey::SlhDsaShake192f(sk) => f
                .debug_struct("PrivKey::SlhDsaShake192f")
                .field("value", sk)
                .finish(),
            PrivKey::SlhDsaShake256s(sk) => f
                .debug_struct("PrivKey::SlhDsaShake256s")
                .field("value", sk)
                .finish(),
            PrivKey::SlhDsaShake256f(sk) => f
                .debug_struct("PrivKey::SlhDsaShake256f")
                .field("value", sk)
                .finish(),
        }
    }
}

impl Signature {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Signature::SlhDsaShake128s(sig) => sig.encode(),
            Signature::SlhDsaShake128f(sig) => sig.encode(),
            Signature::SlhDsaShake192s(sig) => sig.encode(),
            Signature::SlhDsaShake192f(sig) => sig.encode(),
            Signature::SlhDsaShake256s(sig) => sig.encode(),
            Signature::SlhDsaShake256f(sig) => sig.encode(),
        }
    }

    pub fn decode(bytes: &[u8]) -> KResult<Self> {
        let res =
            match bytes.len() {
                slhdsa_shake128s::sizes::PK_SIZE => {
                    let sig = slhdsa_shake128s::Signature::decode(bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_SIGNATURE_LEN_RANGE)
                        })?;
                    Signature::SlhDsaShake128s(sig)
                }
                slhdsa_shake128f::sizes::SIG_SIZE => {
                    let sig = slhdsa_shake128f::Signature::decode(bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_SIGNATURE_LEN_RANGE)
                        })?;
                    Signature::SlhDsaShake128f(sig)
                }
                slhdsa_shake192s::sizes::SIG_SIZE => {
                    let sig = slhdsa_shake192s::Signature::decode(bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_SIGNATURE_LEN_RANGE)
                        })?;
                    Signature::SlhDsaShake192s(sig)
                }
                slhdsa_shake192f::sizes::SIG_SIZE => {
                    let sig = slhdsa_shake192f::Signature::decode(bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_SIGNATURE_LEN_RANGE)
                        })?;
                    Signature::SlhDsaShake192f(sig)
                }
                slhdsa_shake256s::sizes::SIG_SIZE => {
                    let sig = slhdsa_shake256s::Signature::decode(bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_SIGNATURE_LEN_RANGE)
                        })?;
                    Signature::SlhDsaShake256s(sig)
                }
                slhdsa_shake256f::sizes::SIG_SIZE => {
                    let sig = slhdsa_shake256f::Signature::decode(bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_SIGNATURE_LEN_RANGE)
                        })?;
                    Signature::SlhDsaShake256f(sig)
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
            PubKey::SlhDsaShake128s(pk) => pk.encode(),
            PubKey::SlhDsaShake128f(pk) => pk.encode(),
            PubKey::SlhDsaShake192s(pk) => pk.encode(),
            PubKey::SlhDsaShake192f(pk) => pk.encode(),
            PubKey::SlhDsaShake256s(pk) => pk.encode(),
            PubKey::SlhDsaShake256f(pk) => pk.encode(),
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

        let res =
            match param_set {
                CKP_SLH_DSA_SHAKE_128S => {
                    let pk = slhdsa_shake128s::PubKey::decode(pk_bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                        })?;
                    PubKey::SlhDsaShake128s(pk)
                }
                CKP_SLH_DSA_SHAKE_128F => {
                    let pk = slhdsa_shake128f::PubKey::decode(pk_bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                        })?;
                    PubKey::SlhDsaShake128f(pk)
                }
                CKP_SLH_DSA_SHAKE_192S => {
                    let pk = slhdsa_shake192s::PubKey::decode(pk_bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                        })?;
                    PubKey::SlhDsaShake192s(pk)
                }
                CKP_SLH_DSA_SHAKE_192F => {
                    let pk = slhdsa_shake192f::PubKey::decode(pk_bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                        })?;
                    PubKey::SlhDsaShake192f(pk)
                }
                CKP_SLH_DSA_SHAKE_256S => {
                    let pk = slhdsa_shake256s::PubKey::decode(pk_bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                        })?;
                    PubKey::SlhDsaShake256s(pk)
                }
                CKP_SLH_DSA_SHAKE_256F => {
                    let pk = slhdsa_shake256f::PubKey::decode(pk_bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                        })?;
                    PubKey::SlhDsaShake256f(pk)
                }
                _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
            };

        Ok(res)
    }

    pub const fn output_len(param_set: CK_ULONG) -> KResult<usize> {
        let len = match param_set {
            CKP_SLH_DSA_SHAKE_128S => slhdsa_shake128s::sizes::PK_SIZE,
            CKP_SLH_DSA_SHAKE_128F => slhdsa_shake128f::sizes::PK_SIZE,
            CKP_SLH_DSA_SHAKE_192S => slhdsa_shake192s::sizes::PK_SIZE,
            CKP_SLH_DSA_SHAKE_192F => slhdsa_shake192f::sizes::PK_SIZE,
            CKP_SLH_DSA_SHAKE_256S => slhdsa_shake256s::sizes::PK_SIZE,
            CKP_SLH_DSA_SHAKE_256F => slhdsa_shake256f::sizes::PK_SIZE,
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        };

        Ok(len)
    }

    pub const fn signature_len(param_set: CK_ULONG) -> KResult<usize> {
        let len = match param_set {
            CKP_SLH_DSA_SHAKE_128S => slhdsa_shake128s::sizes::SIG_SIZE,
            CKP_SLH_DSA_SHAKE_128F => slhdsa_shake128f::sizes::SIG_SIZE,
            CKP_SLH_DSA_SHAKE_192S => slhdsa_shake192s::sizes::SIG_SIZE,
            CKP_SLH_DSA_SHAKE_192F => slhdsa_shake192f::sizes::SIG_SIZE,
            CKP_SLH_DSA_SHAKE_256S => slhdsa_shake256s::sizes::SIG_SIZE,
            CKP_SLH_DSA_SHAKE_256F => slhdsa_shake256f::sizes::SIG_SIZE,
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
        match (self, signature) {
            (PubKey::SlhDsaShake128s(pk), Signature::SlhDsaShake128s(sig)) => {
                pk.verify(msg, sig)
            }
            (PubKey::SlhDsaShake128f(pk), Signature::SlhDsaShake128f(sig)) => {
                pk.verify(msg, sig)
            }
            (PubKey::SlhDsaShake192s(pk), Signature::SlhDsaShake192s(sig)) => {
                pk.verify(msg, sig)
            }
            (PubKey::SlhDsaShake192f(pk), Signature::SlhDsaShake192f(sig)) => {
                pk.verify(msg, sig)
            }
            (PubKey::SlhDsaShake256s(pk), Signature::SlhDsaShake256s(sig)) => {
                pk.verify(msg, sig)
            }
            (PubKey::SlhDsaShake256f(pk), Signature::SlhDsaShake256f(sig)) => {
                pk.verify(msg, sig)
            }
            _ => Err(signature::Error::from_source(
                "Mismatched key and signature types",
            )),
        }
    }
}

impl PubKey {
    pub fn verify_with_params(
        &self,
        msg: &[u8],
        signature: &Signature,
        params: &SlhDsaSignAddCtx,
    ) -> Result<(), signature::Error> {
        if let Some(ctx) = params.ctx.as_deref() {
            let res = match (self, signature) {
                (
                    PubKey::SlhDsaShake128s(pk),
                    Signature::SlhDsaShake128s(sig),
                ) => pk.verify_with_ctx(msg, sig, ctx),
                (
                    PubKey::SlhDsaShake128f(pk),
                    Signature::SlhDsaShake128f(sig),
                ) => pk.verify_with_ctx(msg, sig, ctx),
                (
                    PubKey::SlhDsaShake192s(pk),
                    Signature::SlhDsaShake192s(sig),
                ) => pk.verify_with_ctx(msg, sig, ctx),
                (
                    PubKey::SlhDsaShake192f(pk),
                    Signature::SlhDsaShake192f(sig),
                ) => pk.verify_with_ctx(msg, sig, ctx),
                (
                    PubKey::SlhDsaShake256s(pk),
                    Signature::SlhDsaShake256s(sig),
                ) => pk.verify_with_ctx(msg, sig, ctx),
                (
                    PubKey::SlhDsaShake256f(pk),
                    Signature::SlhDsaShake256f(sig),
                ) => pk.verify_with_ctx(msg, sig, ctx),
                _ => {
                    return Err(signature::Error::from_source(
                        "Mismatched key and signature types",
                    ))
                }
            };
            res.map_err(|e| signature::Error::from_source(e))
        } else {
            // Fallback to default verify (no ctx)
            self.verify(msg, signature)
        }
    }
}

impl PrivKey {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PrivKey::SlhDsaShake128s(sk) => sk.encode(),
            PrivKey::SlhDsaShake128f(sk) => sk.encode(),
            PrivKey::SlhDsaShake192s(sk) => sk.encode(),
            PrivKey::SlhDsaShake192f(sk) => sk.encode(),
            PrivKey::SlhDsaShake256s(sk) => sk.encode(),
            PrivKey::SlhDsaShake256f(sk) => sk.encode(),
        }
    }

    pub fn decode(obj: &Object) -> KResult<Self> {
        let param_set = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => p,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };

        let sk_bytes = match obj.get_attr_as_bytes(CKA_VALUE) {
            Ok(val) => val,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };

        let res =
            match param_set {
                CKP_SLH_DSA_SHAKE_128S => {
                    let sk = slhdsa_shake128s::PrivKey::decode(sk_bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                        })?;
                    PrivKey::SlhDsaShake128s(sk)
                }
                CKP_SLH_DSA_SHAKE_128F => {
                    let sk = slhdsa_shake128f::PrivKey::decode(sk_bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                        })?;
                    PrivKey::SlhDsaShake128f(sk)
                }
                CKP_SLH_DSA_SHAKE_192S => {
                    let sk = slhdsa_shake192s::PrivKey::decode(sk_bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                        })?;
                    PrivKey::SlhDsaShake192s(sk)
                }
                CKP_SLH_DSA_SHAKE_192F => {
                    let sk = slhdsa_shake192f::PrivKey::decode(sk_bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                        })?;
                    PrivKey::SlhDsaShake192f(sk)
                }
                CKP_SLH_DSA_SHAKE_256S => {
                    let sk = slhdsa_shake256s::PrivKey::decode(sk_bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                        })?;
                    PrivKey::SlhDsaShake256s(sk)
                }
                CKP_SLH_DSA_SHAKE_256F => {
                    let sk = slhdsa_shake256f::PrivKey::decode(sk_bytes)
                        .map_err(|e| {
                            log::error!("Decode error: {e:?}");
                            to_rv!(CKR_ATTRIBUTE_VALUE_INVALID)
                        })?;
                    PrivKey::SlhDsaShake256f(sk)
                }
                _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
            };

        Ok(res)
    }

    pub const fn output_len(param_set: CK_ULONG) -> KResult<usize> {
        let len = match param_set {
            CKP_SLH_DSA_SHAKE_128S => slhdsa_shake128s::sizes::SK_SIZE,
            CKP_SLH_DSA_SHAKE_128F => slhdsa_shake128f::sizes::SK_SIZE,
            CKP_SLH_DSA_SHAKE_192S => slhdsa_shake192s::sizes::SK_SIZE,
            CKP_SLH_DSA_SHAKE_192F => slhdsa_shake192f::sizes::SK_SIZE,
            CKP_SLH_DSA_SHAKE_256S => slhdsa_shake256s::sizes::SK_SIZE,
            CKP_SLH_DSA_SHAKE_256F => slhdsa_shake256f::sizes::SK_SIZE,
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        };

        Ok(len)
    }

    pub const fn signature_len(param_set: CK_ULONG) -> KResult<usize> {
        let len = match param_set {
            CKP_SLH_DSA_SHAKE_128S => slhdsa_shake128s::sizes::SIG_SIZE,
            CKP_SLH_DSA_SHAKE_128F => slhdsa_shake128f::sizes::SIG_SIZE,
            CKP_SLH_DSA_SHAKE_192S => slhdsa_shake192s::sizes::SIG_SIZE,
            CKP_SLH_DSA_SHAKE_192F => slhdsa_shake192f::sizes::SIG_SIZE,
            CKP_SLH_DSA_SHAKE_256S => slhdsa_shake256s::sizes::SIG_SIZE,
            CKP_SLH_DSA_SHAKE_256F => slhdsa_shake256f::sizes::SIG_SIZE,
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        };

        Ok(len)
    }
}

impl Signer<Signature> for PrivKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        /* By default perform hedged signatures */
        match self {
            PrivKey::SlhDsaShake128s(sk) => {
                let sig = sk.try_sign(msg)?;
                Ok(Signature::SlhDsaShake128s(sig))
            }
            PrivKey::SlhDsaShake128f(sk) => {
                let sig = sk.try_sign(msg)?;
                Ok(Signature::SlhDsaShake128f(sig))
            }
            PrivKey::SlhDsaShake192s(sk) => {
                let sig = sk.try_sign(msg)?;
                Ok(Signature::SlhDsaShake192s(sig))
            }
            PrivKey::SlhDsaShake192f(sk) => {
                let sig = sk.try_sign(msg)?;
                Ok(Signature::SlhDsaShake192f(sig))
            }
            PrivKey::SlhDsaShake256s(sk) => {
                let sig = sk.try_sign(msg)?;
                Ok(Signature::SlhDsaShake256s(sig))
            }
            PrivKey::SlhDsaShake256f(sk) => {
                let sig = sk.try_sign(msg)?;
                Ok(Signature::SlhDsaShake256f(sig))
            }
        }
    }
}

impl PrivKey {
    pub fn try_sign_with_params(
        &self,
        msg: &[u8],
        params: &SlhDsaSignAddCtx,
    ) -> Result<Signature, signature::Error> {
        let det = params.hedge == CKH_DETERMINISTIC_REQUIRED;

        if det || params.ctx.is_some() {
            let ctx = params.ctx.as_deref().unwrap_or(&[]);
            match self {
                PrivKey::SlhDsaShake128s(sk) => {
                    let sig = sk.try_sign_with_ctx(msg, ctx, det)?;
                    Ok(Signature::SlhDsaShake128s(sig))
                }
                PrivKey::SlhDsaShake128f(sk) => {
                    let sig = sk.try_sign_with_ctx(msg, ctx, det)?;
                    Ok(Signature::SlhDsaShake128f(sig))
                }
                PrivKey::SlhDsaShake192s(sk) => {
                    let sig = sk.try_sign_with_ctx(msg, ctx, det)?;
                    Ok(Signature::SlhDsaShake192s(sig))
                }
                PrivKey::SlhDsaShake192f(sk) => {
                    let sig = sk.try_sign_with_ctx(msg, ctx, det)?;
                    Ok(Signature::SlhDsaShake192f(sig))
                }
                PrivKey::SlhDsaShake256s(sk) => {
                    let sig = sk.try_sign_with_ctx(msg, ctx, det)?;
                    Ok(Signature::SlhDsaShake256s(sig))
                }
                PrivKey::SlhDsaShake256f(sk) => {
                    let sig = sk.try_sign_with_ctx(msg, ctx, det)?;
                    Ok(Signature::SlhDsaShake256f(sig))
                }
            }
        } else {
            /* Fallback to default case (no ctx and hedged mode) */
            self.try_sign(msg)
        }
    }
}

/// Generates an SLH-DSA key pair for the specified parameter set.
///
/// # Parameters
///
/// - `param_set`: The SLH-DSA parameter set to use for key generation.
///                Must be one of the supported ones:
///                 - `CKP_SLH_DSA_SHAKE_128S`
///                 - `CKP_SLH_DSA_SHAKE_128F`
///                 - `CKP_SLH_DSA_SHAKE_192S`
///                 - `CKP_SLH_DSA_SHAKE_192F`
///                 - `CKP_SLH_DSA_SHAKE_256S`
///                 - `CKP_SLH_DSA_SHAKE_256F`
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
pub fn generate_key_pair(param_set: CK_ULONG) -> KResult<(PrivKey, PubKey)> {
    match param_set {
        CKP_SLH_DSA_SHAKE_128S => {
            let (sk, pk) =
                slhdsa_shake128s::generate_key_pair().map_err(|e| {
                    log::error!(
                        "SLH-DSA-SHAKE128s key pair generation error: {e:?}"
                    );
                    to_rv!(CKR_FUNCTION_FAILED)
                })?;
            Ok((PrivKey::SlhDsaShake128s(sk), PubKey::SlhDsaShake128s(pk)))
        }
        CKP_SLH_DSA_SHAKE_128F => {
            let (sk, pk) =
                slhdsa_shake128f::generate_key_pair().map_err(|e| {
                    log::error!(
                        "SLH-DSA-SHAKE128f key pair generation error: {e:?}"
                    );
                    to_rv!(CKR_FUNCTION_FAILED)
                })?;
            Ok((PrivKey::SlhDsaShake128f(sk), PubKey::SlhDsaShake128f(pk)))
        }
        CKP_SLH_DSA_SHAKE_192S => {
            let (sk, pk) =
                slhdsa_shake192s::generate_key_pair().map_err(|e| {
                    log::error!(
                        "SLH-DSA-SHAKE192s key pair generation error: {e:?}"
                    );
                    to_rv!(CKR_FUNCTION_FAILED)
                })?;
            Ok((PrivKey::SlhDsaShake192s(sk), PubKey::SlhDsaShake192s(pk)))
        }
        CKP_SLH_DSA_SHAKE_192F => {
            let (sk, pk) =
                slhdsa_shake192f::generate_key_pair().map_err(|e| {
                    log::error!(
                        "SLH-DSA-SHAKE192f key pair generation error: {e:?}"
                    );
                    to_rv!(CKR_FUNCTION_FAILED)
                })?;
            Ok((PrivKey::SlhDsaShake192f(sk), PubKey::SlhDsaShake192f(pk)))
        }
        CKP_SLH_DSA_SHAKE_256S => {
            let (sk, pk) =
                slhdsa_shake256s::generate_key_pair().map_err(|e| {
                    log::error!(
                        "SLH-DSA-SHAKE256s key pair generation error: {e:?}"
                    );
                    to_rv!(CKR_FUNCTION_FAILED)
                })?;
            Ok((PrivKey::SlhDsaShake256s(sk), PubKey::SlhDsaShake256s(pk)))
        }
        CKP_SLH_DSA_SHAKE_256F => {
            let (sk, pk) =
                slhdsa_shake256f::generate_key_pair().map_err(|e| {
                    log::error!(
                        "SLH-DSA-SHAKE256f key pair generation error: {e:?}"
                    );
                    to_rv!(CKR_FUNCTION_FAILED)
                })?;
            Ok((PrivKey::SlhDsaShake256f(sk), PubKey::SlhDsaShake256f(pk)))
        }
        _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
    }
}
