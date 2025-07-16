use libcrux_ml_dsa::{
    ml_dsa_44::{
        self, MLDSA44Signature, MLDSA44SigningKey, MLDSA44VerificationKey,
    },
    KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE,
};
use rand_core::{OsRng, TryRngCore};
use signature::{Signer, Verifier};
use std::error::Error;

#[derive(Clone)]
pub struct PubKey(Box<MLDSA44VerificationKey>);

#[derive(Clone)]
pub struct PrivKey(Box<MLDSA44SigningKey>);

pub struct Signature(Box<MLDSA44Signature>);

pub mod sizes {
    #![allow(dead_code)]
    use super::*;

    pub(crate) const ML_DSA_44_PK_SIZE: usize = PubKey::output_len();
    pub(crate) const ML_DSA_44_SK_SIZE: usize = PrivKey::output_len();
    pub(crate) const ML_DSA_44_SIG_SIZE: usize = Signature::output_len();
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubKey")
            .field("Public value", &self.0.as_slice())
            .finish()
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivKey")
            .field("Private value", &self.0.as_slice())
            .finish()
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("Signature value", &self.0.as_slice())
            .finish()
    }
}

impl Signature {
    pub fn encode(&self) -> Vec<u8> {
        self.0.as_slice().to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        if bytes.len() != Self::output_len() {
            return Err(format!(
                "Invalid ML-DSA-44 signature length: expected {}, got {}",
                Self::output_len(),
                bytes.len()
            )
            .into());
        }
        let sig = MLDSA44Signature::new(bytes.try_into()?);

        Ok(Self(Box::new(sig)))
    }

    const fn output_len() -> usize {
        MLDSA44Signature::len()
    }
}

impl PubKey {
    pub fn encode(&self) -> Vec<u8> {
        self.0.as_slice().to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        if bytes.len() != Self::output_len() {
            return Err(format!(
                "Invalid ML-DSA-44 public key length: expected {}, got {}",
                Self::output_len(),
                bytes.len()
            )
            .into());
        }
        let pk = MLDSA44VerificationKey::new(bytes.try_into()?);

        Ok(Self(Box::new(pk)))
    }

    const fn output_len() -> usize {
        MLDSA44VerificationKey::len()
    }
}

impl Verifier<Signature> for PubKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &Signature,
    ) -> Result<(), signature::Error> {
        ml_dsa_44::verify(&self.0, msg, &[], &signature.0).map_err(|e| {
            signature::Error::from_source(format!(
                "ML-DSA-44 signature verification failed: {e:?}"
            ))
        })?;

        Ok(())
    }
}

impl PubKey {
    /// Verifies a message signature with an optional context.
    ///
    /// # Arguments
    ///
    /// * `msg` - The original message that was signed.
    /// * `signature` - The signature to verify.
    /// * `ctx` - The context used during signing.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature verification fails.
    pub fn verify_with_ctx(
        &self,
        msg: &[u8],
        signature: &Signature,
        ctx: &[u8],
    ) -> Result<(), signature::Error> {
        ml_dsa_44::verify(&self.0, msg, ctx, &signature.0).map_err(|e| {
            signature::Error::from_source(format!(
                "ML-DSA-44 signature verification failed: {e:?}"
            ))
        })?;

        Ok(())
    }
}

impl PrivKey {
    pub fn encode(&self) -> Vec<u8> {
        self.0.as_slice().to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        if bytes.len() != Self::output_len() {
            return Err(format!(
                "Invalid ML-DSA-44 private key length: expected {}, got {}",
                Self::output_len(),
                bytes.len()
            )
            .into());
        }
        let sk = MLDSA44SigningKey::new(bytes.try_into()?);

        Ok(Self(Box::new(sk)))
    }

    const fn output_len() -> usize {
        MLDSA44SigningKey::len()
    }
}

impl Signer<Signature> for PrivKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        let mut rnd = [0u8; SIGNING_RANDOMNESS_SIZE];

        OsRng.try_fill_bytes(&mut rnd).map_err(|e| {
            signature::Error::from_source(format!(
                "Error while genrating randomness: {e:?}"
            ))
        })?;

        let sig = ml_dsa_44::sign(&self.0, msg, &[], rnd).map_err(|e| {
            signature::Error::from_source(format!(
                "ML-DSA-44 signing failed: {e:?}"
            ))
        })?;

        Ok(Signature(Box::new(sig)))
    }
}

impl PrivKey {
    /// Attempts to sign a message, with optional context and support for
    /// deterministic or randomized signing.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to be signed.
    /// * `ctx` - Optional context (max 255 bytes).
    /// * `det` - If `true`, uses deterministic signing;
    ///           otherwise, uses hedged signing.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The context exceeds 255 bytes.
    /// - Randomness generation fails when hedged mode is requested.
    /// - The underlying signing function fails.
    pub fn try_sign_with_ctx(
        &self,
        msg: &[u8],
        ctx: &[u8],
        det: bool,
    ) -> Result<Signature, signature::Error> {
        if ctx.len() > 255 {
            return Err(signature::Error::from_source(format!(
                "Context length exceeds 255 bytes"
            )));
        }

        let mut rnd = [0u8; SIGNING_RANDOMNESS_SIZE];
        if !det {
            OsRng.try_fill_bytes(&mut rnd).map_err(|e| {
                signature::Error::from_source(format!(
                    "Error while genrating randomness: {e:?}"
                ))
            })?;
        }
        let sig = ml_dsa_44::sign(&self.0, msg, ctx, rnd).map_err(|e| {
            signature::Error::from_source(format!(
                "ML-DSA-44 signing failed: {e:?}"
            ))
        })?;

        Ok(Signature(Box::new(sig)))
    }
}

/// Generates an ML-DSA-44 key pair.
///
/// # Arguments
///
/// * `rnd` - Optional 32-byte array to use as deterministic randomness seed.
///           Pass `None` to generate fresh randomness by default.
///
/// # Returns
///
/// * `Ok((PrivKey, PubKey))` on success, with a tuple containing the generated
///                           key pair.
/// * `Err(Box<dyn Error>)` if key pair or randomness generation fails.
pub fn generate_key_pair(
    rnd: Option<[u8; KEY_GENERATION_RANDOMNESS_SIZE]>,
) -> Result<(PrivKey, PubKey), Box<dyn Error>> {
    let randomness = match rnd {
        Some(v) => v,
        None => {
            let mut rnd = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
            OsRng
                .try_fill_bytes(&mut rnd)
                .map_err(|e| -> Box<dyn Error> {
                    format!("Error while generating randomness: {e:?}").into()
                })?;
            rnd
        }
    };

    let pair = ml_dsa_44::generate_key_pair(randomness);

    let sk = PrivKey(Box::new(pair.signing_key));
    let pk = PubKey(Box::new(pair.verification_key));

    Ok((sk, pk))
}
