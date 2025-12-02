use crate::adapters::error::{AResult, AdapterError};
use rand_core::{OsRng, TryRngCore};
use signature::{Signer, Verifier};
use slh_dsa::{
    signature::Keypair, Shake256f, Signature as SlhDsaSignature, SigningKey,
    VerifyingKey,
};

#[derive(Clone)]
pub struct PubKey(Box<VerifyingKey<Shake256f>>);

#[derive(Clone)]
pub struct PrivKey(Box<SigningKey<Shake256f>>);

pub struct Signature(Box<SlhDsaSignature<Shake256f>>);

pub mod sizes {
    #![allow(dead_code)]
    use super::*;

    pub(crate) const SLH_DSA_SHAKE_256F_PK_SIZE: usize = PubKey::output_len();
    pub(crate) const SLH_DSA_SHAKE_256F_SK_SIZE: usize = PrivKey::output_len();
    pub(crate) const SLH_DSA_SHAKE_256F_SIG_SIZE: usize =
        Signature::output_len();
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubKey")
            .field("Public value", &self.0.to_bytes())
            .finish()
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivKey")
            .field("Private value", &self.0.to_bytes())
            .finish()
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("Signature value", &self.0.to_bytes())
            .finish()
    }
}

impl Signature {
    pub fn encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> AResult<Self> {
        if bytes.len() != Self::output_len() {
            return Err(AdapterError::InvalidSignatureLen {
                expected: Self::output_len(),
                actual: bytes.len(),
            });
        }

        let sig = SlhDsaSignature::try_from(bytes)
            .map_err(|e| AdapterError::InvalidSignature(e.to_string()))?;

        Ok(Self(Box::new(sig)))
    }

    const fn output_len() -> usize {
        return 49856;
    }
}

impl PubKey {
    pub fn encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> AResult<Self> {
        if bytes.len() != Self::output_len() {
            return Err(AdapterError::InvalidKeyLen {
                expected: Self::output_len(),
                actual: bytes.len(),
            });
        }
        let pk = VerifyingKey::try_from(bytes)
            .map_err(|e| AdapterError::InvalidPublicKey(e.to_string()))?;

        Ok(Self(Box::new(pk)))
    }

    const fn output_len() -> usize {
        return 64;
    }
}

impl Verifier<Signature> for PubKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &Signature,
    ) -> Result<(), signature::Error> {
        VerifyingKey::<Shake256f>::try_verify_with_context(
            &self.0,
            msg,
            &[],
            &signature.0,
        )
        .map_err(|e| {
            signature::Error::from_source(AdapterError::VerificationError(
                format!(
                    "SLH-DSA-SHAKE256f signature verification failed: {e:?}"
                ),
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
        if ctx.len() > 255 {
            return Err(signature::Error::from_source(
                AdapterError::ContextTooLong {
                    max: 255,
                    actual: ctx.len(),
                },
            ));
        }

        VerifyingKey::<Shake256f>::try_verify_with_context(
            &self.0,
            msg,
            ctx,
            &signature.0,
        )
        .map_err(|e| {
            signature::Error::from_source(AdapterError::VerificationError(
                format!(
                    "SLH-DSA-SHAKE256f signature verification failed: {e:?}"
                ),
            ))
        })?;

        Ok(())
    }
}

impl PrivKey {
    pub fn encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> AResult<Self> {
        if bytes.len() != Self::output_len() {
            return Err(AdapterError::InvalidKeyLen {
                expected: Self::output_len(),
                actual: bytes.len(),
            });
        }

        let sk = SigningKey::try_from(bytes)
            .map_err(|e| AdapterError::InvalidPrivateKey(e.to_string()))?;

        Ok(Self(Box::new(sk)))
    }

    const fn output_len() -> usize {
        return 128;
    }
}

impl Signer<Signature> for PrivKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        let mut rnd = [0u8; 32];

        OsRng
            .try_fill_bytes(&mut rnd)
            .map_err(|e| AdapterError::RandomnessError(e))?;

        let sig = SigningKey::<Shake256f>::try_sign_with_context(
            &self.0,
            msg,
            &[],
            Some(&rnd),
        )
        .map_err(|e| {
            signature::Error::from_source(AdapterError::SigningError(format!(
                "SLH-DSA-SHAKE256f signing failed: {e:?}"
            )))
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
            return Err(signature::Error::from_source(
                AdapterError::ContextTooLong {
                    max: 255,
                    actual: ctx.len(),
                },
            ));
        }

        let rnd_opt: Option<[u8; 32]> = if det {
            None
        } else {
            let mut rnd = [0u8; 32];
            OsRng.try_fill_bytes(&mut rnd).map_err(|e| {
                signature::Error::from_source(AdapterError::RandomnessError(e))
            })?;
            Some(rnd)
        };
        let sig = SigningKey::<Shake256f>::try_sign_with_context(
            &self.0,
            msg,
            ctx,
            rnd_opt.as_ref().map(|r| r.as_slice()),
        )
        .map_err(|e| {
            signature::Error::from_source(AdapterError::SigningError(format!(
                "SLH-DSA-SHAKE256f signing failed: {e:?}"
            )))
        })?;

        Ok(Signature(Box::new(sig)))
    }
}

/// Generates an SLH-DSA-SHAKE256f key pair.
///
/// # Returns
///
/// * `Ok((PrivKey, PubKey))` on success, with a tuple containing the generated
///                           key pair.
/// * `Err(AdapterError)` if key pair or randomness generation fails.
pub fn generate_key_pair() -> AResult<(PrivKey, PubKey)> {
    let mut rng = rand_slhdsa::rng();

    let privkey = SigningKey::<Shake256f>::new(&mut rng);

    let sk = PrivKey(Box::new(privkey.clone()));
    let pk = PubKey(Box::new(privkey.verifying_key()));

    Ok((sk, pk))
}
