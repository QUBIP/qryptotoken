use crate::error::*;
use crate::interface::*;
use crate::log::*;
use crate::object::*;
use crate::{err_rv, to_rv};
use libcrux_ed25519::{
    self, generate_key_pair as generate_ed25519_key_pair, SigningKey,
    VerificationKey,
};
use signature::{Signer, Verifier};

pub struct Ed25519PubKey(Box<VerificationKey>);
impl Clone for Ed25519PubKey {
    /// Performs a clone of the Ed25519 public key by extracting the raw
    /// 32-byte array from the internal `VerificationKey`, reconstructing a
    /// new key from those bytes, and wrapping it in a new `Box`.
    fn clone(&self) -> Self {
        let bytes: [u8; 32] = *self.0.as_ref().as_ref();
        let cloned_key = VerificationKey::from_bytes(bytes);
        Ed25519PubKey(Box::new(cloned_key))
    }
}

pub enum PubKey {
    Ed25519(Ed25519PubKey),
}

pub struct Ed25519PrivKey(Box<SigningKey>);
impl Clone for Ed25519PrivKey {
    /// Performs a clone of the Ed25519 private key by extracting the raw
    /// 32-byte array from the internal `VerificationKey`, reconstructing a
    /// new key from those bytes, and wrapping it in a new `Box`.
    fn clone(&self) -> Self {
        let bytes: [u8; 32] = *self.0.as_ref().as_ref();
        let cloned_key = SigningKey::from_bytes(bytes);
        Ed25519PrivKey(Box::new(cloned_key))
    }
}

pub enum PrivKey {
    Ed25519(Ed25519PrivKey),
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivKey")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubKey")
            .field("value", &"<redacted>")
            .finish()
    }
}

/*
 * The first `as_ref()` dereferences the `Box<VerificationKey>` to `
 * VerificationKey`, and the second `as_ref()` calls the `AsRef<[u8; 32]>`
 * implementation to get the raw bytes. This gives a reference to the
 * internal `[u8; 32]`, which can be copied or used as a slice.
 */
impl PubKey {
    pub fn as_ref(&self) -> &[u8] {
        match self {
            PubKey::Ed25519(pk) => pk.0.as_ref().as_ref(),
        }
    }
}

/*
 * The first `as_ref()` dereferences the `Box<SigningKey>` to `&SigningKey`,
 * and the second `as_ref()` calls the `AsRef<[u8; 32]>` implementation to
 * get the raw bytes. This gives a reference to the internal `[u8; 32]`,
 * which can be copied or used as a slice.
 */
impl PrivKey {
    pub fn as_ref(&self) -> &[u8] {
        match self {
            PrivKey::Ed25519(sk) => sk.0.as_ref().as_ref(),
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
            PubKey::Ed25519(pk) => {
                let sig: [u8; 64] = signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| signature::Error::new())?;

                libcrux_ed25519::verify(msg, pk.0.as_ref().as_ref(), &sig)
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
        let result = match self {
            PrivKey::Ed25519(sk) => {
                libcrux_ed25519::sign(msg, sk.0.as_ref().as_ref())
                    .map(|sig| sig.to_vec())
            }
        };

        result.map_err(|e| {
            error!("Signing operation failed: {e:?}");
            signature::Error::new()
        })
    }
}

/* FIX: this function should have the type of the curve as parameter */
pub fn generate_key_pair() -> KResult<(PrivKey, PubKey)> {
    #[cfg(feature = "pure-rust")]
    let mut rng = crate::rng::RNG::new().expect("RNG instantiation failed");

    let (sk, pk) = generate_ed25519_key_pair(&mut rng).map_err(|e| {
        error!("Ed25519 key generation failed: {e:?}");
        to_rv!(CKR_GENERAL_ERROR)
    })?;

    Ok((
        PrivKey::Ed25519(Ed25519PrivKey(Box::new(sk))),
        PubKey::Ed25519(Ed25519PubKey(Box::new(pk))),
    ))
}

impl std::convert::TryFrom<&[u8]> for Ed25519PubKey {
    type Error = KError;

    fn try_from(pk_bytes: &[u8]) -> KResult<Self> {
        let encoded_key: &[u8; 32] = match pk_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        let vk = VerificationKey::from_bytes(*encoded_key);
        Ok(Ed25519PubKey(Box::new(vk)))
    }
}

impl std::convert::TryFrom<&[u8]> for Ed25519PrivKey {
    type Error = KError;

    fn try_from(sk_bytes: &[u8]) -> KResult<Self> {
        let encoded_key: &[u8; 32] = match sk_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        let sk = SigningKey::from_bytes(*encoded_key);
        Ok(Ed25519PrivKey(Box::new(sk)))
    }
}

impl std::convert::TryFrom<&Object> for PubKey {
    type Error = KError;

    fn try_from(key: &Object) -> KResult<Self> {
        let pk_bytes = match key.get_attr_as_bytes(CKA_VALUE) {
            Ok(val) => val,
            Err(_) => {
                error!("Failed to get CKA_VALUE for public key");
                return err_rv!(CKR_TEMPLATE_INCONSISTENT);
            }
        };

        let pk = Ed25519PubKey::try_from(pk_bytes.as_slice())?;
        Ok(PubKey::Ed25519(pk))
    }
}

impl std::convert::TryFrom<&Object> for PrivKey {
    type Error = KError;

    fn try_from(key: &Object) -> KResult<Self> {
        let sk_bytes = match key.get_attr_as_bytes(CKA_VALUE) {
            Ok(val) => val,
            Err(_) => {
                error!("Failed to get CKA_VALUE for private key");
                return err_rv!(CKR_TEMPLATE_INCONSISTENT);
            }
        };

        let sk = Ed25519PrivKey::try_from(sk_bytes.as_slice())?;
        Ok(PrivKey::Ed25519(sk))
    }
}
