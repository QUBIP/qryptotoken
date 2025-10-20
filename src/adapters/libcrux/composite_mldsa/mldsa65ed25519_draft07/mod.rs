use crate::log::*;
use libcrux_ed25519::{
    self, generate_key_pair as generate_ed25519_key_pair,
    SigningKey as Ed25519SigningKey, VerificationKey as Ed25519VerificationKey,
};
use libcrux_ml_dsa::{
    ml_dsa_65::{
        self, generate_key_pair as genererate_mldsa65_keypair,
        MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey,
    },
    SIGNING_RANDOMNESS_SIZE,
};
use rand_core::{OsRng, TryRngCore};
use sha2::{Digest, Sha512};
use signature::{Signer, Verifier};
use std::error::Error;

pub mod sizes {
    #![allow(dead_code)]
    use super::*;

    pub(crate) const MLDSA65_ED25519_PK_SIZE: usize = PubKey::output_len();
    pub(crate) const MLDSA65_ED25519_SK_SIZE: usize = PrivKey::output_len();
    pub(crate) const MLDSA65_ED25519_SIG_SIZE: usize = Signature::output_len();
}

/* libcrux_ed25519 doesn't provide a method to get these sizes */
const ED25519_PK_SIZE: usize = 32;
const ED25519_SK_SIZE: usize = 32;
const ED25519_SIG_SIZE: usize = 64;

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

pub struct PubKey {
    mldsa65_pk: MLDSA65VerificationKey,
    ed25519_pk: Ed25519VerificationKey,
}

pub struct PrivKey {
    mldsa65_sk: MLDSA65SigningKey,
    ed25519_sk: Ed25519SigningKey,
}

#[derive(Debug)]
pub struct Signature {
    r: Vec<u8>,
    mldsa65_sig: Vec<u8>,
    ed25519_sig: Vec<u8>,
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubKey")
            .field("mldsa65_pk", &self.mldsa65_pk.as_slice())
            .field("ed25519_pk", &self.ed25519_pk.as_ref())
            .finish()
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivKey")
            .field("mldsa65_sk", &self.mldsa65_sk.as_slice())
            .field("ed25519_sk", &self.ed25519_sk.as_ref())
            .finish()
    }
}

impl PubKey {
    #[allow(unused)]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.mldsa65_pk.as_ref().to_vec();
        bytes.extend_from_slice(self.ed25519_pk.as_ref().as_ref());
        bytes
    }

    #[allow(unused)]
    pub fn decode(key: &[u8]) -> Result<Self, Box<dyn Error>> {
        if key.len() != Self::output_len() {
            return Err(format!(
                "Invalid key length: expected {}, got {}",
                Self::output_len(),
                key.len()
            )
            .into());
        }

        let (mldsa65_bytes, ed25519_bytes) =
            key.split_at(MLDSA65VerificationKey::len());

        let mldsa65_pk = MLDSA65VerificationKey::new(mldsa65_bytes.try_into()?);
        let ed25519_pk =
            Ed25519VerificationKey::from_bytes(ed25519_bytes.try_into()?);

        Ok(Self {
            mldsa65_pk,
            ed25519_pk,
        })
    }

    pub const fn output_len() -> usize {
        return MLDSA65VerificationKey::len() + ED25519_PK_SIZE;
    }
}

impl PrivKey {
    #[allow(unused)]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.mldsa65_sk.as_ref().to_vec();
        bytes.extend_from_slice(self.ed25519_sk.as_ref().as_ref());
        bytes
    }

    #[allow(unused)]
    pub fn decode(key: &[u8]) -> Result<Self, Box<dyn Error>> {
        if key.len() != Self::output_len() {
            return Err(format!(
                "Invalid key length: expected {}, got {}",
                Self::output_len(),
                key.len()
            )
            .into());
        }

        let (mldsa65_bytes, ed25519_bytes) =
            key.split_at(MLDSA65SigningKey::len());

        let mldsa65_sk = MLDSA65SigningKey::new(mldsa65_bytes.try_into()?);

        let ed25519_sk =
            Ed25519SigningKey::from_bytes(ed25519_bytes.try_into()?);

        Ok(Self {
            mldsa65_sk,
            ed25519_sk,
        })
    }

    pub const fn output_len() -> usize {
        return MLDSA65SigningKey::len() + ED25519_SK_SIZE;
    }
}

impl Signature {
    #[allow(unused)]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.r.clone();
        bytes.extend_from_slice(&self.mldsa65_sig);
        bytes.extend_from_slice(&self.ed25519_sig);
        bytes
    }

    #[allow(unused)]
    pub fn decode(sig: &[u8]) -> Result<Self, Box<dyn Error>> {
        if sig.len() != Self::output_len() {
            return Err(format!(
                "Invalid signature length: expected {}, got {}",
                Self::output_len(),
                sig.len()
            )
            .into());
        }

        let (r, bytes) = sig.split_at(RANDOMIZER_SIZE);
        let (mldsa65_sig, ed25519_sig) =
            bytes.split_at(MLDSA65Signature::len());

        Ok(Signature {
            r: r.to_vec(),
            mldsa65_sig: mldsa65_sig.to_vec(),
            ed25519_sig: ed25519_sig.to_vec(),
        })
    }

    pub const fn output_len() -> usize {
        return RANDOMIZER_SIZE + MLDSA65Signature::len() + ED25519_SIG_SIZE;
    }
}

impl Verifier<Signature> for PubKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &Signature,
    ) -> Result<(), signature::Error> {
        /* Construct the message representative M′ */
        let m_prime = compute_message(
            PREFIX,
            DOMAIN_SEPARATOR_MLDSA65_ED25519_SHA512,
            signature.r.as_slice(),
            msg,
        );

        /*
         * `m_prime` is moved into the first thread (`mldsa_verify_thread`),
         * so we clone it for reuse in the second thread
         * (`ed25519_verify_thread`) to avoid ownership issues.
         */
        let m_prime_copy = m_prime.clone();
        let mldsa65_pk = self.mldsa65_pk.clone();
        let sig_bytes: [u8; MLDSA65Signature::len()] = signature
            .mldsa65_sig
            .as_slice()
            .try_into()
            .map_err(|_| signature::Error::new())?;

        let mldsa_handle = std::thread::Builder::new()
            .name("mldsa_verify_thread".into())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let sig = MLDSA65Signature::new(sig_bytes);

                let result = ml_dsa_65::verify(
                    &mldsa65_pk,
                    &m_prime,
                    DOMAIN_SEPARATOR_MLDSA65_ED25519_SHA512,
                    &sig,
                );

                result
            })
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread spawn failed during verification"
                );
                signature::Error::new()
            })?;

        let ret = mldsa_handle
            .join()
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread panicked during verification"
                );
                signature::Error::new()
            })?
            .map_err(|e| {
                crate::trace!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "ML-DSA-65 Verification failed: {e:?}"
                );
                signature::Error::new()
            });

        if ret.is_err() {
            crate::trace!(
                target: crate::QRYPTOTOKEN_TARGET,
                "Internal ML-DSA-65 verification failure"
            );
            return ret;
        }

        debug!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 👌👌👌 ML-DSA-65 Verification succesful!"
        );

        /* For ed25519 it's not possible to derive clone */
        let bytes: [u8; 32] = *self.ed25519_pk.as_ref();
        let ed25519_pk = Ed25519VerificationKey::from_bytes(bytes);

        let sig_bytes: [u8; ED25519_SIG_SIZE] = signature
            .ed25519_sig
            .as_slice()
            .try_into()
            .map_err(|_| signature::Error::new())?;

        let ed25519_handle = std::thread::Builder::new()
            .name("ed25519_verify_thread".into())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let result = libcrux_ed25519::verify(
                    &m_prime_copy,
                    ed25519_pk.as_ref(),
                    &sig_bytes,
                );

                result
            })
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread spawn failed during Ed25519 verification"
                );
                signature::Error::new()
            })?;

        let ret = ed25519_handle
            .join()
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread panicked during verification"
                );
                signature::Error::new()
            })?
            .map_err(|e| {
                crate::trace!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Ed25519 Verification failed: {e:?}"
                );
                signature::Error::new()
            });

        if ret.is_err() {
            crate::trace!(
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
}

impl Signer<Signature> for PrivKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        /* Generate a 32-byte random value that will act as a randomizer */
        let mut randomizer = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut randomizer)
            .expect("Random generation failed");

        /* Construct the to-be-signed message representative M′ */
        let m_prime = compute_message(
            PREFIX,
            DOMAIN_SEPARATOR_MLDSA65_ED25519_SHA512,
            &randomizer,
            msg,
        );

        let m_prime_copy = m_prime.clone();
        let mldsa65_sk = self.mldsa65_sk.clone();

        let mldsa_handle = std::thread::Builder::new()
            .name("mldsa_try_sign_thread".into())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
                let result = ml_dsa_65::sign(
                    &mldsa65_sk,
                    &m_prime,
                    DOMAIN_SEPARATOR_MLDSA65_ED25519_SHA512,
                    randomness,
                )
                .map(|sig| sig.as_ref().to_vec());

                result
            })
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread spawn failed during signing"
                );
                signature::Error::new()
            })?;

        let mldsa65_sig = mldsa_handle
            .join()
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread panicked during signing"
                );
                signature::Error::new()
            })?
            .map_err(|e| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "ML-DSA-65 signing failed: {e:?}"
                );
                signature::Error::new()
            });

        debug!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 👌👌👌 ML-DSA-65 Signing succesful!"
        );

        /* For ed25519 it's not possible to derive clone */
        let bytes: [u8; 32] = *self.ed25519_sk.as_ref();
        let ed25519_sk = Ed25519SigningKey::from_bytes(bytes);

        let ed25519_handle = std::thread::Builder::new()
            .name("ed25519_try_sign_thread".into())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let result =
                    libcrux_ed25519::sign(&m_prime_copy, ed25519_sk.as_ref());

                result
            })
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread spawn failed during Ed25519 signing"
                );
                signature::Error::new()
            })?;

        let ed25519_sig = ed25519_handle
            .join()
            .map_err(|_| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Thread panicked during signing"
                );
                signature::Error::new()
            })?
            .map_err(|e| {
                error!(
                    target: crate::QRYPTOTOKEN_TARGET,
                    "Ed25519 Signing failed: {e:?}"
                );
                signature::Error::new()
            });

        debug!(
            target: crate::QRYPTOTOKEN_TARGET,
            "🦀 👌👌👌 Ed25519 Signing succesful!"
        );

        let mldsa65_sig = mldsa65_sig?;
        let ed25519_sig = ed25519_sig?.to_vec();

        return Ok(Signature {
            r: randomizer.to_vec(),
            mldsa65_sig: mldsa65_sig,
            ed25519_sig: ed25519_sig,
        });
    }
}

/// Generates a new MLDSA65-Ed22519 key pair.
///
/// # Returns
///
/// `Result(PrivKey, PubKey)` on success, where:
/// - `PrivKey` is the private key type holding both ML-DSA-65 and Ed25519
/// signing keys.
/// - `PubKey` is the combined public key holding both ML-DSA-65 and Ed25519
/// verification keys.
///
/// # Errors
///
/// Returns an `Error` if the Ed25519 key pair generation fails or
/// if the internal RNG instantiation fails.
#[allow(unused)]
pub fn generate_key_pair() -> Result<(PrivKey, PubKey), Box<dyn Error>> {
    let rng = [0u8; libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE];

    let mldsa65_pair = genererate_mldsa65_keypair(rng);

    let mldsa65_sk = mldsa65_pair.signing_key;
    let mldsa65_pk = mldsa65_pair.verification_key;

    let mut rng = crate::rng::RNG::new().expect("RNG instantiation failed");
    let (ed25519_sk, ed25519_pk) = generate_ed25519_key_pair(&mut rng)
        .map_err(|e| {
            Box::<dyn std::error::Error>::from(format!(
                "Ed25519 key generation failed: {:?}",
                e
            ))
        })?;

    let pk = PubKey {
        mldsa65_pk,
        ed25519_pk,
    };

    let sk = PrivKey {
        mldsa65_sk,
        ed25519_sk,
    };

    Ok((sk, pk))
}

/// Helper function for generating the to-be-signed message representative M'.
///
/// M' := Prefix || Domain || len(ctx) || ctx || r || PH(M)
///
/// This function constructs the final message buffer to be signed by both
/// ML-DSA and the traditional signature algorithm.
/// # Returns:
///
/// `<Vec<u8>`: The final message representative M' encoded as raw bytes
fn compute_message(
    prefix: &[u8],
    domain: &[u8],
    randomizer: &[u8],
    message: &[u8],
) -> Vec<u8> {
    let mut to_be_signed = Vec::with_capacity(
        prefix.len()
            + domain.len()
            + CTX_LENGTH_SIZE
            + RANDOMIZER_SIZE
            + Sha512::output_size(),
    );

    to_be_signed.extend_from_slice(prefix);
    to_be_signed.extend_from_slice(domain);
    /* ctx is assumed to be empty */
    to_be_signed.push(0);
    to_be_signed.extend_from_slice(randomizer);
    let digest = Sha512::digest(message);
    to_be_signed.extend_from_slice(&digest);

    to_be_signed
}

#[cfg(test)]
pub mod tests;
