use crate::err_rv;
use crate::error::*;
use crate::interface::*;
use crate::log::*;
use crate::object::*;
use signature::{Keypair, RandomizedSigner, Signer, Verifier};
use slh_dsa::{
    Shake128f, Shake128s, Shake192f, Shake192s, Shake256f, Shake256s,
    Signature, SigningKey, VerifyingKey,
};

#[derive(Clone)]
pub struct PubKeySlhDsaShake128s(Box<VerifyingKey<Shake128s>>);
#[derive(Clone)]
pub struct PubKeySlhDsaShake128f(Box<VerifyingKey<Shake128f>>);
#[derive(Clone)]
pub struct PubKeySlhDsaShake192s(Box<VerifyingKey<Shake192s>>);
#[derive(Clone)]
pub struct PubKeySlhDsaShake192f(Box<VerifyingKey<Shake192f>>);
#[derive(Clone)]
pub struct PubKeySlhDsaShake256s(Box<VerifyingKey<Shake256s>>);
#[derive(Clone)]
pub struct PubKeySlhDsaShake256f(Box<VerifyingKey<Shake256f>>);

#[derive(Clone)]
pub struct PrivKeySlhDsaShake128s(Box<SigningKey<Shake128s>>);
#[derive(Clone)]
pub struct PrivKeySlhDsaShake128f(Box<SigningKey<Shake128f>>);
#[derive(Clone)]
pub struct PrivKeySlhDsaShake192s(Box<SigningKey<Shake192s>>);
#[derive(Clone)]
pub struct PrivKeySlhDsaShake192f(Box<SigningKey<Shake192f>>);
#[derive(Clone)]
pub struct PrivKeySlhDsaShake256s(Box<SigningKey<Shake256s>>);
#[derive(Clone)]
pub struct PrivKeySlhDsaShake256f(Box<SigningKey<Shake256f>>);

pub enum PubKey {
    SlhDsaShake128s(PubKeySlhDsaShake128s),
    SlhDsaShake128f(PubKeySlhDsaShake128f),
    SlhDsaShake192s(PubKeySlhDsaShake192s),
    SlhDsaShake192f(PubKeySlhDsaShake192f),
    SlhDsaShake256s(PubKeySlhDsaShake256s),
    SlhDsaShake256f(PubKeySlhDsaShake256f),
}

pub enum PrivKey {
    SlhDsaShake128s(PrivKeySlhDsaShake128s),
    SlhDsaShake128f(PrivKeySlhDsaShake128f),
    SlhDsaShake192s(PrivKeySlhDsaShake192s),
    SlhDsaShake192f(PrivKeySlhDsaShake192f),
    SlhDsaShake256s(PrivKeySlhDsaShake256s),
    SlhDsaShake256f(PrivKeySlhDsaShake256f),
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
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            PubKey::SlhDsaShake128s(pk) => pk.0.to_vec(),
            PubKey::SlhDsaShake128f(pk) => pk.0.to_vec(),
            PubKey::SlhDsaShake192s(pk) => pk.0.to_vec(),
            PubKey::SlhDsaShake192f(pk) => pk.0.to_vec(),
            PubKey::SlhDsaShake256s(pk) => pk.0.to_vec(),
            PubKey::SlhDsaShake256f(pk) => pk.0.to_vec(),
        }
    }
}

impl PrivKey {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            PrivKey::SlhDsaShake128s(sk) => sk.0.to_vec(),
            PrivKey::SlhDsaShake128f(sk) => sk.0.to_vec(),
            PrivKey::SlhDsaShake192s(sk) => sk.0.to_vec(),
            PrivKey::SlhDsaShake192f(sk) => sk.0.to_vec(),
            PrivKey::SlhDsaShake256s(sk) => sk.0.to_vec(),
            PrivKey::SlhDsaShake256f(sk) => sk.0.to_vec(),
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
            PubKey::SlhDsaShake128s(pk) => {
                let sig =
                    Signature::<Shake128s>::try_from(signature.as_slice())?;
                pk.0.verify(msg, &sig)
            }
            PubKey::SlhDsaShake128f(pk) => {
                let sig =
                    Signature::<Shake128f>::try_from(signature.as_slice())?;
                pk.0.verify(msg, &sig)
            }
            PubKey::SlhDsaShake192s(pk) => {
                let sig =
                    Signature::<Shake192s>::try_from(signature.as_slice())?;
                pk.0.verify(msg, &sig)
            }
            PubKey::SlhDsaShake192f(pk) => {
                let sig =
                    Signature::<Shake192f>::try_from(signature.as_slice())?;
                pk.0.verify(msg, &sig)
            }
            PubKey::SlhDsaShake256s(pk) => {
                let sig =
                    Signature::<Shake256s>::try_from(signature.as_slice())?;
                pk.0.verify(msg, &sig)
            }
            PubKey::SlhDsaShake256f(pk) => {
                let sig =
                    Signature::<Shake256f>::try_from(signature.as_slice())?;
                pk.0.verify(msg, &sig)
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
        let mut rng = rand::thread_rng();

        let sig = match self {
            PrivKey::SlhDsaShake128s(sk) => {
                sk.0.try_sign_with_rng(&mut rng, msg)?.to_vec()
            }
            PrivKey::SlhDsaShake128f(sk) => {
                sk.0.try_sign_with_rng(&mut rng, msg)?.to_vec()
            }
            PrivKey::SlhDsaShake192s(sk) => {
                sk.0.try_sign_with_rng(&mut rng, msg)?.to_vec()
            }
            PrivKey::SlhDsaShake192f(sk) => {
                sk.0.try_sign_with_rng(&mut rng, msg)?.to_vec()
            }
            PrivKey::SlhDsaShake256s(sk) => {
                sk.0.try_sign_with_rng(&mut rng, msg)?.to_vec()
            }
            PrivKey::SlhDsaShake256f(sk) => {
                sk.0.try_sign_with_rng(&mut rng, msg)?.to_vec()
            }
        };

        Ok(sig)
    }
}

pub fn generate_key_pair(param_set: CK_ULONG) -> KResult<(PrivKey, PubKey)> {
    let mut rng = rand::thread_rng();

    let ret = match param_set {
        CKP_SLH_DSA_SHAKE_128S => {
            let sk = SigningKey::<Shake128s>::new(&mut rng);
            let pk = sk.verifying_key();
            (
                PrivKey::SlhDsaShake128s(PrivKeySlhDsaShake128s(Box::new(sk))),
                PubKey::SlhDsaShake128s(PubKeySlhDsaShake128s(Box::new(pk))),
            )
        }
        CKP_SLH_DSA_SHAKE_128F => {
            let sk = SigningKey::<Shake128f>::new(&mut rng);
            let pk = sk.verifying_key();
            (
                PrivKey::SlhDsaShake128f(PrivKeySlhDsaShake128f(Box::new(sk))),
                PubKey::SlhDsaShake128f(PubKeySlhDsaShake128f(Box::new(pk))),
            )
        }
        CKP_SLH_DSA_SHAKE_192S => {
            let sk = SigningKey::<Shake192s>::new(&mut rng);
            let pk = sk.verifying_key();
            (
                PrivKey::SlhDsaShake192s(PrivKeySlhDsaShake192s(Box::new(sk))),
                PubKey::SlhDsaShake192s(PubKeySlhDsaShake192s(Box::new(pk))),
            )
        }
        CKP_SLH_DSA_SHAKE_192F => {
            let sk = SigningKey::<Shake192f>::new(&mut rng);
            let pk = sk.verifying_key();
            (
                PrivKey::SlhDsaShake192f(PrivKeySlhDsaShake192f(Box::new(sk))),
                PubKey::SlhDsaShake192f(PubKeySlhDsaShake192f(Box::new(pk))),
            )
        }
        CKP_SLH_DSA_SHAKE_256S => {
            let sk = SigningKey::<Shake256s>::new(&mut rng);
            let pk = sk.verifying_key();
            (
                PrivKey::SlhDsaShake256s(PrivKeySlhDsaShake256s(Box::new(sk))),
                PubKey::SlhDsaShake256s(PubKeySlhDsaShake256s(Box::new(pk))),
            )
        }
        CKP_SLH_DSA_SHAKE_256F => {
            let sk = SigningKey::<Shake256f>::new(&mut rng);
            let pk = sk.verifying_key();
            (
                PrivKey::SlhDsaShake256f(PrivKeySlhDsaShake256f(Box::new(sk))),
                PubKey::SlhDsaShake256f(PubKeySlhDsaShake256f(Box::new(pk))),
            )
        }
        _ => return err_rv!(CKR_MECHANISM_INVALID),
    };

    Ok(ret)
}

impl TryFrom<&[u8]> for PubKeySlhDsaShake128s {
    type Error = KError;

    fn try_from(pk_bytes: &[u8]) -> KResult<Self> {
        let pk = match VerifyingKey::<Shake128s>::try_from(pk_bytes) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        Ok(PubKeySlhDsaShake128s(Box::new(pk)))
    }
}

impl TryFrom<&[u8]> for PubKeySlhDsaShake128f {
    type Error = KError;

    fn try_from(pk_bytes: &[u8]) -> KResult<Self> {
        let pk = match VerifyingKey::<Shake128f>::try_from(pk_bytes) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        Ok(PubKeySlhDsaShake128f(Box::new(pk)))
    }
}

impl TryFrom<&[u8]> for PubKeySlhDsaShake192s {
    type Error = KError;

    fn try_from(pk_bytes: &[u8]) -> KResult<Self> {
        let pk = match VerifyingKey::<Shake192s>::try_from(pk_bytes) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        Ok(PubKeySlhDsaShake192s(Box::new(pk)))
    }
}

impl TryFrom<&[u8]> for PubKeySlhDsaShake192f {
    type Error = KError;

    fn try_from(pk_bytes: &[u8]) -> KResult<Self> {
        let pk = match VerifyingKey::<Shake192f>::try_from(pk_bytes) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        Ok(PubKeySlhDsaShake192f(Box::new(pk)))
    }
}

impl TryFrom<&[u8]> for PubKeySlhDsaShake256s {
    type Error = KError;

    fn try_from(pk_bytes: &[u8]) -> KResult<Self> {
        let pk = match VerifyingKey::<Shake256s>::try_from(pk_bytes) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        Ok(PubKeySlhDsaShake256s(Box::new(pk)))
    }
}

impl TryFrom<&[u8]> for PubKeySlhDsaShake256f {
    type Error = KError;

    fn try_from(pk_bytes: &[u8]) -> KResult<Self> {
        let pk = match VerifyingKey::<Shake256f>::try_from(pk_bytes) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        Ok(PubKeySlhDsaShake256f(Box::new(pk)))
    }
}

impl TryFrom<&[u8]> for PrivKeySlhDsaShake128s {
    type Error = KError;

    fn try_from(sk_bytes: &[u8]) -> KResult<Self> {
        let sk = match SigningKey::<Shake128s>::try_from(sk_bytes) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        Ok(PrivKeySlhDsaShake128s(Box::new(sk)))
    }
}

impl TryFrom<&[u8]> for PrivKeySlhDsaShake128f {
    type Error = KError;

    fn try_from(sk_bytes: &[u8]) -> KResult<Self> {
        let sk = match SigningKey::<Shake128f>::try_from(sk_bytes) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        Ok(PrivKeySlhDsaShake128f(Box::new(sk)))
    }
}

impl TryFrom<&[u8]> for PrivKeySlhDsaShake192s {
    type Error = KError;

    fn try_from(sk_bytes: &[u8]) -> KResult<Self> {
        let sk = match SigningKey::<Shake192s>::try_from(sk_bytes) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        Ok(PrivKeySlhDsaShake192s(Box::new(sk)))
    }
}

impl TryFrom<&[u8]> for PrivKeySlhDsaShake192f {
    type Error = KError;

    fn try_from(sk_bytes: &[u8]) -> KResult<Self> {
        let sk = match SigningKey::<Shake192f>::try_from(sk_bytes) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        Ok(PrivKeySlhDsaShake192f(Box::new(sk)))
    }
}

impl TryFrom<&[u8]> for PrivKeySlhDsaShake256s {
    type Error = KError;

    fn try_from(sk_bytes: &[u8]) -> KResult<Self> {
        let sk = match SigningKey::<Shake256s>::try_from(sk_bytes) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        Ok(PrivKeySlhDsaShake256s(Box::new(sk)))
    }
}

impl TryFrom<&[u8]> for PrivKeySlhDsaShake256f {
    type Error = KError;

    fn try_from(sk_bytes: &[u8]) -> KResult<Self> {
        let sk = match SigningKey::<Shake256f>::try_from(sk_bytes) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        Ok(PrivKeySlhDsaShake256f(Box::new(sk)))
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
            CKP_SLH_DSA_SHAKE_128S => {
                let pk = PubKeySlhDsaShake128s::try_from(pk_bytes.as_slice())?;
                PubKey::SlhDsaShake128s(pk)
            }
            CKP_SLH_DSA_SHAKE_128F => {
                let pk = PubKeySlhDsaShake128f::try_from(pk_bytes.as_slice())?;
                PubKey::SlhDsaShake128f(pk)
            }
            CKP_SLH_DSA_SHAKE_192S => {
                let pk = PubKeySlhDsaShake192s::try_from(pk_bytes.as_slice())?;
                PubKey::SlhDsaShake192s(pk)
            }
            CKP_SLH_DSA_SHAKE_192F => {
                let pk = PubKeySlhDsaShake192f::try_from(pk_bytes.as_slice())?;
                PubKey::SlhDsaShake192f(pk)
            }
            CKP_SLH_DSA_SHAKE_256S => {
                let pk = PubKeySlhDsaShake256s::try_from(pk_bytes.as_slice())?;
                PubKey::SlhDsaShake256s(pk)
            }
            CKP_SLH_DSA_SHAKE_256F => {
                let pk = PubKeySlhDsaShake256f::try_from(pk_bytes.as_slice())?;
                PubKey::SlhDsaShake256f(pk)
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
            CKP_SLH_DSA_SHAKE_128S => {
                let sk = PrivKeySlhDsaShake128s::try_from(sk_bytes.as_slice())?;
                PrivKey::SlhDsaShake128s(sk)
            }
            CKP_SLH_DSA_SHAKE_128F => {
                let sk = PrivKeySlhDsaShake128f::try_from(sk_bytes.as_slice())?;
                PrivKey::SlhDsaShake128f(sk)
            }
            CKP_SLH_DSA_SHAKE_192S => {
                let sk = PrivKeySlhDsaShake192s::try_from(sk_bytes.as_slice())?;
                PrivKey::SlhDsaShake192s(sk)
            }
            CKP_SLH_DSA_SHAKE_192F => {
                let sk = PrivKeySlhDsaShake192f::try_from(sk_bytes.as_slice())?;
                PrivKey::SlhDsaShake192f(sk)
            }
            CKP_SLH_DSA_SHAKE_256S => {
                let sk = PrivKeySlhDsaShake256s::try_from(sk_bytes.as_slice())?;
                PrivKey::SlhDsaShake256s(sk)
            }
            CKP_SLH_DSA_SHAKE_256F => {
                let sk = PrivKeySlhDsaShake256f::try_from(sk_bytes.as_slice())?;
                PrivKey::SlhDsaShake256f(sk)
            }
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        };

        Ok(res)
    }
}
