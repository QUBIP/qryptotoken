use crate::adapters::error::AResult;

pub trait MLDsaSignVariant {
    type PrivKey;
    type Signature;

    fn decode_privkey(bytes: &[u8]) -> AResult<Self::PrivKey>;

    fn try_sign_with_ctx(
        privkey: &Self::PrivKey,
        msg: &[u8],
        ctx: &[u8],
        det: bool,
    ) -> Result<Self::Signature, signature::Error>;

    fn encode_signature(sig: &Self::Signature) -> Vec<u8>;

    fn generate_key_pair(
        seed: Option<[u8; 32]>,
    ) -> AResult<(Self::PrivKey, ())>;
}

pub trait MLDsaVerifyVariant {
    type PubKey;
    type Signature;

    fn decode_pubkey(bytes: &[u8]) -> AResult<Self::PubKey>;

    fn decode_signature(bytes: &[u8]) -> AResult<Self::Signature>;

    fn verify(
        pubkey: &Self::PubKey,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), signature::Error>;

    fn verify_with_ctx(
        pubkey: &Self::PubKey,
        msg: &[u8],
        sig: &Self::Signature,
        ctx: &[u8],
    ) -> Result<(), signature::Error>;
}
