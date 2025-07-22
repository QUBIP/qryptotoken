pub trait MLDsaSignVariant {
    type PrivKey;
    type Signature;

    fn decode_privkey(
        bytes: &[u8],
    ) -> Result<Self::PrivKey, Box<dyn std::error::Error>>;

    fn try_sign_with_ctx(
        privkey: &Self::PrivKey,
        msg: &[u8],
        ctx: &[u8],
        det: bool,
    ) -> Result<Self::Signature, Box<dyn std::error::Error>>;

    fn encode_signature(sig: &Self::Signature) -> Vec<u8>;

    fn generate_key_pair(
        seed: Option<[u8; 32]>,
    ) -> Result<(Self::PrivKey, ()), Box<dyn std::error::Error>>;
}

pub trait MLDsaVerifyVariant {
    type PubKey;
    type Signature;

    fn decode_pubkey(
        bytes: &[u8],
    ) -> Result<Self::PubKey, Box<dyn std::error::Error>>;

    fn decode_signature(
        bytes: &[u8],
    ) -> Result<Self::Signature, Box<dyn std::error::Error>>;

    fn verify(pubkey: &Self::PubKey, msg: &[u8], sig: &Self::Signature)
        -> bool;

    fn verify_with_ctx(
        pubkey: &Self::PubKey,
        msg: &[u8],
        sig: &Self::Signature,
        ctx: &[u8],
    ) -> bool;
}
