use super::*;
use base64::{engine::general_purpose, Engine};
use env_logger::Builder;
use std::sync::Once;

/*
 * The following test keys and signature are taken as an example from
 * https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/06/
 */
const PK: &str = "sUBfqZd4dRMattD2hhtr9zkKoTYD3EzX\
    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\
    lbcmxZll3dXvh53tzHyphlb2BOJnHg==";

const _SK: &str = "Us5P2y9Za2FgacrCLKhfToSnDQAcxQMrw7MJdLCpvsH/Eo9gC70cPn\
    3OjprC89BXwsjbb1RWN5Yu8oEr8h3ckw==";

const SIG: &str = "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\
    pdeKqLvowB";

const MSG: &[u8] = b"The quick brown fox jumps over the lazy dog.";

static INIT: Once = Once::new();

/* Setup function that runs before each test (optional) */
fn setup() -> () {
    INIT.call_once(|| {
        Builder::from_default_env()
            //.filter_level(log::levelfilter::debug)
            .format_timestamp(None) // optional: disable timestamps
            .format_module_path(true) // optional: disable module path
            .format_target(false) // optional: disable target
            .format_source_path(true)
            .init();
    });
}

#[test]
fn test_backend_sizes() {
    setup();
    /*
     * The serialized public key must have a length of
     * 1952 (ML-DSA-65) + 32 (Ed25519)
     */
    assert_eq!(PubKey::output_len(), (1952 + 32));

    /*
     * The serialized private key must have a length of
     * 4032 (ML-DSA-65) + 32 (Ed25519)
     */
    assert_eq!(PrivKey::output_len(), (4032 + 32));

    /*
     * The composite signature must have a length of
     * 32 (r) + 3309 (ML-DSA-65 sig) + 64 (Ed25519 sig)
     */
    assert_eq!(Signature::output_len(), (32 + 3309 + 64));
}

#[test]
fn test_decode_invalid_private_key_length() {
    setup();

    let invalid_bytes = vec![0u8; 20];
    let result = PrivKey::decode(&invalid_bytes);
    assert!(
        result.is_err(),
        "Expected decoding to fail with invalid private key length"
    );
}

#[test]
fn test_decode_invalid_public_key_length() {
    setup();

    let invalid_bytes = vec![0u8; 20];
    let result = PubKey::decode(&invalid_bytes);
    assert!(
        result.is_err(),
        "Expected decoding to fail with invalid public key length"
    );
}

#[test]
fn test_generate_keypair_encoding_decoding() {
    /*
     * To test the generated keypair we implicitly test also
     * encoding/decoding
     */
    setup();
    let (priv_key, pub_key) =
        generate_key_pair().expect("Keypair generation failed");

    eprintln!("Private key: {priv_key:?}");
    eprintln!("\n\nPublic key: {pub_key:?}");

    let sk_bytes = priv_key.encode();
    let pk_bytes = pub_key.encode();

    eprintln!(
        "\n\nSerialized mldsa65-ed25519 private key: (len: {}) {sk_bytes:?}",
        sk_bytes.len()
    );
    eprintln!(
        "\n\nSerialized mldsa65-ed25519 public key: (len: {}) {pk_bytes:?}\n",
        pk_bytes.len()
    );

    assert_eq!(sk_bytes.len(), PrivKey::output_len());
    assert_eq!(pk_bytes.len(), PubKey::output_len());

    let decoded_priv =
        PrivKey::decode(&sk_bytes).expect("private key decoding failed");
    let decoded_pub =
        PubKey::decode(&pk_bytes).expect("public key decoding failed");

    assert_eq!(decoded_priv.encode(), sk_bytes);
    assert_eq!(decoded_pub.encode(), pk_bytes);
}

#[test]
fn test_sign_verify_signature_encoding_decoding() {
    /*
     * We don't want to import a signature to decode so we need to generate one
     * and by doing so we implicitly test Signer and simultaneously we can
     * test the Verifer.
     */
    setup();
    let (sk, pk) = generate_key_pair().expect("Keypair generation failed");
    let msg = b"message test to be signed";

    let sig = sk.try_sign(msg).expect("Sign failed");
    eprintln!("\n\nSignature: {sig:?}");

    let sig_bytes = sig.encode();
    eprintln!(
        "\n\nSignature bytes: (len: {}) {sig_bytes:?}\n",
        sig_bytes.len()
    );

    assert_eq!(sig_bytes.len(), Signature::output_len());

    let _sig_decoded =
        Signature::decode(&sig_bytes).expect("Signature decoding failed");

    pk.verify(msg, &sig).expect("Verify failed");
}

#[test]
fn test_signature_decode_encode() {
    setup();
    let input_sig_bytes = general_purpose::STANDARD.decode(SIG).unwrap();

    let output_sig =
        Signature::decode(&input_sig_bytes).expect("Signature decoding failed");

    eprintln!("\n\n{output_sig:?}\n");

    let encoded_sig_bytes = output_sig.encode();

    assert_eq!(input_sig_bytes, encoded_sig_bytes);
}

#[test]
fn test_import_pubkey_verify_signature() {
    setup();
    let input_sig_bytes = general_purpose::STANDARD.decode(SIG).unwrap();
    let sig =
        Signature::decode(&input_sig_bytes).expect("Signature decoding failed");

    let input_pk = general_purpose::STANDARD.decode(PK).unwrap();
    let pk =
        PubKey::decode(&input_pk).expect("Failure while decoding Public Key");

    eprintln!("\n\nPublic Key: {pk:?}\n");

    pk.verify(MSG, &sig).expect("Verify failed");
}

#[test]
fn test_verify_signature_with_wrong_message() {
    setup();

    let input_sig_bytes = general_purpose::STANDARD.decode(SIG).unwrap();
    let sig =
        Signature::decode(&input_sig_bytes).expect("Signature decoding failed");

    let input_pk = general_purpose::STANDARD.decode(PK).unwrap();
    let pk =
        PubKey::decode(&input_pk).expect("Failure while decoding Public Key");

    /* Flip a bit */
    let mut tampered_msg = MSG.to_vec();
    tampered_msg[0] ^= 0xFF;

    let result = pk.verify(&tampered_msg, &sig);
    assert!(
        result.is_err(),
        "Expected verification to fail with wrong message"
    );
}

#[test]
fn test_verify_signature_with_wrong_pubkey() {
    setup();
    /* Discard the private key */
    let (_sk, pk) = generate_key_pair().expect("Keypair generation failed");

    let input_sig_bytes = general_purpose::STANDARD.decode(SIG).unwrap();
    let sig =
        Signature::decode(&input_sig_bytes).expect("Signature decoding failed");

    let result = pk.verify(MSG, &sig);
    assert!(
        result.is_err(),
        "Expected verification to fail with wrong Public Key"
    );
}

#[test]
fn test_verify_signature_with_corrupted_pubkey() {
    setup();

    let input_sig_bytes = general_purpose::STANDARD.decode(SIG).unwrap();
    let sig =
        Signature::decode(&input_sig_bytes).expect("Signature decoding failed");

    let mut corrupted_input_pk = general_purpose::STANDARD.decode(PK).unwrap();
    corrupted_input_pk[0] ^= 0xFF;

    let corrupted_pk = PubKey::decode(&corrupted_input_pk)
        .expect("Failure while decoding Public Key");

    let result = corrupted_pk.verify(MSG, &sig);
    assert!(
        result.is_err(),
        "Expected verification to fail with corrupted Public Key"
    );
}

#[test]
fn test_verify_signature_with_corrupted_signature() {
    setup();
    let mut corrupted_sig_bytes =
        general_purpose::STANDARD.decode(SIG).unwrap();
    corrupted_sig_bytes[0] ^= 0xFF;

    let corrupted_sig = Signature::decode(&corrupted_sig_bytes)
        .expect("Should still decode corrupted signature");

    let input_pk = general_purpose::STANDARD.decode(PK).unwrap();
    let pk =
        PubKey::decode(&input_pk).expect("Failure while decoding Public Key");

    let result = pk.verify(MSG, &corrupted_sig);
    assert!(
        result.is_err(),
        "Expected verification to fail with corrupted signature"
    );
}
