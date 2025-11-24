use super::*;
use wycheproof::composite_mldsa_sign;
use wycheproof::composite_mldsa_verify;

/* Setup function that runs before each test (optional) */
fn setup() -> () {
    crate::try_init_logging().expect("Failed initializing logging subsystem");
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
     * 32 (ML-DSA-65 seed) + 32 (Ed25519)
     */
    assert_eq!(PrivKey::output_len(), (32 + 32));

    /*
     * The composite signature must have a length of
     * 3309 (ML-DSA-65 sig) + 64 (Ed25519 sig)
     */
    assert_eq!(Signature::output_len(), (3309 + 64));
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
    let test_set = composite_mldsa_sign::TestSet::load(
        composite_mldsa_sign::TestName::MlDsa65Ed25519,
    )
    .unwrap_or_else(|e| panic!("Failed to load sign test set: {e}"));

    for group in test_set.test_groups {
        for test in &group.tests {
            let input_sig_bytes = test.sig.clone();
            let output_sig = Signature::decode(&input_sig_bytes)
                .expect("Signature decoding failed");

            eprintln!("\n\n{output_sig:?}\n");
            let encoded_sig_bytes = output_sig.encode();

            assert_eq!(input_sig_bytes.to_vec(), encoded_sig_bytes);
        }
    }
}

#[test]
fn test_import_pubkey_verify_signature() {
    setup();

    let test_set = composite_mldsa_verify::TestSet::load(
        composite_mldsa_verify::TestName::MlDsa65Ed25519,
    )
    .unwrap_or_else(|e| panic!("Failed to load verify test set: {e}"));

    for group in test_set.test_groups {
        let input_pk = group.pubkey;
        let pk = PubKey::decode(&input_pk)
            .expect("Failure while decoding Public Key");
        eprintln!("\n\nPublic Key: {pk:?}\n");
        for test in &group.tests {
            let sig = Signature::decode(&test.sig)
                .expect("Signature decoding failed");

            pk.verify(&test.msg, &sig).expect("Verify failed");
        }
    }
}

#[test]
fn test_verify_signature_with_wrong_message() {
    setup();

    let test_set = composite_mldsa_verify::TestSet::load(
        composite_mldsa_verify::TestName::MlDsa65Ed25519,
    )
    .unwrap_or_else(|e| panic!("Failed to load verify test set: {e}"));

    for group in test_set.test_groups {
        let input_pk = group.pubkey;
        let pk = PubKey::decode(&input_pk)
            .expect("Failure while decoding Public Key");
        eprintln!("\n\nPublic Key: {pk:?}\n");
        for test in &group.tests {
            let sig = Signature::decode(&test.sig)
                .expect("Signature decoding failed");

            /* Flip a bit */
            let mut tampered_msg = test.msg.clone().to_vec();
            tampered_msg[0] ^= 0xFF;

            let result = pk.verify(&tampered_msg, &sig);
            assert!(
                result.is_err(),
                "Expected verification to fail with wrong message"
            );
        }
    }
}

#[test]
fn test_verify_signature_with_wrong_pubkey() {
    setup();
    /* Discard the private key */
    let (_sk, pk) = generate_key_pair().expect("Keypair generation failed");

    let test_set = composite_mldsa_verify::TestSet::load(
        composite_mldsa_verify::TestName::MlDsa65Ed25519,
    )
    .unwrap_or_else(|e| panic!("Failed to load verify test set: {e}"));

    for group in test_set.test_groups {
        eprintln!("\n\nPublic Key: {pk:?}\n");
        for test in &group.tests {
            let sig = Signature::decode(&test.sig)
                .expect("Signature decoding failed");

            let result = pk.verify(&test.msg, &sig);
            assert!(
                result.is_err(),
                "Expected verification to fail with wrong Public Key"
            );
        }
    }
}

#[test]
fn test_verify_signature_with_corrupted_pubkey() {
    setup();

    let test_set = composite_mldsa_verify::TestSet::load(
        composite_mldsa_verify::TestName::MlDsa65Ed25519,
    )
    .unwrap_or_else(|e| panic!("Failed to load verify test set: {e}"));

    for group in test_set.test_groups {
        let mut corrupted_input_pk = group.pubkey.to_vec();
        corrupted_input_pk[0] ^= 0xFF;
        let pk = PubKey::decode(&corrupted_input_pk)
            .expect("Failure while decoding Public Key");
        eprintln!("\n\nPublic Key: {pk:?}\n");
        for test in &group.tests {
            let sig = Signature::decode(&test.sig)
                .expect("Signature decoding failed");

            /* Flip a bit */
            let mut tampered_msg = test.msg.clone().to_vec();
            tampered_msg[0] ^= 0xFF;

            let result = pk.verify(&tampered_msg, &sig);
            assert!(
                result.is_err(),
                "Expected verification to fail with corrupted Public Key"
            );
        }
    }
}

#[test]
fn test_verify_signature_with_corrupted_signature() {
    setup();
    let test_set = composite_mldsa_verify::TestSet::load(
        composite_mldsa_verify::TestName::MlDsa65Ed25519,
    )
    .unwrap_or_else(|e| panic!("Failed to load verify test set: {e}"));

    for group in test_set.test_groups {
        let input_pk = group.pubkey;
        let pk = PubKey::decode(&input_pk)
            .expect("Failure while decoding Public Key");
        eprintln!("\n\nPublic Key: {pk:?}\n");
        for test in &group.tests {
            let mut corrupted_sig_bytes = test.sig.to_vec();
            corrupted_sig_bytes[0] ^= 0xFF;
            let corrupted_sig = Signature::decode(&corrupted_sig_bytes)
                .expect("Signature decoding failed");

            let result = pk.verify(&test.msg, &corrupted_sig);
            assert!(
                result.is_err(),
                "Expected verification to fail with corrupted signature"
            );
        }
    }
}

#[test]
fn test_sign_message() {
    let test_set = composite_mldsa_sign::TestSet::load(
        composite_mldsa_sign::TestName::MlDsa65Ed25519,
    )
    .unwrap_or_else(|e| panic!("Failed to load sign test set: {e}"));

    for group in test_set.test_groups {
        let input_sk = group.privkey;
        let sk = PrivKey::decode(&input_sk)
            .expect("Failure while decoding Private Key");
        eprintln!("\n\nPrivate Key: {sk:?}\n");
        for test in &group.tests {
            let output_sig = sk.try_sign(&test.msg).expect("Signing failed");
            assert_eq!(test.sig.to_vec(), output_sig.encode());
        }
    }
}
