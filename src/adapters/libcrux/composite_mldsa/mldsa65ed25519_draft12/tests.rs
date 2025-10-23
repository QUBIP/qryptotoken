use super::*;
use base64::{engine::general_purpose, Engine};

/*
 * The following test keys and signature are taken as an example from
 * https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/12/
 */
const PK: &str = "rvG6fbi3GP3DBRHsmQRl4YZuMg0uDjyO\
    2Dq8ZTgCgefQbit+7iYSXcSTxQHP4AE6DSOfjXfx8SrZFzFiiuwC6cCMX5UBOKzba+pz\
    oUZW9dQX6AkGnhotB55OCzwZAaa4CifaigVCPK/mlY31Smcc+HY0alwRvL/svVpaaK6d\
    8ZWOWrSNKfBUysGPazZ/XBggKzQDJjtOUwweW4GJqLiFvJfn4WKa9kspKS7s8eqHWwzo\
    rrdJta+SpCc5GtHj3LgQ+Ocee79yXI0NJuBuPL/PTuWguyV7Pz6JJOKFl3/oRgcQBVq9\
    okCbZGudvfTS2B+3QmdiR2CXJ9feiqXJTs4Dgml3TW8xIeYhN2rVzKZwhp+aE0p7x150\
    Lsm4KVGNSHON5LFtRTlvwDhbfAgkI/J4Mu8bMhVlXfW6uHijo0CZXU8eWEyVt+p1kEi2\
    4RwG4Zg7bPY3a0sMbtfT3faC6TLRRZgYQizyGtb8plEUV0y3bCtrZeTxnAdOmFVDisfc\
    2J6G8MSi2QOUJHMBq3o3fETmpf486KZTUVSGO2rgMtWhJoKRJhGImcaH4W/3HEJx34vg\
    frvWU+6AzWAqAak2xMqV9lwMhi3C9oOUfcKYtjjS57H34ID4+J4CQbv0ppukBhKrabBT\
    H7U7BLIj4Y5SNxX9V19goLBgnJrSqsiT+lJya6qDlNZ81I4Vh0coehEeM44LqIYTQRAi\
    9Vu1Izc7DVELDGEMalNf/iLA+1kF2j0T6GrNUEvD+vZH3SX0tJz3eM/qBBqZFYsbOf8z\
    iIOuyQ5EzZ1S6RwsBLtQriroC2rj3Hh9MSPWcKYZOaEIqC8oJ9qBIbWjXgN2dIKI6yWJ\
    YZlKitLRtsRUfLUJDUuaktUbdvnfautUNTj7yPpiAE5y8c1XFqPQEqukisWD0H9MWKLV\
    MNYW+FVzdc/VL9AkH3SWPln7hX0hVtTU5atD1KM8ZAMiGb8uDSRD9qCGyL1viQD2Czvs\
    lB/iEqpbD9aAWGh7LbuS1A7HjeQPyw9GLQH/AHqxfKgr2IpwRC3hAvH8bk/dkRyWvN7l\
    JkWs7qs4BGY71UtPG2xcE/N3N9ur254N4P60bwp1uV1/H0o0fbjHwMqTH5uGY1DuYVnK\
    mfdTuBi8vjv3NCbVpF1E7yym6TuiSl6MMbgHnyWyvUfpm8ROkP1N+yRiUxDEr1l0NvPB\
    Yn5lUyUtjWVBYOLwE9pLZbL3M41VNN+6ks+GjpVUMUlVWSb8QMYb1psCxWrV9CzJJZYX\
    7qPfe5FbnrYn84AfLWjcrfAvtCL1y1C66xJ5MoOJqfZr+MwUsm9HyYr6h00yRgqXSABY\
    VNXjFouXrlW9cvq7Qb4XHndXeUQNpPHAfTq3CzOKutc0+CIjvij7zM1+zvnrLhZCmxkH\
    OXMXgbzmrQP3bhdDSQfRWNp1uzYUox2Mu6uUpSCAdckCb/5qGBeou5K2iV6YHDlGU7e1\
    dBDLN3X5yPEVXJnHXGIrLZl7Dpm8pnjkKEQ063XmNyWXtvYfVdLXgLvsHqHltVWyNFtW\
    Zgrgm5WmMofhWaW6BXcgKpePp8CxfWpBpFFMctmfonpE4nN11xR8NkDk4q2KY2BOK0em\
    QgPxmfU124U5QcjgA5kQFISr2PUn1292xNBjayY9m0wnNgQKdzToOu6CDNSDKIDUINIv\
    kwBq18+2iHFg1PQkYJpDw4lV88jx35g9LyKGbJ5KDlIY1yuHL5bg2C4VQyDwih8En+5+\
    3s0Zafhb7UnyLNdgpCEmk1vjrvsiKtTkYpJEcnP4wkppbURZJGz8St+zt5MfQkc9muQB\
    iVS0gFxGNGAr9EnvpAK6wxICGh5j038vqxiIGqgMwzL5RZGD1aS7m01V0KlHqvVcjYi3\
    Fxyk8rjXTn+xy2BgIOWEkr0asApDMsfj92DaTPw70CrPiYwalU0s0iSUamptEHzUMw7F\
    rGiKkYCdHZO6j9w7aA4J5IwCLgoEnl2Mz/9gJvsXW1J0GjRKIwtcrK0hN/crLXsir2ZJ\
    opv4piNr5qzhKDi1KuOh7qAZf7woJyY+QznJOXccW8CmBv4rPqXjipoAmqpgokWdX7SF\
    whXAqbsPiZ6A/mY+BukdlGUF0ddghH7SuyNt/5uRhU+3fyY/5xuond7l+8v2JZZKMfFz\
    Coe1/hhrI+Ws4N2uRGk44cdCSqECxTav+tS+x4rS8RpBT0qJ0lq7cpWvLsIXGfIojLD0\
    LgeuyHUhNt7b2qXLu+Qzuu+jrZnPE1uBVZmRNIjLslPyEsdVUIdV6p5MgLsjDVKs65SQ\
    3T7BVWyB+Oh1Kp+w7sBoEsraczlzGvk5ADGU8aRfTbOeCAeKnBNkZDBdmJ+l+5PWXaYN\
    U99Rv0Rj75tCCA5QbDaPXo+XTAH0H+kKjNN3vHI6IIrZrgft2saq7K0j23ngac+mp03I\
    1NO9ntBx8JrOIM6jjH1lS3xyXS3Ch7d/bM+3UT26E8ECywRoOtnKaavq3LdUl0xm8VKe\
    Zt5pGQHYbk5pNIyqWKTx3KhPVdfeJBS7vYZXLuUgcUC373JVXdrY+wDmaLtMCZ/Ug4ym\
    p7q6mPkvYI2xjfSAxI5oTnD6CyD1H0MTpI0D+jRumZYJwf7qwzHI/F6A0ZLhvkI45s5C\
    Y4m4ItmV7TQFEJZdBSz5ygVBOqcPSA==";

const _SK: &str = "EkUToDUvNsneugbHg799w72nJfVUserx92MZD7j\
    A+0hZ4KFiurjdBrQPCwinrht9O4uhkdU13atErq6x6IjWMw==";

const SIG: &str = "A7yvehKyIbxyO0\
    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";

const MSG: &str =
    "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=";

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

    let msg = general_purpose::STANDARD.decode(MSG).unwrap();

    pk.verify(&msg, &sig).expect("Verify failed");
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
    let msg = general_purpose::STANDARD.decode(MSG).unwrap();
    let mut tampered_msg = msg.to_vec();
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

    let msg = general_purpose::STANDARD.decode(MSG).unwrap();
    let result = pk.verify(&msg, &sig);
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

    let msg = general_purpose::STANDARD.decode(MSG).unwrap();
    let result = corrupted_pk.verify(&msg, &sig);
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

    let msg = general_purpose::STANDARD.decode(MSG).unwrap();
    let result = pk.verify(&msg, &corrupted_sig);
    assert!(
        result.is_err(),
        "Expected verification to fail with corrupted signature"
    );
}
