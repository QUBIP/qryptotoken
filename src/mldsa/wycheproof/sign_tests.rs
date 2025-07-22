use super::reader::*;
use super::sign_schema::SignResult;
use crate::mldsa::wycheproof::mldsa_variant::MLDsaSignVariant;

use hex::decode;

pub struct Mldsa44;
pub struct Mldsa65;
pub struct Mldsa87;

macro_rules! impl_mldsa_sign_variant {
    ($variant:ident, $privkey:ty, $sig:ty, $gen_path:path) => {
        impl $crate::mldsa::wycheproof::mldsa_variant::MLDsaSignVariant
            for $variant
        {
            type PrivKey = $privkey;
            type Signature = $sig;

            fn decode_privkey(
                bytes: &[u8],
            ) -> Result<Self::PrivKey, Box<dyn std::error::Error>> {
                <$privkey>::decode(bytes)
            }

            fn try_sign_with_ctx(
                privkey: &Self::PrivKey,
                msg: &[u8],
                ctx: &[u8],
                det: bool,
            ) -> Result<Self::Signature, Box<dyn std::error::Error>> {
                privkey.try_sign_with_ctx(msg, ctx, det).map_err(Into::into)
            }

            fn encode_signature(sig: &Self::Signature) -> Vec<u8> {
                sig.encode()
            }

            fn generate_key_pair(
                seed: Option<[u8; 32]>,
            ) -> Result<(Self::PrivKey, ()), Box<dyn std::error::Error>> {
                use $gen_path as gen_mod;
                let (privkey, _) = gen_mod::generate_key_pair(seed)?;
                Ok((privkey, ()))
            }
        }
    };
}

impl_mldsa_sign_variant!(
    Mldsa44,
    crate::adapters::libcrux::mldsa::mldsa44::PrivKey,
    crate::adapters::libcrux::mldsa::mldsa44::Signature,
    crate::adapters::libcrux::mldsa::mldsa44
);

impl_mldsa_sign_variant!(
    Mldsa65,
    crate::adapters::libcrux::mldsa::mldsa65::PrivKey,
    crate::adapters::libcrux::mldsa::mldsa65::Signature,
    crate::adapters::libcrux::mldsa::mldsa65
);

impl_mldsa_sign_variant!(
    Mldsa87,
    crate::adapters::libcrux::mldsa::mldsa87::PrivKey,
    crate::adapters::libcrux::mldsa::mldsa87::Signature,
    crate::adapters::libcrux::mldsa::mldsa87
);

fn run_mldsa_wycheproof_sign_tests_internal<T: MLDsaSignVariant>(
    path: &str,
    det: bool,
) {
    let schema = load_sign_schema_from_file(path)
        .expect("Failed to load sign test vectors");

    let mut passed = 0;
    let mut failed = 0;

    for group in &schema.test_groups {
        let priv_bytes = decode(&group.private_input).unwrap();
        let privkey = if priv_bytes.len() == 32 {
            let seed: [u8; 32] =
                priv_bytes.try_into().expect("Seed should be 32 bytes");
            match T::generate_key_pair(Some(seed)) {
                Ok((sk, _)) => sk,
                Err(e) => {
                    let all_invalid = group
                        .tests
                        .iter()
                        .all(|t| matches!(t.result, SignResult::Invalid));
                    if all_invalid {
                        passed += group.tests.len();
                    } else {
                        failed += group.tests.len();
                        eprintln!("Keygen from seed failed: {e}");
                    }
                    continue;
                }
            }
        } else {
            match T::decode_privkey(&priv_bytes) {
                Ok(pk) => pk,
                Err(e) => {
                    let all_invalid = group
                        .tests
                        .iter()
                        .all(|t| matches!(t.result, SignResult::Invalid));
                    if all_invalid {
                        passed += group.tests.len();
                    } else {
                        failed += group.tests.len();
                        eprintln!("Private key decode failed: {e}");
                    }
                    continue;
                }
            }
        };

        for test in &group.tests {
            let msg = decode(&test.msg).unwrap();
            let ctx = decode(&test.ctx).unwrap_or_default();

            let sig_res = T::try_sign_with_ctx(&privkey, &msg, &ctx, det);

            match (&sig_res, &test.result) {
                (Err(_), SignResult::Invalid) => {
                    println!(
                        "✅ tcId {}: {} :— signing failed as expected (invalid)",
                        test.tc_id, test.comment
                    );
                    passed += 1;
                }
                (Err(e), SignResult::Valid) => {
                    println!(
                        "❌ tcId {}: {} — unexpected signing failure: {}",
                        test.tc_id, test.comment, e
                    );
                    failed += 1;
                }
                (Ok(_), SignResult::Invalid) => {
                    println!(
                        "❌ tcId {}: {} — expected invalid but signing succeeded",
                        test.tc_id, test.comment
                     );
                    failed += 1;
                }
                (Ok(sig), SignResult::Valid) => {
                    if det {
                        let expected = decode(&test.sig).unwrap();
                        let actual = T::encode_signature(sig);
                        if actual == expected {
                            println!(
                                "✅ tcId {}: {} — signature matches expected",
                                test.tc_id, test.comment
                            );
                            passed += 1;
                        } else {
                            println!(
                                "❌ tcId {}: {} — signature mismatch",
                                test.tc_id, test.comment,
                            );
                            failed += 1;
                        }
                    } else {
                        println!("✅ tcId {}: {}", test.tc_id, test.comment);
                        passed += 1;
                    }
                }
            }
        }
    }

    println!(
        "\n✔️ Passed: {} | ❌ Failed: {} | Total: {}",
        passed,
        failed,
        passed + failed
    );

    assert_eq!(failed, 0, "Some Wycheproof signing test cases failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa44_sign_with_seed() {
        let path_buf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/wycheproof/mldsa_44_sign_seed_test.json");

        let path = path_buf
            .to_str()
            .expect("Path to testvector must be valid UTF-8");
        run_mldsa_wycheproof_sign_tests_internal::<Mldsa44>(path, true);
    }

    #[test]
    fn test_mldsa44_sign_without_seed() {
        let path_buf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/wycheproof/mldsa_44_sign_noseed_test.json");

        let path = path_buf
            .to_str()
            .expect("Path to testvector must be valid UTF-8");
        run_mldsa_wycheproof_sign_tests_internal::<Mldsa44>(path, true);
    }

    #[test]
    fn test_mldsa65_sign_with_seed() {
        let path_buf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/wycheproof/mldsa_65_seed_sign_test.json");

        let path = path_buf
            .to_str()
            .expect("Path to testvector must be valid UTF-8");
        run_mldsa_wycheproof_sign_tests_internal::<Mldsa65>(path, true);
    }

    #[test]
    fn test_mldsa65_sign_without_seed() {
        let path_buf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/wycheproof/mldsa_65_noseed_sign_test.json");

        let path = path_buf
            .to_str()
            .expect("Path to testvector must be valid UTF-8");
        run_mldsa_wycheproof_sign_tests_internal::<Mldsa65>(path, true);
    }

    #[test]
    fn test_mldsa87_sign_with_seed() {
        let path_buf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/wycheproof/mldsa_87_sign_seed_test.json");

        let path = path_buf
            .to_str()
            .expect("Path to testvector must be valid UTF-8");
        run_mldsa_wycheproof_sign_tests_internal::<Mldsa87>(path, true);
    }

    #[test]
    fn test_mldsa87_sign_without_seed() {
        let path_buf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/wycheproof/mldsa_87_sign_noseed_test.json");

        let path = path_buf
            .to_str()
            .expect("Path to testvector must be valid UTF-8");
        run_mldsa_wycheproof_sign_tests_internal::<Mldsa87>(path, true);
    }
}
