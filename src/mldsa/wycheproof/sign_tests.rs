use crate::adapters::error::*;
use crate::mldsa::wycheproof::mldsa_variant::MLDsaSignVariant;
use std::error::Error;
use wycheproof::mldsa_sign::{self, *};
use wycheproof::TestResult;

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

            fn decode_privkey(bytes: &[u8]) -> AResult<Self::PrivKey> {
                <$privkey>::decode(bytes)
            }

            fn try_sign_with_ctx(
                privkey: &Self::PrivKey,
                msg: &[u8],
                ctx: &[u8],
                det: bool,
            ) -> Result<Self::Signature, signature::Error> {
                privkey.try_sign_with_ctx(msg, ctx, det)
            }

            fn encode_signature(sig: &Self::Signature) -> Vec<u8> {
                sig.encode()
            }

            fn generate_key_pair(
                seed: Option<[u8; 32]>,
            ) -> AResult<(Self::PrivKey, ())> {
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

fn extract_adapter_error(err: &signature::Error) -> Option<&AdapterError> {
    let mut source = err.source();
    while let Some(src) = source {
        if let Some(adapter_err) = src.downcast_ref::<AdapterError>() {
            return Some(adapter_err);
        }
        source = src.source();
    }
    None
}

fn error_matches_flag(flag: &TestFlag, err: &AdapterError) -> bool {
    match (flag, err) {
        (
            TestFlag::IncorrectPrivateKeyLength,
            AdapterError::InvalidKeyLen { .. },
        ) => true,
        (TestFlag::InvalidContext, AdapterError::ContextTooLong { .. }) => true,
        (TestFlag::InvalidPrivateKey, AdapterError::SigningError(_)) => true,
        _ => false,
    }
}

/// Tests are designed to continue running after a failure rather than
/// panicking, so that all failures can be reported together.
///
/// For negative tests, we verify that the actual error matches the expected
/// flags whenever possible. However, for signature generation, the exact
/// backend error may not be fully under our control. In such cases, if the
/// generation fails as expected, we consider the test as passed but classify
/// the error as `AdapterError::VerificationError`.
///
/// If a negative test fails as expected (i.e., the result is `Invalid`) but
/// the returned error does not match any of the expected flags, we count it
/// as a failure and mark it as a warning that requires further inspection.
fn run_mldsa_wycheproof_sign_tests_internal<MlDsaParamSet: MLDsaSignVariant>(
    test_name: TestName,
    det: bool,
) {
    let test_set = mldsa_sign::TestSet::load(test_name)
        .unwrap_or_else(|e| panic!("Failed to load sign test set: {e}"));
    let mut passed = 0;
    let mut failed = 0;

    for group in test_set.test_groups {
        /*
         * In Wycheproof, each entry in "testGroups" defines a private key that
         * is used for all tests in the associated "tests" array. If the
         * private key is invalid, the "tests" array usually contains only one
         * test case explaining the reason for the invalid key.
         *
         * Therefore, when private key decoding fails (or generation from seed)
         * we immediately validate that this failure matches the expected
         * outcome for all tests in the group, then skip to the next
         * "testGroup". If the private key is valid, we continue and execute
         * all tests within that group.
         */

        /* Use privseed first, otherwise fallback to privkey */
        let priv_bytes = group
            .privseed
            .as_ref()
            .or(group.privkey.as_ref())
            .map(|b| b.as_slice().to_vec())
            .unwrap_or_else(|| {
                panic!(
                    "Neither privateKey nor privateSeed present in test group"
                )
            });

        let privkey = if priv_bytes.len() == 32 {
            /* Seed case */
            let seed: [u8; 32] =
                priv_bytes.try_into().expect("Seed should be 32 bytes");
            match MlDsaParamSet::generate_key_pair(Some(seed)) {
                Ok((sk, _)) => sk,
                Err(e) => {
                    for test in &group.tests {
                        if test.result == TestResult::Invalid {
                            let matched = test
                                .flags
                                .iter()
                                .any(|f| error_matches_flag(f, &e));
                            if matched {
                                println!(
                                    "✅ tcId {}: {} — keygen from seed failed \
                                        as expected",
                                    test.tc_id, test.comment
                                );
                                passed += 1;
                            } else {
                                println!(
                                    "⚠️ tcId {}: {} — keygen from seed failed \
                                        as expected but did not match any \
                                        flag.  Error: {:?}, Flags: {:?}",
                                    test.tc_id, test.comment, e, test.flags
                                );
                                failed += 1;
                            }
                        } else {
                            println!(
                                "❌ tcId {}: {} — expected Valid, but keygen \
                                    from seed failed: {:?}",
                                test.tc_id, test.comment, e
                            );
                            failed += 1;
                        }
                    }
                    /* Jump to next group */
                    continue;
                }
            }
        } else {
            /* Raw Privkey case */
            match MlDsaParamSet::decode_privkey(&priv_bytes) {
                Ok(sk) => sk,
                Err(e) => {
                    for test in &group.tests {
                        if test.result == TestResult::Invalid {
                            let matched = test
                                .flags
                                .iter()
                                .any(|f| error_matches_flag(f, &e));
                            if matched {
                                println!(
                                    "✅ tcId {}: {} — privkey decode failed \
                                        as expected",
                                    test.tc_id, test.comment
                                );
                                passed += 1;
                            } else {
                                println!(
                                    "⚠️ tcId {}: {} — privkey decode failed \
                                        as expected but did not match any \
                                        flag. Error: {:?}, Flags: {:?}",
                                    test.tc_id, test.comment, e, test.flags
                                );
                                failed += 1;
                            }
                        } else {
                            println!(
                                "❌ tcId {}: {} — expected Valid, but privkey \
                                    decode failed: {:?}",
                                test.tc_id, test.comment, e
                            );
                            failed += 1;
                        }
                    }
                    /* Jump to next group */
                    continue;
                }
            }
        };

        for test in &group.tests {
            let msg = test.msg.as_ref();
            let ctx = test.ctx.as_ref().map_or(&[][..], |c| c.as_ref());
            let sig_res =
                MlDsaParamSet::try_sign_with_ctx(&privkey, &msg, &ctx, det);

            match (&sig_res, test.result) {
                (Err(e), TestResult::Invalid) => {
                    if let Some(adapter_err) = extract_adapter_error(e) {
                        let matched = test
                            .flags
                            .iter()
                            .any(|f| error_matches_flag(f, adapter_err));
                        if matched {
                            println!(
                                "✅ tcId {}: {} — signing failed as expected",
                                test.tc_id, test.comment
                            );
                            passed += 1;
                        } else {
                            println!(
                                "⚠️ tcId {}: {} — signing failed as expected \
                                    but did not match any flag. \
                                    Error: {:?}, Flags: {:?}",
                                test.tc_id,
                                test.comment,
                                adapter_err,
                                test.flags
                            );
                            failed += 1;
                        }
                    } else {
                        println!(
                            "❌ tcId {}: {} — could not extract AdapterError \
                                from signing failure",
                            test.tc_id, test.comment
                        );
                        failed += 1;
                    }
                }
                (Err(e), TestResult::Valid) => {
                    println!(
                        "❌ tcId {}: {} — expected Valid, but signing \
                            failed: {:?}",
                        test.tc_id, test.comment, e
                    );
                    failed += 1;
                }
                (Ok(_), TestResult::Invalid) => {
                    println!(
                        "❌ tcId {}: {} — expected Invalid, but signing \
                            succeeded",
                        test.tc_id, test.comment
                    );
                    failed += 1;
                }
                (Ok(sig), TestResult::Valid) => {
                    if det {
                        let expected = test.sig.as_ref();
                        let actual = MlDsaParamSet::encode_signature(sig);
                        if actual == expected {
                            println!(
                                "✅ tcId {}: {} — signature matches expected",
                                test.tc_id, test.comment
                            );
                            passed += 1;
                        } else {
                            println!(
                                "❌ tcId {}: {} — signature mismatch",
                                test.tc_id, test.comment
                            );
                            failed += 1;
                        }
                    } else {
                        println!("✅ tcId {}: {}", test.tc_id, test.comment);
                        passed += 1;
                    }
                }
                _ => {
                    println!(
                        "❌ tcId {}: {} — 'Acceptable' case not covered",
                        test.tc_id, test.comment
                    );
                    failed += 1;
                }
            }
        }
    }

    println!(
        "\n✔️ Passed: {passed} | ❌ Failed: {failed} | Total: {}",
        passed + failed
    );
    assert_eq!(failed, 0, "Some Wycheproof signing test cases failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa44_sign_with_seed() {
        run_mldsa_wycheproof_sign_tests_internal::<Mldsa44>(
            TestName::MlDsa44SignSeed,
            true,
        );
    }

    #[test]
    fn test_mldsa44_sign_without_seed() {
        run_mldsa_wycheproof_sign_tests_internal::<Mldsa44>(
            TestName::MlDsa44SignNoSeed,
            true,
        );
    }

    #[test]
    fn test_mldsa65_sign_with_seed() {
        run_mldsa_wycheproof_sign_tests_internal::<Mldsa65>(
            TestName::MlDsa65SignSeed,
            true,
        );
    }

    #[test]
    fn test_mldsa65_sign_without_seed() {
        run_mldsa_wycheproof_sign_tests_internal::<Mldsa65>(
            TestName::MlDsa65SignNoSeed,
            true,
        );
    }

    #[test]
    fn test_mldsa87_sign_with_seed() {
        run_mldsa_wycheproof_sign_tests_internal::<Mldsa87>(
            TestName::MlDsa87SignSeed,
            true,
        );
    }

    #[test]
    fn test_mldsa87_sign_without_seed() {
        run_mldsa_wycheproof_sign_tests_internal::<Mldsa87>(
            TestName::MlDsa87SignSeed,
            true,
        );
    }
}
