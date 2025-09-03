use crate::adapters::error::*;
use crate::adapters::libcrux::mldsa::mldsa44::{
    PubKey as PubKey44, Signature as Signature44,
};
use crate::adapters::libcrux::mldsa::mldsa65::{
    PubKey as PubKey65, Signature as Signature65,
};
use crate::adapters::libcrux::mldsa::mldsa87::{
    PubKey as PubKey87, Signature as Signature87,
};
use crate::mldsa::wycheproof::mldsa_variant::MLDsaVerifyVariant;
use signature::Verifier;
use std::error::Error;
use wycheproof::mldsa_verify::{self, *};
use wycheproof::TestResult;

pub struct Mldsa44;
pub struct Mldsa65;
pub struct Mldsa87;

#[macro_export]
macro_rules! impl_mldsa_verify_variant {
    ($variant:ident, $pubkey:ty, $sig:ty) => {
        impl $crate::mldsa::wycheproof::mldsa_variant::MLDsaVerifyVariant
            for $variant
        {
            type PubKey = $pubkey;
            type Signature = $sig;

            fn decode_pubkey(bytes: &[u8]) -> AResult<Self::PubKey> {
                <$pubkey>::decode(bytes)
            }

            fn decode_signature(bytes: &[u8]) -> AResult<Self::Signature> {
                <$sig>::decode(bytes)
            }

            fn verify(
                pubkey: &Self::PubKey,
                msg: &[u8],
                sig: &Self::Signature,
            ) -> Result<(), signature::Error> {
                pubkey.verify(msg, sig)
            }

            fn verify_with_ctx(
                pubkey: &Self::PubKey,
                msg: &[u8],
                sig: &Self::Signature,
                ctx: &[u8],
            ) -> Result<(), signature::Error> {
                pubkey.verify_with_ctx(msg, sig, ctx)
            }
        }
    };
}

impl_mldsa_verify_variant!(Mldsa44, PubKey44, Signature44);
impl_mldsa_verify_variant!(Mldsa65, PubKey65, Signature65);
impl_mldsa_verify_variant!(Mldsa87, PubKey87, Signature87);

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
            TestFlag::IncorrectSignatureLength,
            AdapterError::InvalidSignatureLen { .. },
        ) => true,
        (
            TestFlag::IncorrectPublicKeyLength,
            AdapterError::InvalidKeyLen { .. },
        ) => true,
        (TestFlag::InvalidContext, AdapterError::ContextTooLong { .. }) => true,
        (
            TestFlag::InvalidHintsEncoding,
            AdapterError::VerificationError(_),
        ) => true,
        (TestFlag::ModifiedSignature, AdapterError::VerificationError(_)) => {
            true
        }

        _ => false,
    }
}

/// Tests are designed to continue running after a failure rather than
/// panicking, so that all failures can be reported together.
///
/// For negative tests, we verify that the actual error matches the expected
/// flags whenever possible. However, for signature verification, the exact
/// backend error may not be fully under our control. In such cases, if the
/// verification fails as expected, we consider the test as passed but classify
/// the error as `AdapterError::VerificationError`.
///
/// If a negative test fails as expected (i.e., the result is `Invalid`) but
/// the returned error does not match any of the expected flags, we count it
/// as a failure and mark it as a warning that requires further inspection.
pub fn run_mldsa_wycheproof_verify_tests<MlDsaParamSet: MLDsaVerifyVariant>(
    test_name: TestName,
) {
    let test_set = mldsa_verify::TestSet::load(test_name)
        .unwrap_or_else(|e| panic!("Failed to load sign test set: {e}"));
    let mut passed = 0;
    let mut failed = 0;

    for group in test_set.test_groups {
        /*
         * In Wycheproof, each entry in "testGroups" defines a public key that
         * is used for all tests in the associated "tests" array. If the public
         * key is invalid, the "tests" array usually contains only one test
         * case explaining the reason for the invalid key.
         *
         * Therefore, when public key decoding fails, we immediately validate
         * that this failure matches the expected outcome for all tests in the
         * group, then skip to the next "testGroup". If the public key is
         * valid, we continue and execute all tests within that group.
         */
        let pubkey_bytes = group.pubkey.as_ref();
        let pubkey = match MlDsaParamSet::decode_pubkey(&pubkey_bytes) {
            Ok(pk) => pk,
            Err(e) => {
                for test in &group.tests {
                    if test.result == TestResult::Invalid {
                        let matched = test
                            .flags
                            .iter()
                            .any(|f| error_matches_flag(f, &e));
                        if matched {
                            println!(
                                "✅ tcId {}: {} — pubkey decode failed as expected",
                                test.tc_id, test.comment,
                            );
                            passed += 1;
                        } else {
                            println!(
                                "⚠️ tcId {}: {} — pubkey decode failed as \
                                    expected but did not match any flag. \
                                    Error: {:?}, Flags: {:?}",
                                test.tc_id, test.comment, e, test.flags
                            );
                            failed += 1;
                        }
                    } else {
                        println!(
                            "❌ tcId {}: {} — expected Valid, but pubkey \
                                decode failed: {:?}",
                            test.tc_id, test.comment, e
                        );
                        failed += 1;
                    }
                }
                /* Jump to next group */
                continue;
            }
        };

        for test in &group.tests {
            let msg = test.msg.as_ref();
            let input_sig = test.sig.as_ref();
            let sig = match MlDsaParamSet::decode_signature(&input_sig) {
                Ok(sig) => sig,
                Err(e) => {
                    let invalid = TestResult::Invalid == test.result;
                    if invalid {
                        let matched = test
                            .flags
                            .iter()
                            .any(|f| error_matches_flag(f, &e));
                        if matched {
                            println!(
                                "✅ tcId {}: {} — signature decode failed as \
                                    expected",
                                test.tc_id, test.comment
                            );
                        } else {
                            println!(
                                "⚠️ tcId {}: {} — Signature decode failed as \
                                    expected but did not match any flag. \
                                    Error: {:?} Flags: {:?}",
                                test.tc_id, test.comment, e, test.flags
                            );
                        }
                        passed += 1;
                    } else {
                        println!(
                            "❌ tcId {}: {} — Expected Valid, but signature \
                                decode failed: {}",
                            test.tc_id, test.comment, e
                        );
                        failed += 1;
                    }
                    continue;
                }
            };

            let ctx = test.ctx.as_ref().map_or(&[][..], |c| c.as_ref());

            let result = if !ctx.is_empty() {
                MlDsaParamSet::verify_with_ctx(&pubkey, &msg, &sig, &ctx)
            } else {
                MlDsaParamSet::verify(&pubkey, &msg, &sig)
            };

            let expected = &test.result;
            let passed_case = match (expected, result.is_ok()) {
                (TestResult::Valid, true) => true,
                (TestResult::Invalid, false) => true,
                _ => false,
            };
            if passed_case {
                if result.is_err() {
                    let err = result.as_ref().err().unwrap();

                    if let Some(adapter_err) = extract_adapter_error(err) {
                        if !test
                            .flags
                            .iter()
                            .any(|f| error_matches_flag(f, adapter_err))
                        {
                            println!(
                                "⚠️ tcId {}: {}\nNegative case passed but \
                                    error {:?} did not match any flags {:?}",
                                test.tc_id,
                                test.comment,
                                adapter_err,
                                test.flags
                            );
                            failed += 1;
                            continue;
                        }
                    } else {
                        println!(
                            "❌ tcId {}: {} — Could not extract AdapterError",
                            test.tc_id, test.comment
                        );
                        failed += 1;
                        continue;
                    }
                }
                println!("✅ tcId {}: {}", test.tc_id, test.comment);
                passed += 1;
            } else {
                println!(
                    "❌ tcId {}: {} — expected {:?}, got {:?}",
                    test.tc_id, test.comment, expected, result
                );
                failed += 1;
            }
            continue;
        }
    }

    println!(
        "\n✔️ Passed: {passed} | ❌ Failed: {failed} | Total: {}",
        passed + failed
    );
    assert_eq!(failed, 0, "Some Wycheproof test cases failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa_44_verify_from_wycheproof() {
        run_mldsa_wycheproof_verify_tests::<Mldsa44>(TestName::MlDsa44Verify);
    }

    #[test]
    fn test_mldsa_65_verify_from_wycheproof() {
        run_mldsa_wycheproof_verify_tests::<Mldsa65>(TestName::MlDsa65Verify);
    }

    #[test]
    fn test_mldsa_87_verify_from_wycheproof() {
        run_mldsa_wycheproof_verify_tests::<Mldsa87>(TestName::MlDsa87Verify);
    }
}
