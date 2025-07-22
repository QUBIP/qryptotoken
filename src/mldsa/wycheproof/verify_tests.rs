use super::reader::*;
use super::verify_schema::VerifyResult;

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

use hex::decode;

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

            fn decode_pubkey(
                bytes: &[u8],
            ) -> Result<Self::PubKey, Box<dyn std::error::Error>> {
                <$pubkey>::decode(bytes)
            }

            fn decode_signature(
                bytes: &[u8],
            ) -> Result<Self::Signature, Box<dyn std::error::Error>> {
                <$sig>::decode(bytes)
            }

            fn verify(
                pubkey: &Self::PubKey,
                msg: &[u8],
                sig: &Self::Signature,
            ) -> bool {
                pubkey.verify(msg, sig).is_ok()
            }

            fn verify_with_ctx(
                pubkey: &Self::PubKey,
                msg: &[u8],
                sig: &Self::Signature,
                ctx: &[u8],
            ) -> bool {
                pubkey.verify_with_ctx(msg, sig, ctx).is_ok()
            }
        }
    };
}

impl_mldsa_verify_variant!(Mldsa44, PubKey44, Signature44);
impl_mldsa_verify_variant!(Mldsa65, PubKey65, Signature65);
impl_mldsa_verify_variant!(Mldsa87, PubKey87, Signature87);

pub fn run_mldsa_wycheproof_verify_tests<T: MLDsaVerifyVariant>(path: &str) {
    let schema = load_verify_schema_from_file(path)
        .expect("Failed to load test vectors");

    let mut passed = 0;
    let mut failed = 0;

    for group in &schema.test_groups {
        let pubkey_bytes = decode(&group.public_key).unwrap();
        let pubkey = match T::decode_pubkey(&pubkey_bytes) {
            Ok(pk) => pk,
            Err(e) => {
                let all_invalid = group
                    .tests
                    .iter()
                    .all(|t| matches!(t.result, VerifyResult::Invalid));

                if all_invalid {
                    for test in &group.tests {
                        println!(
                            "✅ tcId {}: {} — decoding failed as expected",
                            test.tc_id, test.comment
                        );
                        passed += 1;
                    }
                } else {
                    for test in &group.tests {
                        println!(
                            "❌ tcId {}: {} — pubkey decode failed: {}",
                            test.tc_id, test.comment, e
                        );
                        failed += 1;
                    }
                }

                continue;
            }
        };

        for test in &group.tests {
            let msg = decode(&test.msg).unwrap();
            let sig = match T::decode_signature(&decode(&test.sig).unwrap()) {
                Ok(sig) => sig,
                Err(e) => {
                    if let VerifyResult::Invalid = test.result {
                        println!(
                "✅ tcId {}: {} — signature decode failed as expected",
                test.tc_id, test.comment
            );
                        passed += 1;
                    } else {
                        println!(
                            "❌ tcId {}: {} — Signature decode failed: {}",
                            test.tc_id, test.comment, e
                        );
                        failed += 1;
                    }
                    continue;
                }
            };

            let ctx = decode(&test.ctx).unwrap_or_default();

            let result = if !ctx.is_empty() {
                T::verify_with_ctx(&pubkey, &msg, &sig, &ctx)
            } else {
                T::verify(&pubkey, &msg, &sig)
            };

            let expected = &test.result;
            let passed_case = match (expected, result) {
                (VerifyResult::Valid, true) => true,
                (VerifyResult::Invalid, false) => true,
                _ => false,
            };
            if passed_case {
                println!("✅ tcId {}: {}", test.tc_id, test.comment);
                passed += 1;
            } else {
                println!(
                    "❌ tcId {}: {} — expected {:?}, got {}",
                    test.tc_id, test.comment, expected, result
                );
                failed += 1;
            }
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
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/wycheproof/mldsa_44_verify_test.json");
        run_mldsa_wycheproof_verify_tests::<Mldsa44>(path.to_str().unwrap());
    }

    #[test]
    fn test_mldsa_65_verify_from_wycheproof() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/wycheproof/mldsa_65_verify_test.json");
        run_mldsa_wycheproof_verify_tests::<Mldsa65>(path.to_str().unwrap());
    }

    #[test]
    fn test_mldsa_87_verify_from_wycheproof() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/wycheproof/mldsa_87_verify_test.json");
        run_mldsa_wycheproof_verify_tests::<Mldsa87>(path.to_str().unwrap());
    }
}
