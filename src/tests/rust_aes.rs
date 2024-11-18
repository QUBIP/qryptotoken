
// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

use serial_test::parallel;

const AES_BLOCK_SIZE: usize = 16;

#[test]
#[parallel]
fn test_aes_operations() {
    let mut testtokn = TestToken::initialized(
        "test_aes_operations.sql",
        Some("testdata/test_aes_operations.json"),
    );
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Generate AES key */
    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 16),],
        &[],
        &[
            (CKA_SENSITIVE, true),
            (CKA_TOKEN, false),
            (CKA_ENCRYPT, true),
            (CKA_DECRYPT, true),
            (CKA_WRAP, true),
            (CKA_UNWRAP, true),
        ],
    ));

    {
        /* AES-GCM */

        let tag_len = 4usize;

        /* IV needs to be of size 12 for the test to work in FIPS mode as well */
        let iv = "BA0987654321";
        let aad = "AUTH ME";
        let param = CK_GCM_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: (tag_len * 8) as CK_ULONG,
        };

        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: void_ptr!(&param),
            ulParameterLen: sizeof!(CK_GCM_PARAMS),
        };

        /* Stream mode, so arbitrary data size and matching output */
        let data = "01234567";
        /* enc needs enough space for the tag */
        let enc: [u8; 16] = [0; 16];
        let mut enc_len = enc.len() as CK_ULONG;
        let ret = fn_encrypt(
            session,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, tag_len as CK_ULONG);

        /*let dec = ret_or_panic!(decrypt(
            session,
            handle,
            &enc[..(offset as usize + tag_len)],
            &mechanism,
        ));
        assert_eq!(dec.len(), data.len());
        assert_eq!(data.as_bytes(), dec.as_slice());
*/
        /* retry with one-shot encrypt operation */
        let enc2 = ret_or_panic!(encrypt(
            session,
            handle,
            data.as_bytes(),
            &mechanism,
        ));
        assert_eq!(enc2.len(), 12);
        assert_eq!(&enc[..12], enc2.as_slice());
    }

    {
        /* GCM */

        let testname = "gcmDecrypt128 96,104,128,128 0";
        let key_handle =
            match get_test_key_handle(session, testname, CKO_SECRET_KEY) {
                Ok(k) => k,
                Err(e) => panic!("{}", e),
            };
        let iv = match get_test_data(session, testname, "IV") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let aad = match get_test_data(session, testname, "AAD") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let tag = match get_test_data(session, testname, "Tag") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let ct = match get_test_data(session, testname, "CT") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let plaintext = match get_test_data(session, testname, "PT") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };

        let param = CK_GCM_PARAMS {
            pIv: byte_ptr!(iv.as_ptr()),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: byte_ptr!(aad.as_ptr()),
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };

        let mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: void_ptr!(&param),
            ulParameterLen: sizeof!(CK_GCM_PARAMS),
        };

        let ciphertext = [&ct[..], &tag[..]].concat();

        let dec = ret_or_panic!(decrypt(
            session,
            key_handle,
            &ciphertext,
            &mechanism,
        ));
        assert_eq!(&dec, &plaintext);
    }

    for mech in [CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP] {
        /* AES KEY WRAP */

        /* encryption and key wrapping operations should give the same
         * result, so we try both and compare */

        let data = [0x55u8; AES_BLOCK_SIZE];
        let iv = [0xCCu8; 8];
        let iv_len = match mech {
            CKM_AES_KEY_WRAP => 8,
            CKM_AES_KEY_WRAP_KWP => 4,
            _ => panic!("uh?"),
        };

        let mut wrapped = [0u8; AES_BLOCK_SIZE * 2];
        let mut wraplen = wrapped.len() as CK_ULONG;
        let mut mechanism = CK_MECHANISM {
            mechanism: mech,
            pParameter: void_ptr!(&iv),
            ulParameterLen: iv_len,
        };

        /* key to be wrapped */
        let wp_handle = ret_or_panic!(import_object(
            session,
            CKO_SECRET_KEY,
            &[(CKA_KEY_TYPE, CKK_AES)],
            &[(CKA_VALUE, &data)],
            &[(CKA_EXTRACTABLE, true)],
        ));
        let ret = fn_wrap_key(
            session,
            &mut mechanism,
            handle,
            wp_handle,
            wrapped.as_mut_ptr(),
            &mut wraplen,
        );
        assert_eq!(ret, CKR_OK);

        let dec = ret_or_panic!(decrypt(
            session,
            handle,
            &wrapped[..(wraplen as usize)],
            &mechanism,
        ));
        assert_eq!(data, dec.as_slice());

        let mut enc =
            ret_or_panic!(encrypt(session, handle, &data, &mechanism,));

        let mut template = make_attr_template(
            &[
                (CKA_CLASS, CKO_SECRET_KEY),
                (CKA_KEY_TYPE, CKK_AES),
                (CKA_VALUE_LEN, 16),
            ],
            &[],
            &[(CKA_EXTRACTABLE, true)],
        );

        let mut wp_handle2 = CK_INVALID_HANDLE;
        let ret = fn_unwrap_key(
            session,
            &mut mechanism,
            handle,
            enc.as_mut_ptr(),
            enc.len() as CK_ULONG,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut wp_handle2,
        );
        assert_eq!(ret, CKR_OK);

        let mut value = [0u8; AES_BLOCK_SIZE];
        let mut extract_template = make_ptrs_template(&[(
            CKA_VALUE,
            void_ptr!(value.as_mut_ptr()),
            value.len(),
        )]);

        let ret = fn_get_attribute_value(
            session,
            wp_handle2,
            extract_template.as_mut_ptr(),
            extract_template.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(value, data);
    }

    testtokn.finalize();
}
