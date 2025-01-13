// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms

extern "C" fn fn_encapsulate(
    s_handle: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_public_key: CK_OBJECT_HANDLE,
    _p_template: CK_ATTRIBUTE_PTR,
    _ul_attribute_count: CK_ULONG,
    p_h_key: /* out */ CK_OBJECT_HANDLE_PTR,
    p_ciphertext: /* out */ CK_BYTE_PTR,
    pul_ciphertextlen: /* out */ CK_ULONG_PTR,
) -> CK_RV {
    if p_mechanism.is_null() || p_h_key.is_null() /* || p_template.is_null() */ {
        return CKR_ARGUMENTS_BAD;
    }

    let mechanism = res_or_ret!(kem::validate_mechanism(p_mechanism));

    let ct_len = res_or_ret!(kem::get_ciphertext_len(&mechanism));

    let ciphertext_len = unsafe { *pul_ciphertextlen };

    if p_ciphertext.is_null() || ciphertext_len < ct_len {
        unsafe {
            *pul_ciphertextlen = ct_len;
        }

        return CKR_KEY_SIZE_RANGE;
    }

    unsafe {
        *p_h_key = CK_INVALID_HANDLE;
    };

    let rstate = global_rlock!(STATE);
    let mut token = res_or_ret!(rstate.get_token_from_session_mut(s_handle));

    let public_key = token
        .get_object_by_handle(h_public_key)
        .expect("Cannot retrieve private key from handle");

    res_or_ret!(kem::encapsulate(&mechanism, &public_key, p_ciphertext, pul_ciphertextlen))
}

extern "C" fn fn_decapsulate(
    s_handle: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_private_key: CK_OBJECT_HANDLE,
    p_ciphertext: CK_BYTE_PTR,
    ul_ciphertext_len: CK_ULONG,
    p_template: CK_ATTRIBUTE_PTR,
    ul_attribute_count: CK_ULONG,
    p_h_key: /* out */ CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if p_mechanism.is_null()
        || p_h_key.is_null()
        || p_ciphertext.is_null()
        || p_template.is_null()
    {
        return CKR_ARGUMENTS_BAD;
    }

    let mechanism = res_or_ret!(kem::validate_mechanism(p_mechanism));
    let ct_len = res_or_ret!(kem::get_ciphertext_len(&mechanism));
    if ul_ciphertext_len < ct_len {
        return CKR_ARGUMENTS_BAD;
    }

    let rstate = global_rlock!(STATE);
    let mut token = res_or_ret!(rstate.get_token_from_session_mut(s_handle));

    // Safe because we already checked p_h_key is not null
    unsafe {
        *p_h_key = CK_INVALID_HANDLE;
    };

    let private_key = token
        .get_object_by_handle(h_private_key)
        .expect("Cannot retrieve private key from handle");

    res_or_ret!(kem::decapsulate(&mechanism, &private_key, p_ciphertext, ul_ciphertext_len, p_template, ul_attribute_count, p_h_key, &mut token))
}

static FNLIST_KEM: CK_NSS_KEM_FUNCTIONS = CK_NSS_KEM_FUNCTIONS {
    version: CK_VERSION { major: 1, minor: 0 },
    C_Encapsulate: Some(fn_encapsulate),
    C_Decapsulate: Some(fn_decapsulate),
};

pub static INTERFACE_NSS_KEM: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: c"Vendor NSS KEM Interface".as_ptr() as *const u8,
    pFunctionList: &FNLIST_KEM as *const CK_NSS_KEM_FUNCTIONS
        as *const ::std::os::raw::c_void,
    flags: 0,
};
