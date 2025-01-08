// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms

extern "C" fn fn_encapsulate(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hPublicKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
    pCiphertext: CK_BYTE_PTR,
    pulCiphertextLen: CK_ULONG_PTR,
) -> CK_RV {
    if pMechanism.is_null() || phKey.is_null() || pTemplate.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    todo!();

    //let pub_key= token.get_object_by_handle(hPublicKey).expect("Failed to get object from the handle");

    //if let e = perform_encapsulation(&pub_key, pCiphertext, pulCiphertextLen) {
    //    return CKR_GENERAL_ERROR;
    //}

    CKR_OK
}

fn validate_mechanism(p_mechanism: CK_MECHANISM_PTR) {
    #[cfg(not(debug_assertions))] // code compiled only in release builds
    {
        todo!("Validate mechanism: {:?}", p_mechanism);
    }
    #[cfg(debug_assertions)] // code compiled only in development builds
    {
        let _ = p_mechanism;
        return;
    }
}

extern "C" fn fn_decapsulate(
    s_handle: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_private_key: CK_OBJECT_HANDLE,
    pCiphertext: CK_BYTE_PTR,
    ul_ciphertext_len: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: /* out */ CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if p_mechanism.is_null()
        || phKey.is_null()
        || pCiphertext.is_null()
        || pTemplate.is_null()
    {
        return CKR_ARGUMENTS_BAD;
    }

    validate_mechanism(p_mechanism);

    let ct_len = { todo!("extract ct_len from p_mechanism"); 0u64 };
    if (ul_ciphertext_len < ct_len) {
        return CKR_ARGUMENTS_BAD;
    }
    
    // Safe because we already checked phKey is not null
    unsafe { *phKey = CK_INVALID_HANDLE; };

    let rstate = global_rlock!(STATE);
    let mut token = res_or_ret!(rstate.get_token_from_session_mut(s_handle));

    let private_key = token.get_object_by_handle(h_private_key).expect("Cannot retrieve private key from handle");

    let e = kem::perform_decapsulation(&private_key, pCiphertext, ul_ciphertext_len, pTemplate, ulAttributeCount, phKey, &mut token);
    
    // this is fishy!
    if (e != CKR_OK) {
        return CKR_GENERAL_ERROR;
    }
    CKR_OK
}

static FNLIST_KEM: CK_NSS_KEM_FUNCTIONS = CK_NSS_KEM_FUNCTIONS {
    version: CK_VERSION { major: 1, minor: 0 },
    C_Encapsulate: Some(fn_encapsulate),
    C_Decapsulate: Some(fn_decapsulate),
};

pub static INTERFACE_NSS: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: c"Vendor NSS KEM Interface".as_ptr() as *const u8,
    pFunctionList: &FNLIST_KEM as *const CK_NSS_KEM_FUNCTIONS
        as *const ::std::os::raw::c_void,
    flags: 0,
};
