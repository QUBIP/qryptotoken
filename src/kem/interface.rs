// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms

extern "C" fn fn_encapsulate(
    s_handle: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_public_key: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_attribute_count: CK_ULONG,
    p_h_key: /* out */ CK_OBJECT_HANDLE_PTR,
    p_ciphertext: /* out */ CK_BYTE_PTR,
    pul_ciphertextlen: /* out */ CK_ULONG_PTR,
) -> CK_RV {
    if p_mechanism.is_null()
        || p_h_key.is_null()
        || p_template.is_null()
        || pul_ciphertextlen.is_null()
    {
        return CKR_ARGUMENTS_BAD;
    }

    let template = unsafe {
        let len = ul_attribute_count as usize;
        std::slice::from_raw_parts(p_template, len)
    };

    let mechanism = res_or_ret!(kem::validate_mechanism(p_mechanism));

    let ct_len = res_or_ret!(kem::get_ciphertext_len(&mechanism));

    // Safe because we already checked pul_ciphertextlen is not null
    let ciphertext_len = unsafe { *pul_ciphertextlen };

    /* The Firefox softtoken is checking only for `<`, we are stricter here and
     * check for `!=` as this seems more correct */
    if p_ciphertext.is_null() || ciphertext_len != ct_len {
        unsafe {
            *pul_ciphertextlen = ct_len;
        }
        return CKR_KEY_SIZE_RANGE;
    }

    /* Safe because we already checked p_ciphertext is not null,
     * we need to create a mutable slice of the ciphertext because later
     * it will be used to store the actual ciphertext.
     */
    let ct: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut(p_ciphertext, ct_len as usize)
    };
    // Safe because we already checked p_h_key is not null
    unsafe {
        *p_h_key = CK_INVALID_HANDLE;
    };

    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));

    let slot_id = session.get_slot_id();
    let slot = res_or_ret!(rstate.get_slot(slot_id));

    let mut tokn = res_or_ret!(slot.get_token_mut(false));

    /*
     * The Firefox softtoken here call sftk_NewObject() and then manually
     * adds the various attributes from the template,
     * instead we delegate both tasks to token::create_object()
     * and then we retrieve the handle for the newly created object.
     */
    let ss_obj_h: CK_OBJECT_HANDLE =
        res_or_ret!(tokn.create_object(s_handle, template).map_err(|e| {
            error!("Failed creating object: {e:?}");
            to_rv!(CKR_HOST_MEMORY)
        }));

    let mut ss_obj =
        res_or_ret!(tokn.get_object_by_handle(ss_obj_h).map_err(|e| {
            error!("Failed getting object by handle: {e:?}");
            to_rv!(CKR_HOST_MEMORY)
        }));

    let public_key_obj =
        res_or_ret!(tokn.get_object_by_handle(h_public_key).map_err(|e| {
            error!("Cannot retrieve private key from handle: {e:?}");
            to_rv!(CKR_KEY_HANDLE_INVALID)
        }));

    match kem::encapsulate(&mechanism, &public_key_obj, ct, &mut ss_obj) {
        Ok(_ok) => {
            if ct.len() != ct_len as usize {
                error!("Ciphertext length mismatch");
                return CKR_BUFFER_TOO_SMALL;
            }
            // Safe because we already checked p_h_key is not null
            unsafe {
                *p_h_key = ss_obj_h;
                *pul_ciphertextlen = ct_len;
            };
            CKR_OK
        }
        Err(e) => {
            error!("Encapsulate failed with {e:?}");
            return err_to_rv!(e);
        }
    }
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
    let template = unsafe {
        let len = ul_attribute_count as usize;
        std::slice::from_raw_parts(p_template, len)
    };

    let mechanism = res_or_ret!(kem::validate_mechanism(p_mechanism));
    let ct_len = res_or_ret!(kem::get_ciphertext_len(&mechanism));
    /* The Firefox softtoken is checking only for `<`, we are stricter here and
     * check for `!=` as this seems more correct */
    if ul_ciphertext_len != ct_len {
        return CKR_ARGUMENTS_BAD;
    }
    // Safe because we already checked p_ciphertext is not null
    let ct =
        unsafe { std::slice::from_raw_parts(p_ciphertext, ct_len as usize) };

    // Safe because we already checked p_h_key is not null
    unsafe {
        *p_h_key = CK_INVALID_HANDLE;
    };

    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));

    let slot_id = session.get_slot_id();
    let slot = res_or_ret!(rstate.get_slot(slot_id));

    let mut tokn = res_or_ret!(slot.get_token_mut(false));

    /*
     * The Firefox softtoken here caal sftk_NewObject() and then manually
     * adds the various attributes from the template,
     * instead we delegate both tasks to token::create_object()
     * and then we retrieve the handle for the newly created object.
     */
    let ss_obj_h: CK_OBJECT_HANDLE =
        res_or_ret!(tokn.create_object(s_handle, template).map_err(|e| {
            error!("Failed creating object: {e:?}");
            to_rv!(CKR_HOST_MEMORY)
        }));
    let mut ss_obj =
        res_or_ret!(tokn.get_object_by_handle(ss_obj_h).map_err(|e| {
            error!("Failed getting object by handle: {e:?}");
            to_rv!(CKR_HOST_MEMORY)
        }));

    let private_key_obj =
        res_or_ret!(tokn.get_object_by_handle(h_private_key).map_err(|e| {
            error!("Cannot retrieve private key from handle: {e:?}");
            to_rv!(CKR_KEY_HANDLE_INVALID)
        }));

    match kem::decapsulate(&mechanism, &private_key_obj, ct, &mut ss_obj) {
        Ok(_ok) => {
            // Safe because we already checked p_h_key is not null
            unsafe {
                *p_h_key = ss_obj_h;
            };
            CKR_OK
        }
        Err(e) => {
            error!("Decapsulate failed with {e:?}");
            return err_to_rv!(e);
        }
    }
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
