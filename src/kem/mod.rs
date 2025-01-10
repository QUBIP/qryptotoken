// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms
use crate::err_rv;
use crate::error::KResult;
use crate::interface::*;
use crate::object::Object;

use crate::log::*;
use crate::token::Token;

pub mod mlkem;

pub fn validate_mechanism(
    p_mechanism: CK_MECHANISM_PTR,
) -> KResult<CK_MECHANISM> {
    if p_mechanism.is_null() {
        error!("CK_MECHANISM_PTR was NULL");
        return err_rv!(CKR_MECHANISM_INVALID);
    }

    let mechanism = unsafe { *p_mechanism };
    match mechanism.mechanism {
        CKM_NSS_ML_KEM => mlkem::validate_mechanism(mechanism),
        _ => {
            error!("Unknown mechanism ({:0X?})", mechanism.mechanism);
            return err_rv!(CKR_MECHANISM_INVALID);
        }
    }
    // #[cfg(not(debug_assertions))] // code compiled only in release builds
    // {
    //     todo!("Validate mechanism: {:?}", p_mechanism);
    //     return KError::RvError(CKR_GENERAL_ERROR);
    // }
    // #[cfg(debug_assertions)] // code compiled only in development builds
    // {
    //     let _ = p_mechanism;
    //     // if mlkem mechanism then mlkem::validate_params
    //     // otherwise KError::RvError(CKR_MECHANISM_INVALID)
    //     return Ok(());
    // }
}

pub fn get_ciphertext_len(mechanism: &CK_MECHANISM) -> KResult<CK_ULONG> {
    match mechanism.mechanism {
        CKM_NSS_ML_KEM => mlkem::get_ciphertext_len(&mechanism).map_err(|e| {
            error!("Got {e:?}");
            e
        }),
        _ => {
            error!("Unknown mechanism ({:0X?})", mechanism.mechanism);
            return err_rv!(CKR_MECHANISM_INVALID);
        }
    }
}

pub fn encapsulate(
    mechanism: &CK_MECHANISM,
    public_key: &Object,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG_PTR,
) -> KResult<CK_RV> {
    match mechanism.mechanism {
        CKM_NSS_ML_KEM => mlkem::encapsulate(public_key, data, data_len),
        other => {
            error!("Unknown mechanism: {other:0X?}");
            err_rv!(CKR_MECHANISM_INVALID)
        }
    }
}

pub fn decapsulate(
    mechanism: &CK_MECHANISM,
    private_key: &Object,
    p_data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    p_template: CK_ATTRIBUTE_PTR,
    ul_attribute_count: CK_ULONG,
    p_h_key: CK_OBJECT_HANDLE_PTR,
    token: &mut Token,
) -> KResult<CK_RV> {
    match mechanism.mechanism {
        CKM_NSS_ML_KEM => mlkem::decapsulate(
            private_key,
            p_data,
            data_len,
            p_template,
            ul_attribute_count,
            p_h_key,
            token,
        ),

        other => {
            error!("Unknown mechanism: {other:0X?}");
            err_rv!(CKR_MECHANISM_INVALID)
        }
    }
}
