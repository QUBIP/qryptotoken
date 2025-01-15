// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms
use crate::err_rv;
use crate::error::KResult;
use crate::interface::*;
use crate::object::Object;

use crate::log::*;

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
    public_key_obj: &Object,
    ciphertext: &mut [u8],
    shared_secret_obj: &mut Object,
) -> KResult<CK_RV> {
    match mechanism.mechanism {
        CKM_NSS_ML_KEM => mlkem::encapsulate(
            mechanism,
            public_key_obj,
            ciphertext,
            shared_secret_obj,
        ),
        other => {
            error!("Unknown mechanism: {other:0X?}");
            err_rv!(CKR_MECHANISM_INVALID)
        }
    }
}

pub fn decapsulate(
    mechanism: &CK_MECHANISM,
    private_key_obj: &Object,
    ct: &[u8],
    shared_secret_obj: /* out */ &mut Object,
) -> KResult<CK_RV> {
    match mechanism.mechanism {
        CKM_NSS_ML_KEM => mlkem::decapsulate(
            mechanism,
            private_key_obj,
            ct,
            shared_secret_obj,
        ),

        other => {
            error!("Unknown mechanism: {other:0X?}");
            err_rv!(CKR_MECHANISM_INVALID)
        }
    }
}
