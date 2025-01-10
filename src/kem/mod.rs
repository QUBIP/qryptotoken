// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms
use crate::err_rv;
use crate::error::KResult;
use crate::interface::*;

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

pub fn get_ciphertext_len(p_mechanism: CK_MECHANISM_PTR) -> CK_ULONG {
    let mechanism = match validate_mechanism(p_mechanism) {
        Ok(m) => m,
        Err(e) => {
            error!("Mechanism validation failed with {e:?}");
            return 0;
        }
    };
    match mechanism.mechanism {
        CKM_NSS_ML_KEM => match mlkem::get_ciphertext_len(&mechanism) {
            Ok(l) => l,
            Err(e) => {
                error!("Got {e:?}");
                return 0;
            }
        },
        _ => {
            error!("Unknown mechanism ({:0X?})", mechanism.mechanism);
            return 0;
        }
    }
}
