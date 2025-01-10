use crate::error::KResult;
use crate::interface::*;
use crate::{err_rv, to_rv};

pub mod mlkem;

pub fn validate_mechanism(p_mechanism: CK_MECHANISM_PTR) -> KResult<()> {
    if p_mechanism.is_null() {
        return err_rv!(CKR_MECHANISM_INVALID);
    }

    let mechanism = unsafe { *p_mechanism };
    let param = unsafe { *(mechanism.pParameter as *const CK_ULONG) };
    match mechanism.mechanism {
        CKM_NSS_ML_KEM => {
            const EXPECTED_PARAM_LEN: CK_ULONG = std::mem::size_of::<
                CK_NSS_KEM_PARAMETER_SET_TYPE,
            >() as CK_ULONG;
            if mechanism.ulParameterLen != EXPECTED_PARAM_LEN {
                /*
                 * TODO(Nouman): is this the best error value for this case? (i.e., document why)
                 */
                return err_rv!(CKR_MECHANISM_INVALID);
            }
            mlkem::validate_params(param)
                .map_err(|_| to_rv!(CKR_MECHANISM_PARAM_INVALID))
        }

        _ => return err_rv!(CKR_MECHANISM_INVALID),
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
    if let Err(_) = validate_mechanism(p_mechanism) {
        return 0;
    }

    let mechanism = unsafe { *p_mechanism };

    let p_parameter_set =
        mechanism.pParameter as *const CK_NSS_KEM_PARAMETER_SET_TYPE;

    match unsafe { *p_parameter_set } {
        CKP_NSS_ML_KEM_768 => {
            return KYBER768_CIPHERTEXT_BYTES.into();
        }
        _ => return 0,
    }
}
