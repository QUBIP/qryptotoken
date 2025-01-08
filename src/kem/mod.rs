use crate::error::{KError, KResult};
use crate::{interface::*, mechanism};
use crate::{err_rv};
use crate::error;

pub mod mlkem;

pub fn validate_mechanism(p_mechanism: CK_MECHANISM_PTR) -> KResult<()> {

    if p_mechanism.is_null() {
        return err_rv!(CKR_MECHANISM_INVALID);
    }

    let mechanism = unsafe { *p_mechanism };
    let param = unsafe { *(mechanism.pParameter as *const CK_ULONG) };
    match mechanism.mechanism {
        CKM_NSS_KYBER | CKM_NSS_ML_KEM => {
            if mechanism.ulParameterLen == std::mem::size_of::<CK_NSS_KEM_PARAMETER_SET_TYPE>()as CK_ULONG && mlkem::validate_params(param).is_ok(){
                return Ok(());
            }
            else{
                return Err(KError::RvError(error::CkRvError { rv: CKR_MECHANISM_INVALID }))
             }
    }

    _ => return Err(KError::RvError(error::CkRvError { rv: CKR_MECHANISM_INVALID }))

}
    #[cfg(not(debug_assertions))] // code compiled only in release builds
    {
        todo!("Validate mechanism: {:?}", p_mechanism);
        return KError::RvError(CKR_GENERAL_ERROR);
    }
    #[cfg(debug_assertions)] // code compiled only in development builds
    {
        let _ = p_mechanism;
        // if mlkem mechanism then mlkem::validate_params
        // otherwise KError::RvError(CKR_MECHANISM_INVALID)
        return Ok(());
    }
}
