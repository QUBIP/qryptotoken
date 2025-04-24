use crate::error::{KError, KResult};
use crate::interface::*;

pub mod mlkem;

pub fn validate_mechanism(p_mechanism: CK_MECHANISM_PTR) -> KResult<()> {
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
