// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms
use crate::attribute::from_bytes;
use crate::error::CkRvError;
use crate::interface::*;
use crate::log::*;
use crate::object::Object;
use crate::{err_rv, to_rv};
use crate::{KError, KResult};
use libcrux_kem::{Algorithm, Ct, PrivateKey, PublicKey};
use rand::rngs::OsRng;

const MLKEM768_CIPHERTEXT_BYTES: u64 = 1088;
const MLKEM768_SHAREDSECRET_BYTES: u64 = 32;

pub fn validate_mechanism(mechanism: CK_MECHANISM) -> KResult<CK_MECHANISM> {
    const EXPECTED_PARAM_LEN: CK_ULONG =
        std::mem::size_of::<CK_NSS_KEM_PARAMETER_SET_TYPE>() as CK_ULONG;
    if mechanism.ulParameterLen != EXPECTED_PARAM_LEN {
        /*
         * TODO(Nouman): is this the best error value for this case? (i.e., document why)
         */
        error!(
            "Unexpected params len: expected {:?}, got {:?}",
            EXPECTED_PARAM_LEN, mechanism.ulParameterLen
        );
        return err_rv!(CKR_MECHANISM_INVALID);
    }
    let param = match mechanism.pParameter.is_null() {
        true => {
            error!("mechanism.pParameter was NULL");
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        false => {
            let p_parameter_set =
                mechanism.pParameter as *const CK_NSS_KEM_PARAMETER_SET_TYPE;
            unsafe { *p_parameter_set }
        }
    };
    validate_params(param)
        .map_err(|_| to_rv!(CKR_MECHANISM_PARAM_INVALID))
        .and_then(|_| Ok(mechanism))
}

pub fn validate_params(params: CK_NSS_KEM_PARAMETER_SET_TYPE) -> KResult<()> {
    match params {
        CKP_NSS_ML_KEM_768 => Ok(()),
        _ => Err(KError::RvError(CkRvError {
            rv: CKR_MECHANISM_PARAM_INVALID,
        })),
    }
}

pub fn encapsulate(
    _mechanism: &CK_MECHANISM,
    public_key_obj: &Object,
    ciphertext: /* out */ &mut [u8],
    shared_secret_obj: /* out */ &mut Object,
) -> KResult<CK_RV> {
    /* Later we can check on _mechanism to select the right param set, for now we only support MLKEM768 */
    const PARAM_SET: Algorithm = Algorithm::MlKem768;
    const EXPECTED_SS_LEN: usize = MLKEM768_SHAREDSECRET_BYTES as usize;

    let pk_bytes = public_key_obj
        .get_attr_as_bytes(CKA_VALUE)
        .map_err(|e| {
            error!("Cannot retrieve raw public key value from handle: {e:?}");
            to_rv!(CKR_KEY_HANDLE_INVALID)
        })?
        .as_slice();

    let pk = PublicKey::decode(PARAM_SET, pk_bytes).map_err(|e| {
        error!("Failed to decode the secret key: {e:?}");
        to_rv!(CKR_DATA_INVALID)
    })?;

    let mut rng = OsRng;

    let (ss, ct) = pk.encapsulate(&mut rng).map_err(|e| {
        error!("Failed to decapsulate key: {e:?}");
        // TODO: We might need to return either CKR_ARGUMENTS_BAD or
        // CKR_FUNCTION_FAILED discriminating on the runtime value of `e`
        to_rv!(CKR_FUNCTION_FAILED)
    })?;

    let ss = ss.encode();

    if ss.len() != EXPECTED_SS_LEN {
        error! {"Unexpected size for the encapsulated shared secret. Got {},
        expected {EXPECTED_SS_LEN:}.", ss.len() };
        return err_rv!(CKR_ENCRYPTED_DATA_INVALID);
    }

    shared_secret_obj
        .set_attr(from_bytes(CKA_VALUE, ss))
        .map_err(|e| {
            error!("Failed to set shared secret CKA_VALUE attribute: {e:?}");
            e
        })?;

    let ct_bytes = ct.encode();

    if ct_bytes.len() != ciphertext.len() {
        error!(
            "unexpected ciphertext length: expected {}, got {}",
            ciphertext.len(),
            ct_bytes.len()
        );
        return err_rv!(CKR_BUFFER_TOO_SMALL);
    }

    ciphertext.clone_from_slice(&ct_bytes);

    Ok(CKR_OK)
}

pub fn decapsulate(
    _mechanism: &CK_MECHANISM,
    private_key_obj: &Object,
    ct: &[u8],
    shared_secret_obj: /* out */ &mut Object,
) -> KResult<CK_RV> {
    /* Later we can check on _mechanism to select the right param set, for now we only support MLKEM768 */
    const PARAM_SET: Algorithm = Algorithm::MlKem768;
    const EXPECTED_SS_LEN: usize = MLKEM768_SHAREDSECRET_BYTES as usize;

    let sk_bytes = private_key_obj
        .get_attr_as_bytes(CKA_VALUE)
        .map_err(|e| {
            error!("Cannot retrieve raw private key value from handle: {e:?}");
            to_rv!(CKR_KEY_HANDLE_INVALID)
        })?
        .as_slice();
    let sk = PrivateKey::decode(PARAM_SET, &sk_bytes).map_err(|e| {
        error!("Failed to decode the secret key: {e:?}");
        to_rv!(CKR_DATA_INVALID)
    })?;

    let ct = Ct::decode(PARAM_SET, ct).map_err(|e| {
        error!("Failed to decode ciphertext: {e:?}");
        to_rv!(CKR_ARGUMENTS_BAD)
    })?;

    let ss = ct
        .decapsulate(&sk)
        .map_err(|e| {
            error!("Failed to decapsulate key: {e:?}");
            // TODO: We might need to return either CKR_ARGUMENTS_BAD or
            // CKR_FUNCTION_FAILED discriminating on the runtime value of `e`
            to_rv!(CKR_FUNCTION_FAILED)
        })?
        .encode();

    if ss.len() != EXPECTED_SS_LEN {
        error! {"Unexpected size for the decapsulated shared secret. Got {}, expected {EXPECTED_SS_LEN:}.", ss.len() };
        return err_rv!(CKR_ENCRYPTED_DATA_INVALID);
    }

    shared_secret_obj
        .set_attr(from_bytes(CKA_VALUE, ss))
        .map_err(|e| {
            error!("Failed to set shared secret CKA_VALUE attribute: {e:?}");
            e
        })?;

    Ok(CKR_OK)
}

pub fn get_ciphertext_len(mechanism: &CK_MECHANISM) -> KResult<CK_ULONG> {
    // mechanism should have already been validated (including params)
    assert_ne!(mechanism.pParameter.is_null(), true);
    let parameter_set = unsafe {
        *(mechanism.pParameter as *const CK_NSS_KEM_PARAMETER_SET_TYPE)
    };

    match parameter_set {
        CKP_NSS_ML_KEM_768 => Ok(MLKEM768_CIPHERTEXT_BYTES),
        _ => err_rv!(CKR_MECHANISM_PARAM_INVALID),
    }
}
