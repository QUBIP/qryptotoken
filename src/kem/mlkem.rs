// Copyright (C) 2023-2025 Tampere University
// See LICENSE.txt file for terms
use crate::attribute::from_bytes;
use crate::error::CkRvError;
use crate::interface::*;
use crate::log::*;
use crate::object::Object;
use crate::token::Token;
use crate::{err_rv, to_rv};
use crate::{KError, KResult};
use libcrux::kem::{Algorithm, Ct, PrivateKey, PublicKey};
use rand::rngs::OsRng;

const MLKEM768_CIPHERTEXT_BYTES: u64 = 1088u64;

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
    public_key: &Object,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG_PTR,
) -> KResult<CK_RV> {
    let public_key_info = public_key
        .get_attr_as_bytes(CKA_PUBLIC_KEY_INFO)
        .expect("Failed to get public key info");

    let public_key = PublicKey::decode(Algorithm::MlKem768, &public_key_info)
        .expect("Failed to decode public key");

    let mut rng = OsRng;

    let (_ss, ct) = public_key
        .encapsulate(&mut rng)
        .expect("Failed to encapsulate key");

    let ct_bytes = ct.encode();

    if data.is_null() {
        unsafe { *data_len = ct_bytes.len() as CK_ULONG };
        return Ok(CKR_OK);
    }

    if unsafe { *data_len as usize } < ct_bytes.len() {
        unsafe { *data_len = ct_bytes.len() as CK_ULONG };
        return err_rv!(CKR_BUFFER_TOO_SMALL);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(ct_bytes.as_ptr(), data, ct_bytes.len())
    };

    Ok(CKR_OK)
}

pub fn decapsulate(
    private_key: &Object,
    p_data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    p_template: CK_ATTRIBUTE_PTR,
    ul_attribute_count: CK_ULONG,
    _p_h_key: CK_OBJECT_HANDLE_PTR,
    token: &mut Token,
) -> KResult<CK_RV> {
    let sk_bytes = private_key
        .get_attr_as_bytes(CKA_VALUE)
        .expect("Failed to get private key value");
    let private_key = PrivateKey::decode(Algorithm::MlKem768, &sk_bytes)
        .expect("Failed to decode private key");

    let ciphertext_slice =
        unsafe { std::slice::from_raw_parts(p_data, data_len as usize) };
    let ct = Ct::decode(Algorithm::MlKem768, ciphertext_slice)
        .expect("Failed to decode ciphertext");

    let ss = ct
        .decapsulate(&private_key)
        .expect("Failed to decapsulate key");

    let template_slice: &[CK_ATTRIBUTE] = unsafe {
        std::slice::from_raw_parts(p_template, ul_attribute_count as usize)
    };

    let mut key_object = token
        .get_object_factories()
        .create(template_slice)
        .expect("Failed to create object");
    key_object
        .set_attr(from_bytes(CKA_VALUE, ss.encode()))
        .expect("Failed to set attribute");

    // todo(Nouman): use p_h_key ?

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
