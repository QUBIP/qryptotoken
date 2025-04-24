use crate::attribute::{from_bool, from_bytes, from_ulong};
use crate::interface::*;
use crate::object::{Object, ObjectFactories};
use crate::storage::{self, Storage};
use crate::token::Token;
use crate::{KError, KResult};
use libcrux::kem::*;

pub fn validate_params(
    pparams: *const CK_NSS_KEM_PARAMETER_SET_TYPE,
) -> KResult<()> {
    todo!("Validate parameters for MLKEM");
}

#[cfg(any())]
pub fn encapsulate(
    public_key: &Object,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG_PTR,
) -> CK_RV {
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
        return CKR_OK;
    }

    if unsafe { *data_len as usize } < ct_bytes.len() {
        unsafe { *data_len = ct_bytes.len() as CK_ULONG };
        return CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(ct_bytes.as_ptr(), data, ct_bytes.len())
    };

    CKR_OK
}

pub fn decapsulate(
    private_key: &Object,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    template: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key: CK_OBJECT_HANDLE_PTR,
    token: &mut Token,
) -> CK_RV {
    let sk_bytes = private_key
        .get_attr_as_bytes(CKA_VALUE)
        .expect("Failed to get private key value");
    let private_key = PrivateKey::decode(Algorithm::MlKem768, &sk_bytes)
        .expect("Failed to decode private key");

    let ciphertext_slice =
        unsafe { std::slice::from_raw_parts(data, data_len as usize) };
    let ct = Ct::decode(Algorithm::MlKem768, ciphertext_slice)
        .expect("Failed to decode ciphertext");

    let ss = ct
        .decapsulate(&private_key)
        .expect("Failed to decapsulate key");

    let template_slice: &[CK_ATTRIBUTE] = unsafe {
        std::slice::from_raw_parts(template, attribute_count as usize)
    };

    let mut key_object = token
        .get_object_factories()
        .create(template_slice)
        .expect("Failed to create object");
    key_object
        .set_attr(from_bytes(CKA_VALUE, ss.encode()))
        .expect("Failed to set attribute");

    CKR_OK
}
