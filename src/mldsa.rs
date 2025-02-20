use crate::attribute::{from_bool, from_bytes, from_ulong};
use crate::error::*;
use crate::interface::*;
use crate::mechanism::*;
use crate::object::*;
use crate::{attr_element, bytes_attr_not_empty, err_rv};
use ml_dsa::signature::Signer;
use ml_dsa::signature::Verifier;
use ml_dsa::*;

use once_cell::sync::Lazy;
use std::fmt::Debug;

#[derive(Debug)]
struct PubKey(VerifyingKey<MlDsa65>);

#[derive(Debug)]
struct PrivKey(SigningKey<MlDsa65>);

#[derive(Debug)]
pub struct MlDsaPubFactory {
    attributes: Vec<ObjectAttr>,
}

#[cfg(any())]
mod sizes {
    use super::*;

    /* These will be true once we support also ML-DSA-44 and ML-DSA-87 */
    pub(crate) const MIN_ML_DSA_SIZE_BITS: CK_ULONG = 1312 /* ML-DSA-44 public key */;
    pub(crate) const MAX_ML_DSA_SIZE_BITS: CK_ULONG = 4896 /* ML-DSA-87 private key */;
    pub(crate) const ML_DSA_SIGNATURE_SIZE_BITS: CK_ULONG = 4627 /* ML-DSA-87 signature */;
}

#[cfg(not(any()))]
mod sizes {
    use super::*;

    pub(crate) const MIN_ML_DSA_SIZE_BITS: CK_ULONG = 1952 /* ML-DSA-65 public key */;
    pub(crate) const MAX_ML_DSA_SIZE_BITS: CK_ULONG = 4032 /* ML-DSA-65 private key */;
    pub(crate) const ML_DSA_SIGNATURE_SIZE_BITS: CK_ULONG = 3309 /* ML-DSA-65 signature */;
}

use sizes::*;

impl MlDsaPubFactory {
    pub fn new() -> MlDsaPubFactory {
        let mut data = MlDsaPubFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_public_key_attrs());
        data.attributes.push(attr_element!(CKA_PUBLIC_KEY_INFO; OAFlags::RequiredOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));

        /* default to private */
        let private = attr_element!(CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy; from_bool; val true);
        match data
            .attributes
            .iter()
            .position(|x| x.get_type() == CKA_PRIVATE)
        {
            Some(idx) => data.attributes[idx] = private,
            None => data.attributes.push(private),
        }

        data
    }
}

impl ObjectFactory for MlDsaPubFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template)?;

        mldsa_import(&mut obj)?;

        if obj.get_attr(CKA_PUBLIC_KEY_INFO).is_none() {
            return err_rv!(CKR_TEMPLATE_INCOMPLETE);
        }

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyFactory for MlDsaPubFactory {}
impl PubKeyFactory for MlDsaPubFactory {}

#[derive(Debug)]
pub struct MlDsaPrivFactory {
    attributes: Vec<ObjectAttr>,
}

impl MlDsaPrivFactory {
    pub fn new() -> MlDsaPrivFactory {
        let mut data = MlDsaPrivFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_private_key_attrs());
        data.attributes.push(attr_element!(CKA_VALUE; OAFlags::Sensitive | OAFlags::RequiredOnCreate | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));

        /* default to private */
        let private = attr_element!(CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy; from_bool; val true);
        match data
            .attributes
            .iter()
            .position(|x| x.get_type() == CKA_PRIVATE)
        {
            Some(idx) => data.attributes[idx] = private,
            None => data.attributes.push(private),
        }

        data
    }
}

impl ObjectFactory for MlDsaPrivFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template)?;

        mldsa_import(&mut obj)?;

        if obj.get_attr(CKA_VALUE).is_none() {
            return err_rv!(CKR_TEMPLATE_INCOMPLETE);
        }

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    fn export_for_wrapping(&self, key: &Object) -> KResult<Vec<u8>> {
        PrivKeyFactory::export_for_wrapping(self, key)
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        PrivKeyFactory::import_from_wrapped(self, data, template)
    }
}

impl CommonKeyFactory for MlDsaPrivFactory {}
impl PrivKeyFactory for MlDsaPrivFactory {}

static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlDsaPubFactory::new()));

static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlDsaPrivFactory::new()));

#[derive(Debug)]
pub struct MlDsaMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for MlDsaMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_ML_DSA, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }

        let _mech = mech.mechanism;
        Ok(Box::new(MLDSAOperation {
            output_len: make_output_length_from_obj(key)?,
            public_key: None,
            private_key: Some(PrivKey::try_from(key)?),
            data: Vec::new(),
            finalized: false,
            in_use: false,
            _sigctx: None,
        }))
    }

    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Verify>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_ML_DSA, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }

        let _ = mech;
        Ok(Box::new(MLDSAOperation {
            output_len: make_output_length_from_obj(key)?,
            public_key: Some(PubKey::try_from(key)?),
            private_key: None,
            data: Vec::new(),
            finalized: false,
            in_use: false,
            _sigctx: None,
        }))
    }

    fn generate_keypair(
        &self,
        mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> KResult<(Object, Object)> {
        let mut rng = crate::rng::RNG::new().expect("RNG instantiation failed");

        let mut public_key =
            PUBLIC_KEY_FACTORY.default_object_generate(pubkey_template)?;

        if !public_key
            .check_or_set_attr(from_ulong(CKA_CLASS, CKO_PUBLIC_KEY))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !public_key
            .check_or_set_attr(from_ulong(CKA_KEY_TYPE, CKK_ML_DSA))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        let mut private_key =
            PRIVATE_KEY_FACTORY.default_object_generate(prikey_template)?;

        if !private_key
            .check_or_set_attr(from_ulong(CKA_CLASS, CKO_PRIVATE_KEY))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !private_key
            .check_or_set_attr(from_ulong(CKA_KEY_TYPE, CKK_ML_DSA))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        let key_pair = MlDsa65::key_gen(&mut rng);
        let pk = key_pair.verifying_key().clone();
        let sk = key_pair.signing_key().clone();
        let pk = PubKey(pk);
        let sk = PrivKey(sk);

        // TODO: check if CKA_VALUE is right here
        public_key.set_attr(from_bytes(CKA_VALUE, pk.0.encode().to_vec()))?;

        // TODO: check if CKA_VALUE is right here
        private_key.set_attr(from_bytes(CKA_VALUE, sk.0.encode().to_vec()))?;

        default_key_attributes(&mut private_key, mech.mechanism)?;
        default_key_attributes(&mut public_key, mech.mechanism)?;

        Ok((public_key, private_key))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(
        CKM_ML_DSA,
        Box::new(MlDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_ML_DSA_SIZE_BITS,
                ulMaxKeySize: MAX_ML_DSA_SIZE_BITS,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_ML_DSA_KEYGEN,
        Box::new(MlDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_ML_DSA_SIZE_BITS,
                ulMaxKeySize: MAX_ML_DSA_SIZE_BITS,
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    );

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_ML_DSA),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_ML_DSA),
        &PRIVATE_KEY_FACTORY,
    );
}

fn mldsa_import(obj: &mut Object) -> KResult<()> {
    bytes_attr_not_empty!(obj; CKA_VALUE);
    Ok(())
}

#[derive(Debug)]
struct MLDSAOperation {
    output_len: usize,
    public_key: Option<PubKey>,
    private_key: Option<PrivKey>,
    finalized: bool,
    data: Vec<u8>,
    in_use: bool,
    _sigctx: Option<Signature<MlDsa65>>,
}

impl crate::mechanism::MechOperation for MLDSAOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for MLDSAOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        } else if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        // self.sign_update(data)?;
        else if !self.in_use {
            self.in_use = true;

            if self.private_key.is_none() {
                return err_rv!(CKR_KEY_HANDLE_INVALID);
            }
        }
        self.data.extend_from_slice(data);

        // self.sign_final(signature)
        self.finalized = true;

        let signlen = signature.len();

        let private_key = match self.private_key.as_ref() {
            Some(key) => &key.0,
            None => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };

        // Perform the signing operation
        let signed_data = match private_key.try_sign(&self.data) {
            Ok(sig) => sig,
            Err(_) => return err_rv!(CKR_FUNCTION_FAILED),
        };

        let encoded_signature = signed_data.encode().to_vec();

        if encoded_signature.len() != signlen {
            // TODO: check if this is the right error
            return err_rv!(CKR_BUFFER_TOO_SMALL);
        }

        Ok(())
    }

    fn sign_update(&mut self, data: &[u8]) -> KResult<()> {
        // if self.finalized {
        //     return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        // }
        let _ = data;
        // if !self.in_use {
        //     self.in_use = true;

        //     if self.private_key.is_none() {
        //         return err_rv!(CKR_KEY_HANDLE_INVALID);
        //     }
        // }

        // self.data.extend_from_slice(data);
        // Ok(())
        todo!("Implement this function")
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> KResult<()> {
        let _ = signature;
        // if !self.in_use {
        //     return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        // }
        // // if self.finalized {
        // //     return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        // // }
        // self.finalized = true;

        // let signlen = signature.len();

        // let private_key = match self.private_key.as_ref() {
        //     Some(key) => &key.0,
        //     None => return err_rv!(CKR_KEY_HANDLE_INVALID),
        // };

        // // Perform the signing operation
        // let signed_data = match private_key.try_sign(&self.data) {
        //     Ok(sig) => sig,
        //     Err(_) => return err_rv!(CKR_FUNCTION_FAILED),
        // };

        // let encoded_signature = signed_data.encode().to_vec();

        // if encoded_signature.len() != signlen {
        //     // TODO: check if this is the right error
        //     return err_rv!(CKR_BUFFER_TOO_SMALL);
        // }

        // Ok(())
        todo!("Implement this function")
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

impl Verify for MLDSAOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.verify_update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            self.in_use = true;

            if self.public_key.is_none() {
                return err_rv!(CKR_KEY_HANDLE_INVALID);
            }
        }
        self.data.extend_from_slice(data);
        Ok(())
    }

    fn verify_final(&mut self, signature: &[u8]) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        let public_key = match self.public_key.as_ref() {
            Some(key) => &key.0,
            None => return err_rv!(CKR_KEY_HANDLE_INVALID),
        };

        let decoded_signature = match Signature::<MlDsa65>::try_from(signature)
        {
            Ok(sig) => sig,
            Err(_) => return err_rv!(CKR_SIGNATURE_INVALID), // Error if decoding fails
        };

        match public_key.verify(&self.data, &decoded_signature) {
            Ok(_) => (),
            Err(_) => return err_rv!(CKR_SIGNATURE_INVALID),
        };

        Ok(())
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}
fn make_output_length_from_obj(key: &Object) -> KResult<usize> {
    let bytes = match key.get_attr_as_bytes(CKA_VALUE) {
        Ok(val) => val,
        Err(_) => return err_rv!(CKR_GENERAL_ERROR),
    };

    let output_len = match bytes.len() {
        3309 => ML_DSA_SIGNATURE_SIZE_BITS as usize,
        _ => return err_rv!(CKR_GENERAL_ERROR),
    };

    Ok(output_len)
}

impl std::convert::TryFrom<&Object> for PubKey {
    type Error = KError;

    fn try_from(key: &Object) -> KResult<Self> {
        let pk_bytes = match key.get_attr_as_bytes(CKA_VALUE) {
            Ok(val) => val,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };
        let encoded_key: EncodedVerifyingKey<MlDsa65> =
            match EncodedVerifyingKey::<MlDsa65>::try_from(pk_bytes.as_slice())
            {
                Ok(encoded) => encoded,
                Err(_) => return err_rv!(CKR_GENERAL_ERROR),
            };

        let pk = VerifyingKey::<MlDsa65>::decode(&encoded_key);

        Ok(PubKey(pk))
    }
}

impl std::convert::TryFrom<&Object> for PrivKey {
    type Error = KError;

    fn try_from(key: &Object) -> KResult<Self> {
        let sk_bytes = match key.get_attr_as_bytes(CKA_VALUE) {
            Ok(val) => val,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };

        let encoded_key =
            match EncodedSigningKey::<MlDsa65>::try_from(sk_bytes.as_slice()) {
                Ok(encoded) => encoded,
                Err(_) => return err_rv!(CKR_GENERAL_ERROR),
            };

        let sk = SigningKey::<MlDsa65>::decode(&encoded_key);

        Ok(PrivKey(sk))
    }
}
