use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

use crate::attribute;
use crate::error;
use crate::interface;
use crate::mechanism;
use crate::object;
use crate::{cast_params, err_rv};

use attribute::{from_bool, from_bytes, from_ulong};
use error::{KError, KResult};
use interface::*;
use mechanism::*;
use object::{Object, ObjectFactories};
use crate::bytes_to_vec;

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    PBKDF2Mechanism::register_mechanisms(mechs);
}

#[derive(Debug)]
struct PBKDF2Mechanism {
    info: CK_MECHANISM_INFO,
}

impl PBKDF2Mechanism {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_PKCS5_PBKD2,
            Box::new(PBKDF2Mechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: std::u32::MAX as CK_ULONG,
                    flags: CKF_GENERATE,
                },
            }),
        );
    }

    fn mock_password_object(&self, key: Vec<u8>) -> KResult<Object> {
        let mut obj = Object::new();
        obj.set_zeroize();
        obj.set_attr(from_ulong(CKA_CLASS, CKO_SECRET_KEY))?;
        obj.set_attr(from_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET))?;
        obj.set_attr(from_ulong(CKA_VALUE_LEN, key.len() as CK_ULONG))?;
        obj.set_attr(from_bytes(CKA_VALUE, key))?;
        obj.set_attr(from_bool(CKA_DERIVE, true))?;
        Ok(obj)
    }
}

impl Mechanism for PBKDF2Mechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn generate_key(
        &self,
        mech: &CK_MECHANISM,
        template: &[CK_ATTRIBUTE],
        _mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> KResult<Object> {
        if self.info.flags & CKF_GENERATE != CKF_GENERATE {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        if mech.mechanism != CKM_PKCS5_PBKD2 {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        let params = cast_params!(mech, CK_PKCS5_PBKD2_PARAMS2);
        if params.pPrfData != std::ptr::null_mut() || params.ulPrfDataLen != 0 {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }

        let pbkdf2 = PBKDF2 {
            prf: match params.prf {
                CKP_PKCS5_PBKD2_HMAC_SHA1 => "sha1",
                CKP_PKCS5_PBKD2_HMAC_SHA224 => "sha224",
                CKP_PKCS5_PBKD2_HMAC_SHA256 => "sha256",
                CKP_PKCS5_PBKD2_HMAC_SHA384 => "sha384",
                CKP_PKCS5_PBKD2_HMAC_SHA512 => "sha512",
                _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
            },
            pass: self.mock_password_object(bytes_to_vec!(
                params.pPassword,
                params.ulPasswordLen
            ))?,
            salt: match params.saltSource {
                CKZ_SALT_SPECIFIED => {
                    if params.pSaltSourceData == std::ptr::null_mut()
                        || params.ulSaltSourceDataLen == 0
                    {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                    bytes_to_vec!(
                        params.pSaltSourceData,
                        params.ulSaltSourceDataLen
                    )
                }
                _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
            },
            iter: params.iterations as u32,
        };

        let factory = objfactories.get_obj_factory_from_key_template(template)?;

        let keylen = match template.iter().find(|x| x.type_ == CKA_VALUE_LEN) {
            Some(a) => a.to_ulong()? as usize,
            None => 32, // Default to 32 bytes (256 bits) if not specified
        };

        let dkm = pbkdf2.derive(keylen)?;

        let mut tmpl = template.to_vec();
        tmpl.push(CK_ATTRIBUTE::from_slice(CKA_VALUE, dkm.as_slice()));

        let mut key = factory.create(tmpl.as_slice())?;
        object::default_key_attributes(&mut key, mech.mechanism)?;
        Ok(key)
    }
}

#[derive(Debug)]
struct PBKDF2 {
    prf: &'static str,
    pass: Object,
    salt: Vec<u8>,
    iter: u32,
}

impl PBKDF2 {
    fn derive(&self, dklen: usize) -> KResult<Vec<u8>> {
        let mut dkm = vec![0u8; dklen];

        match self.prf {
            "sha1"      => pbkdf2_hmac::<Sha1>(&self.pass.get_attr_as_bytes(CKA_VALUE)?, &self.salt, self.iter, &mut dkm),
            "sha224"    => pbkdf2_hmac::<Sha224>(&self.pass.get_attr_as_bytes(CKA_VALUE)?, &self.salt, self.iter, &mut dkm),
            "sha256"    => pbkdf2_hmac::<Sha256>(&self.pass.get_attr_as_bytes(CKA_VALUE)?, &self.salt, self.iter, &mut dkm),
            "sha384"    => pbkdf2_hmac::<Sha384>(&self.pass.get_attr_as_bytes(CKA_VALUE)?, &self.salt, self.iter, &mut dkm),
            "sha512"    => pbkdf2_hmac::<Sha512>(&self.pass.get_attr_as_bytes(CKA_VALUE)?, &self.salt, self.iter, &mut dkm),
            _           => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
        }

        Ok(dkm)
    }
}
