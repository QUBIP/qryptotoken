use aes_gcm::{aead::{Aead, KeyInit, OsRng}, AeadCore, Aes128Gcm, Aes256Gcm, Key, Nonce};
use zeroize::Zeroize;

use crate::attribute;
use crate::error;
use crate::interface;
use crate::object;
use crate::{cast_params, attr_element, err_rv, bytes_to_vec};

use crate::attribute::{from_bytes, from_bool, from_ulong};
use crate::error::{KError, KResult};
use interface::*;
use crate::object::{
    CommonKeyFactory, OAFlags, Object, ObjectAttr, ObjectFactories,
    ObjectFactory, ObjectType, SecretKeyFactory,
};

use crate::mechanism;
use mechanism::*;

use once_cell::sync::Lazy;
use std::fmt::Debug;

pub const MIN_AES_SIZE_BYTES: usize = 16; /* 128 bits */
pub const MID_AES_SIZE_BYTES: usize = 32; /* 192 bits -> 256 as there is no 192 rust implementation */
pub const MAX_AES_SIZE_BYTES: usize = 32; /* 256 bits */
pub const AES_BLOCK_SIZE: usize = 16;

fn check_key_len(len: usize) -> KResult<()> {
    match len {
        16 | 32 => Ok(()),
        _ => err_rv!(CKR_KEY_SIZE_RANGE),
    }
}

#[derive(Debug)]
pub struct AesKeyFactory {
    attributes: Vec<ObjectAttr>,
}

impl AesKeyFactory {
    fn new() -> AesKeyFactory {
        let mut data: AesKeyFactory = AesKeyFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes.append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes.append(&mut data.init_common_secret_key_attrs());
        data.attributes.push(attr_element!(CKA_VALUE; OAFlags::Defval | OAFlags::Sensitive | OAFlags::RequiredOnCreate | OAFlags::SettableOnlyOnCreate; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_VALUE_LEN; OAFlags::RequiredOnGenerate; from_bytes; val Vec::new()));

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

impl ObjectFactory for AesKeyFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template)?;
        let len = self.get_key_buffer_len(&obj)?;
        check_key_len(len)?;
        if !obj.check_or_set_attr(from_ulong(CKA_VALUE_LEN, len as CK_ULONG))? {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    fn export_for_wrapping(&self, key: &Object) -> KResult<Vec<u8>> {
        SecretKeyFactory::export_for_wrapping(self, key)
    }

    fn import_from_wrapped(
        &self,
        mut data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        /* AES keys can only be 16, (not for Rust implementation 24), 32 bytes long,
         * ensure we allow only these sizes */
         match template.iter().position(|x| x.type_ == CKA_VALUE_LEN) {
            Some(idx) => {
                let len = template[idx].to_ulong()? as usize;
                if len > data.len() {
                    data.zeroize();
                    return err_rv!(CKR_KEY_SIZE_RANGE);
                }
                if len < data.len() {
                    unsafe { data.set_len(len) };
                }
            }
            None => (),
        }
        match check_key_len(data.len()) {
            Ok(_) => (),
            Err(e) => {
                data.zeroize();
                return Err(e);
            }
        }
        SecretKeyFactory::import_from_wrapped(self, data, template)
    }

    fn default_object_derive(
            &self,
            template: &[CK_ATTRIBUTE],
            origin: &Object,
        ) -> KResult<Object> {
            let obj = self.internal_object_derive(template, origin)?;

            let key_len = self.get_key_len(&obj);
            if key_len != 0 {
                if check_key_len(key_len).is_err() {
                    return err_rv!(CKR_TEMPLATE_INCONSISTENT);
                }
            }
            Ok(obj)
        }

    fn as_secret_key_factory(&self) -> KResult<&dyn SecretKeyFactory> {
        Ok(self)
    }
}

impl CommonKeyFactory for AesKeyFactory {}

impl SecretKeyFactory for AesKeyFactory {
    fn default_object_unwrap(
            &self,
            template: &[CK_ATTRIBUTE],
        ) -> KResult<Object> {
            ObjectFactory::default_object_unwrap(self, template)
        }

    fn set_key(&self, obj: &mut Object, key: Vec<u8>) -> KResult<()> {
        let keylen = key.len();
        check_key_len(keylen)?;
        obj.set_attr(from_bytes(CKA_VALUE, key))?;
        self.set_key_len(obj, keylen)?;
        Ok(())
    }

    fn recommend_key_size(&self, max: usize) -> KResult<usize> {
        if max >= MAX_AES_SIZE_BYTES {
            Ok(MAX_AES_SIZE_BYTES)
        } else if max > MID_AES_SIZE_BYTES {
            Ok(MID_AES_SIZE_BYTES)
        } else if max > MIN_AES_SIZE_BYTES {
            Ok(MIN_AES_SIZE_BYTES)
        } else {
            err_rv!(CKR_KEY_SIZE_RANGE)
        }
    }
}

static AES_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(AesKeyFactory::new()));

#[derive(Debug)]
struct AesMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for AesMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn encryption_new(
            &self,
            mech: &CK_MECHANISM,
            key: &Object,
        ) -> KResult<Box<dyn Encryption>> {
            if self.info.flags & CKF_ENCRYPT != CKF_ENCRYPT {
                return err_rv!(CKR_MECHANISM_INVALID);
            }
            match key.check_key_ops(CKO_SECRET_KEY, CKK_AES, CKA_ENCRYPT) {
                Ok(_) => (),
                Err(e) => return Err(e),
            }
            Ok(Box::new(AesOperation::encrypt_new(mech, key)?))
        }

    fn decryption_new(
            &self,
            mech: &CK_MECHANISM,
            key: &Object,
        ) -> KResult<Box<dyn Decryption>> {
            if self.info.flags & CKF_DECRYPT != CKF_DECRYPT {
                return err_rv!(CKR_MECHANISM_INVALID);
            }
            match key.check_key_ops(CKO_SECRET_KEY, CKK_AES, CKA_DECRYPT) {
                Ok(_) => (),
                Err(e) => return Err(e),
            }
            Ok(Box::new(AesOperation::decrypt_new(mech, key)?))
        }
    
    fn generate_key(
            &self,
            mech: &CK_MECHANISM,
            template: &[CK_ATTRIBUTE],
            _: &Mechanisms,
            _: &ObjectFactories,
        ) -> KResult<Object> {
            if mech.mechanism != CKM_AES_KEY_GEN {
                return err_rv!(CKR_MECHANISM_INVALID);
            }
            let mut key = AES_KEY_FACTORY.default_object_generate(template)?;
            if !key.check_or_set_attr(attribute::from_ulong(
                CKA_CLASS,
                CKO_SECRET_KEY,
            ))? {
                return err_rv!(CKR_TEMPLATE_INCONSISTENT);
            }
            if !key
                .check_or_set_attr(attribute::from_ulong(CKA_KEY_TYPE, CKK_AES))?
            {
                return err_rv!(CKR_TEMPLATE_INCONSISTENT);
            }
    
            object::default_secret_key_generate(&mut key)?;
            object::default_key_attributes(&mut key, mech.mechanism)?;
            Ok(key) 
        }

    fn wrap_key(
            &self,
            mech: &CK_MECHANISM,
            wrapping_key: &Object,
            key: &Object,
            data: CK_BYTE_PTR,
            data_len: CK_ULONG_PTR,
            key_template: &Box<dyn ObjectFactory>,
        ) -> KResult<()> {
            if self.info.flags & CKF_WRAP != CKF_WRAP {
                return err_rv!(CKR_MECHANISM_INVALID);
            }
    
            AesOperation::wrap(
                mech,
                wrapping_key,
                key_template.export_for_wrapping(key)?,
                data,
                data_len,
            )
        }

    fn unwrap_key(
            &self,
            mech: &CK_MECHANISM,
            wrapping_key: &Object,
            data: &[u8],
            template: &[CK_ATTRIBUTE],
            key_template: &Box<dyn ObjectFactory>,
        ) -> KResult<Object> {
            if self.info.flags & CKF_UNWRAP != CKF_UNWRAP {
                return err_rv!(CKR_MECHANISM_INVALID);
            }
            let keydata = AesOperation::unwrap(mech, wrapping_key, data)?;
            key_template.import_from_wrapped(keydata, template)
        }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    AesOperation::register_mechanisms(mechs);

    ot.add_factory(ObjectType::new(CKO_SECRET_KEY, CKK_AES), &AES_KEY_FACTORY);
}

#[derive(Debug)]
struct AesKey {
    raw: Vec<u8>,
}

impl Drop for AesKey {
    fn drop(&mut self) {
        self.raw.zeroize()
    }
}

fn object_to_raw_key(key: &Object) -> KResult<AesKey> {
    let val = key.get_attr_as_bytes(CKA_VALUE)?;
    check_key_len(val.len())?;
    Ok(AesKey { raw: val.clone() })
}


fn new_mechanism(flags: CK_FLAGS) -> Box<dyn Mechanism> {
    Box::new(AesMechanism {
        info: CK_MECHANISM_INFO {
            ulMinKeySize: MIN_AES_SIZE_BYTES as CK_ULONG,
            ulMaxKeySize: MAX_AES_SIZE_BYTES as CK_ULONG,
            flags: flags,
        },
    })
}


#[derive(Debug)]
struct AesParams {
    iv: Vec<u8>,
    aad: Vec<u8>,
    taglen: usize,
}

#[derive(Debug)]
struct AesOperation {
    mech: CK_MECHANISM_TYPE,
    key: AesKey,
    params: AesParams,
    finalized: bool,
    in_use: bool,
    finalbuf: Vec<u8>,
}

impl Drop for AesOperation {
    fn drop(&mut self) {
        self.finalbuf.zeroize()
    }
}

enum AesGcmCipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

impl AesOperation {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[
            CKM_AES_GCM,
            CKM_AES_KEY_WRAP,
            CKM_AES_KEY_WRAP_KWP,
        ] {
            mechs.add_mechanism(
                *ckm,
                new_mechanism(
                    CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
                ),
            );
        }

        mechs.add_mechanism(CKM_AES_KEY_GEN, new_mechanism(CKF_GENERATE));
    }

    fn init_params(mech: &CK_MECHANISM) -> KResult<AesParams> {
        match mech.mechanism {
            #[cfg(False)]
            CKM_AES_CCM => {
                let params = cast_params!(mech, CK_CCM_PARAMS);
                if params.ulNonceLen < 7 || params.ulNonceLen > 13 {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                let l = 15 - params.ulNonceLen;
                if params.ulDataLen == 0
                    || params.ulDataLen > (1 << (8 * l))
                    || (params.ulDataLen + params.ulMACLen)
                        > u64::MAX as CK_ULONG
                {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if params.ulAADLen > (u32::MAX - 1) as CK_ULONG {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                match params.ulMACLen {
                    4 | 6 | 8 | 10 | 12 | 14 | 16 => (),
                    _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
                }
                Ok(AesParams {
                    iv: bytes_to_vec!(params.pNonce, params.ulNonceLen),
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: params.ulDataLen as usize,
                    aad: bytes_to_vec!(params.pAAD, params.ulAADLen),
                    taglen: params.ulMACLen as usize,
                })
            }
            CKM_AES_GCM => {
                let params = cast_params!(mech, CK_GCM_PARAMS);
                if params.ulIvLen == 0 || params.ulIvLen > (1 << 32) - 1 {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if params.ulAADLen > (1 << 32) - 1 {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if params.ulTagBits > 128 {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if params.ulIvLen < 1 || params.pIv == std::ptr::null_mut() {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                Ok(AesParams {
                    iv: bytes_to_vec!(params.pIv, params.ulIvLen),
                    //maxblocks: 0,
                    //ctsmode: 0,
                    //datalen: 0,
                    aad: bytes_to_vec!(params.pAAD, params.ulAADLen),
                    taglen: (params.ulTagBits as usize + 7) / 8,
                })
            }
            #[cfg(False)]
            CKM_AES_CTR => {
                let params = cast_params!(mech, CK_AES_CTR_PARAMS);
                let iv = params.cb.to_vec();
                let ctrbits = params.ulCounterBits as usize;
                let mut maxblocks = 0u128;
                if ctrbits < (AES_BLOCK_SIZE * 8) {
                    /* FIXME: support arbitrary counterbits wrapping.
                     * OpenSSL CTR mode is built to handle the whole IV
                     * as a 128bit counter unconditionally.
                     * For callers that want a smaller counterbit size all
                     * we can do is to set a maximum number of blocks so
                     * that the counter space does *not* wrap (because
                     * openssl won't wrap it but proceed to increment the
                     * octets part of the IV/Nonce). This means that for
                     * applications that initialize the counter to a value
                     * like 1 all will be fine, but application that
                     * initialize the counter to a random value and expect
                     * wrapping will see a failure instead of wrapping */
                    maxblocks = (1 << ctrbits) - 1;
                    let fulloctects = ctrbits / 8;
                    let mut idx = 0;
                    while fulloctects > idx {
                        maxblocks -= (iv[15 - idx] as u128) << (idx * 8);
                        idx += 1;
                    }
                    let part = ctrbits % 8;
                    if part > 0 {
                        maxblocks -= ((iv[15 - idx] as u128) & (part as u128))
                            << (idx * 8);
                    }
                    if maxblocks == 0 {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                } else if ctrbits > (AES_BLOCK_SIZE * 8) {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }

                Ok(AesParams {
                    iv: iv,
                    maxblocks: maxblocks,
                    ctsmode: 0,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            #[cfg(False)]
            CKM_AES_CTS | CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if mech.ulParameterLen != (AES_BLOCK_SIZE as CK_ULONG) {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                let mut ctsmode = 0u8;
                if mech.mechanism == CKM_AES_CTS {
                    ctsmode = 1u8;
                }
                Ok(AesParams {
                    iv: bytes_to_vec!(mech.pParameter, mech.ulParameterLen),
                    maxblocks: 0,
                    ctsmode: ctsmode,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            #[cfg(False)]
            CKM_AES_ECB => Ok(AesParams {
                iv: Vec::with_capacity(0),
                maxblocks: 0,
                ctsmode: 0,
                datalen: 0,
                aad: Vec::new(),
                taglen: 0,
            }),
            #[cfg(False)]
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                if mech.ulParameterLen != (AES_BLOCK_SIZE as CK_ULONG) {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                Ok(AesParams {
                    iv: bytes_to_vec!(mech.pParameter, mech.ulParameterLen),
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            #[cfg(False)]
            CKM_AES_KEY_WRAP => {
                let iv = match mech.ulParameterLen {
                    0 => Vec::new(),
                    8 => bytes_to_vec!(mech.pParameter, mech.ulParameterLen),
                    _ => return err_rv!(CKR_ARGUMENTS_BAD),
                };
                Ok(AesParams {
                    iv: iv,
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            #[cfg(False)]
            CKM_AES_KEY_WRAP_KWP => {
                let iv = match mech.ulParameterLen {
                    0 => Vec::new(),
                    4 => bytes_to_vec!(mech.pParameter, mech.ulParameterLen),
                    _ => return err_rv!(CKR_ARGUMENTS_BAD),
                };
                Ok(AesParams {
                    iv: iv,
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }

    #[cfg(False)]
    fn init_cipher(
        mech: CK_MECHANISM_TYPE,
        key: &[u8],
    ) -> KResult<AesGcmCipher> {todo!()}

    fn encrypt_new(mech: &CK_MECHANISM, key: &Object) -> KResult<AesOperation> {
        Ok(AesOperation {
            mech: mech.mechanism,
            key: object_to_raw_key(key)?,
            params: Self::init_params(mech)?,
            finalized: false,
            in_use: false,
            //ctx: EvpCipherCtx::new()?,
            finalbuf: Vec::new(),
            //blockctr: 0,
        })
    }

    fn decrypt_new(mech: &CK_MECHANISM, key: &Object) -> KResult<AesOperation> {todo!()} 

    fn wrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        mut keydata: Vec<u8>,
        output: CK_BYTE_PTR,
        output_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        let mut op = match Self::encrypt_new(mech, wrapping_key) {
            Ok(o) => o,
            Err(e) => {
                keydata.zeroize();
                return Err(e);
            }
        };

        match mech.mechanism {
            #[cfg(False)]
            CKM_AES_CBC | CKM_AES_ECB => {
                /* non-padding block modes needs 0 padding for the input */
                let pad = keydata.len() % AES_BLOCK_SIZE;
                if pad != 0 {
                    keydata.resize(keydata.len() + AES_BLOCK_SIZE - pad, 0);
                }
            }
            #[cfg(False)]
            CKM_AES_CCM => {
                /* Check the data length in CCM matches the provided data -- this is one-shot
                 * operation only */
                if op.params.datalen != keydata.len() {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
            }
            _ => (),
        }
        let result = op.encrypt(&keydata, output, output_len);
        keydata.zeroize();
        result
    }
    
    fn unwrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        data: &[u8],
    ) -> KResult<Vec<u8>> {
        let mut op = Self::decrypt_new(mech, wrapping_key)?;
        let mut result = vec![0u8; data.len()];
        let mut len = result.len() as CK_ULONG;
        op.decrypt(data, result.as_mut_ptr(), &mut len)?;
        unsafe { result.set_len(len as usize) };
        Ok(result)
    }
}

impl MechOperation for AesOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Encryption for AesOperation {
    fn encrypt(
        &mut self,
        plain: &[u8],
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if cipher_len.is_null() {
            return err_rv!(CKR_ARGUMENTS_BAD);
        }
        
        let mut outlen = self.encryption_len(plain.len() as u64)?;
        
        if cipher.is_null() {
            unsafe {
                *cipher_len = outlen as CK_ULONG;
            }
            return Ok(());
        }

        match self.mech {
            #[cfg(False)]
            CKM_AES_GCM => {
                todo!()
            }
            _ => (),
        }
        if unsafe { *cipher_len as usize } < outlen {
            /* This is the only, non-fatal error */
            unsafe { *cipher_len = outlen as CK_ULONG };
            return err_rv!(CKR_BUFFER_TOO_SMALL);
        }
        
        let mut plain_buf = plain.as_ptr();
        let mut plain_len = plain.len();

        let key = self.key.raw.as_slice();
        let key: &Key<Aes256Gcm> = key.into();
        let ctx = Aes256Gcm::new(key.into());
        // Forcing to 12 bytes because of aes-gcm expects that
        let nonce = &self.params.iv[..12];
        let payload = plain;
        let ciphertext = ctx.encrypt(nonce.into(),payload);
        match ciphertext {
            Ok(ct) => {
                let ct_buf = ct.as_ptr();
                let ct_len = ct.len();
                // Safe to dereference cipher_len as we checked it's not null
                let out_len = unsafe{*cipher_len as usize};
                assert!(ct_len <= out_len);
                unsafe 
                {
                std::ptr::copy_nonoverlapping(ct_buf, cipher, ct_len);
                }

            },
            Err(e) => todo!("return error"),
        }

        Ok(())
    }

    fn encryption_len(&self, data_len: CK_ULONG) -> KResult<usize> {
        let len: usize = match self.mech {
            CKM_AES_GCM => data_len as usize + self.params.taglen,
            _ => return err_rv!(CKR_GENERAL_ERROR),
        };
        Ok(len)
    }
}

impl Decryption for AesOperation {
    fn decrypt(
            &mut self,
            _cipher: &[u8],
            _plain: CK_BYTE_PTR,
            _plain_len: CK_ULONG_PTR,
        ) -> KResult<()> {todo!()}

    fn decryption_len(&self, _data_len: CK_ULONG) -> KResult<usize> {todo!()}
}