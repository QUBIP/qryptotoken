// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms
use error::KError;

#[cfg(not(feature = "pure-rust"))]
use {
    super::drbg, super::err_rv, super::interface, super::mechanism,
    interface::*,
};

#[cfg(feature = "pure-rust")]
use drbg::thread::LocalCtrDrbg;

use super::error;
use error::KResult;

#[cfg(not(feature = "pure-rust"))]
#[derive(Debug)]
pub struct RNG {
    drbg: Box<dyn mechanism::DRBG>,
}

#[cfg(feature = "pure-rust")]
pub struct RNG {
    #[cfg(feature = "pure-rust")]
    drbg: LocalCtrDrbg,
}

#[cfg(feature = "pure-rust")]
impl std::fmt::Debug for RNG {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RNG")
            .field("drbg", &"<not inspectable>")
            .finish()
    }
}

impl aes_gcm::aead::rand_core::CryptoRng for RNG {}

// Implemented by following https://rust-random.github.io/rand/rand_core/trait.RngCore.html guidelines
impl aes_gcm::aead::rand_core::RngCore for RNG {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let mut ret: u64 = 0;
        // Safe because we are casting a u64 to a u8 slice of the same size
        // Declared a variable to hold the u64 value and using the standard library to
        // create a mutable byte slice (&mut [u8]) from a raw pointer to a u64 value
        let ret_as_bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                &mut ret as *mut u64 as *mut u8,
                std::mem::size_of::<u64>(),
            )
        };

        self.fill_bytes(ret_as_bytes);

        ret
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.drbg.fill_bytes(dst, None).expect("drbg failed")
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), aes_gcm::aead::rand_core::Error> {
        self.drbg
            .fill_bytes(dest, None)
            .map_err(|e| aes_gcm::aead::rand_core::Error::new(e))
    }
}

impl rand_core::RngCore for RNG {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let mut ret: u64 = 0;
        // Safe because we are casting a u64 to a u8 slice of the same size
        // Declared a variable to hold the u64 value and using the standard library to
        // create a mutable byte slice (&mut [u8]) from a raw pointer to a u64 value
        let ret_as_bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                &mut ret as *mut u64 as *mut u8,
                std::mem::size_of::<u64>(),
            )
        };

        self.fill_bytes(ret_as_bytes);

        ret
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.drbg.fill_bytes(dst, None).expect("drbg failed")
    }
}
impl rand_core::CryptoRng for RNG {}

impl RNG {
    #[cfg(not(feature = "pure-rust"))]
    pub fn new(alg: &str) -> KResult<RNG> {
        match alg {
            "HMAC DRBG SHA256" => Ok(RNG {
                drbg: Box::new(drbg::HmacSha256Drbg::new()?),
            }),
            "HMAC DRBG SHA512" => Ok(RNG {
                drbg: Box::new(drbg::HmacSha512Drbg::new()?),
            }),
            _ => err_rv!(CKR_RANDOM_NO_RNG),
        }
    }

    #[cfg(feature = "pure-rust")]
    pub fn new() -> KResult<RNG> {
        let drbg = LocalCtrDrbg::default();
        Ok(RNG { drbg })
    }

    pub fn generate_random(&mut self, buffer: &mut [u8]) -> KResult<()> {
        #[cfg(not(feature = "pure-rust"))]
        {
            let noaddtl: [u8; 0] = [];
            self.drbg.generate(&noaddtl, buffer)
        }

        #[cfg(feature = "pure-rust")]
        {
            self.drbg.fill_bytes(buffer, None).map_err(|e| {
                let _ = e;
                let ckrverror = crate::error::CkRvError {
                    rv: crate::interface::CKR_GENERAL_ERROR,
                };
                KError::RvError(ckrverror)
            })
        }
    }
}
