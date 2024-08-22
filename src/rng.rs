// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(not(feature = "pure-rust"))]
use {
    super::drbg,
    super::err_rv,
    super::interface,
    super::mechanism,

    interface::*,
    error::KError,
};

#[cfg(feature = "pure-rust")]
use {
    rand::rngs::StdRng,
    rand::{Rng as StdRngTrait, SeedableRng},
};

use super::error;
use error::KResult;

#[derive(Debug)]
pub struct RNG {
    #[cfg(not(feature = "pure-rust"))]
    drbg: Box<dyn mechanism::DRBG>,

    #[cfg(feature = "pure-rust")]
    std_rng: StdRng,
}

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
        Ok(RNG {
            std_rng: StdRng::from_entropy(),
        })
    }

    pub fn generate_random(&mut self, buffer: &mut [u8]) -> KResult<()> {
        #[cfg(not(feature = "pure-rust"))]
        {
            let noaddtl: [u8; 0] = [];
            self.drbg.generate(&noaddtl, buffer)
        }

        #[cfg(feature = "pure-rust")]
        {
            self.std_rng.fill(buffer);
            Ok(())
        }
    }
}
