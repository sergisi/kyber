use core::convert::TryInto;

use rand_core::{CryptoRng, RngCore};

use crate::{
    indcpa::{gen_a, gen_at},
    poly::poly_getnoise_eta1,
    polyvec::{Polymat, Polyvec},
    rng::randombytes,
    symmetric::hash_g,
    KyberError, KYBER_K, KYBER_SYMBYTES,
};

#[derive(Debug)]
pub struct GenState {
    publicseed: [u8; KYBER_SYMBYTES],
    noiseseed: [u8; KYBER_SYMBYTES],
    nonce: u8,
}

impl GenState {
    pub fn new<R>(_rng: &mut R) -> Result<Self, KyberError>
    where
        R: RngCore + CryptoRng,
    {
        let mut buf = [0u8; 2 * KYBER_SYMBYTES];
        let mut randbuf = [0u8; 2 * KYBER_SYMBYTES];
        randombytes(&mut randbuf, KYBER_SYMBYTES, _rng)?;
        hash_g(&mut buf, &randbuf, KYBER_SYMBYTES);
        let (publicseed, noiseseed): (&[u8], &[u8]) = buf.split_at(KYBER_SYMBYTES);
        let closure = |_| KyberError::RandomBytesGeneration;
        return Ok(GenState {
            publicseed: publicseed.try_into().map_err(closure)?,
            noiseseed: noiseseed.try_into().map_err(closure)?,
            nonce: 0_u8,
        });
    }

    pub fn gen_small_polyvec(self: &mut Self) -> Polyvec {
        let mut s = Polyvec::new();
        for i in 0..KYBER_K {
            poly_getnoise_eta1(&mut s.vec[i], &self.noiseseed, self.nonce);
            self.nonce += 1;
        }
        s.ntt();
        return s;
    }

    pub fn gen_matrix_a(self: Self) -> Polymat {
        let mut a = [Polyvec::new(); KYBER_K];
        gen_a(&mut a, &self.publicseed);
        Polymat { vec: a }
    }

    pub fn gen_matrix_at(self: Self) -> Polymat {
        let mut a = [Polyvec::new(); KYBER_K];
        gen_at(&mut a, &self.publicseed);
        Polymat { vec: a }
    }
}
