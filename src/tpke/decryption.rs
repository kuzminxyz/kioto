use std::num::NonZeroUsize;
use ark_ec::hashing::{HashToCurve, HashToCurveError};

use crate::tpke::{EncryptionKey, EncryptionOutput, PairingExt};
use super::DOMAIN;


pub struct Decryptor<CRV: PairingExt> {
    /// Minimal number of shares to decrypt message.
    threshold: NonZeroUsize,
    _curve: core::marker::PhantomData<CRV>,
}

pub struct DecryptionShare<CRV>{

}

/// Error occurs during [Decryptor::decrypt]
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("")]
    InsufficientShares {
        provided: usize,
       threshold: usize,
    },

    #[error("hash to curve: {0}")]
    HashToCurve(#[from] HashToCurveError),

}

impl<CRV: PairingExt> Decryptor<CRV> {
    pub fn decrypt(&self, encryted: EncryptionOutput<CRV>, shares: &[DecryptionShare<CRV>]) -> Result<(), Error>{
        if shares.len() < self.threshold.get(){
            return Err(Error::InsufficientShares { provided: shares.len(), threshold: self.threshold.get() });
        }
        let h = CRV::MapToG1Hasher::new(DOMAIN.as_bytes())?.hash(encryted.w.as_slice())?;

        todo!()
    }
}
