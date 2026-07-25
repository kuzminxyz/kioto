use ark_ec::{
    CurveGroup,
    hashing::{HashToCurve, HashToCurveError},
};
use ark_ff::Field;
use std::{
    collections::BTreeSet,
    num::NonZeroUsize,
    ops::{Div, Mul, Sub},
};

use super::DOMAIN;
use crate::{
    Share, tpke::{EncryptionOutput, PairingExt, encryption::{XorError, xor_message}},
};

pub struct Decryptor<CRV: PairingExt> {
    /// Minimal number of shares to decrypt message.
    threshold: NonZeroUsize,
    _curve: core::marker::PhantomData<CRV>,
}

pub struct DecryptionContext<F: Field> {
    pub secret_share: Share<F>,
    pub other_domains: Vec<F>,
}

impl<F: Field> DecryptionContext<F> {
    pub fn create_share<G>(&self, u: G) -> DecryptionShare<G>
    where
        G: CurveGroup<ScalarField = F>,
    {
        let mut product = G::ScalarField::ONE;
        self.other_domains.iter().for_each(|x_j| {
            let denominator = x_j.sub(self.secret_share.x);
            product = product.mul(x_j.div(denominator));
        });
        DecryptionShare(u.mul(product.mul(self.secret_share.y)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptionShare<G: CurveGroup>(pub G);

/// Error occurs during [Decryptor::decrypt]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("")]
    InsufficientShares { provided: usize, threshold: usize },

    #[error("hash to curve: {0}")]
    HashToCurve(#[from] HashToCurveError),

    #[error(transparent)]
    XorError(#[from] XorError)
}

impl<CRV: PairingExt> Decryptor<CRV> {
    pub fn decrypt(
        &self,
        encryted: EncryptionOutput<CRV>,
        shares: &[DecryptionShare<CRV::G2>],
    ) -> Result<(), Error> {
        if shares.len() < self.threshold.get() {
            return Err(Error::InsufficientShares {
                provided: shares.len(),
                threshold: self.threshold.get(),
            });
        }
        let h = CRV::MapToG1Hasher::new(DOMAIN.as_bytes())?.hash(encryted.w.as_slice())?;
        let c = shares.iter().map(|share| share.0).sum::<CRV::G2>();
        let symmetric_key = CRV::pairing(h, c.into_affine());

        let mut message = encryted.ciphertext.clone();
        Ok(xor_message(&mut message, &symmetric_key)?)
    }
}
