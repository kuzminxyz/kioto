use std::{
    collections::BTreeSet,
    num::NonZeroUsize,
    ops::{Div, Mul, Sub},
};

use ark_ec::{
    CurveGroup,
    hashing::{HashToCurve, HashToCurveError},
};
use ark_serialize::SerializationError;
use ark_ff::Field;

use super::DOMAIN;
use crate::{
    Share,
    tpke::{
        EncryptionOutput, PairingExt,
        encryption::{ xor_message},
    },
};

/// Error occurs during [Decryptor::decrypt]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("")]
    InsufficientShares { provided: usize, threshold: usize },

    #[error("hash to curve: {0}")]
    HashToCurve(#[from] HashToCurveError),

    #[error("arkworks serialization error: {0}")]
    Serialization(#[from] SerializationError),
}


/// Per-participant decryption context.
/// Its required for creating a [`DecryptionShare`].
pub struct DecryptionContext<F: Field> {
    /// Participant's private secret share.
    pub secret_share: Share<F>,
    /// Other participants domain points.
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

/// Publicly distributed decryption share.
///
/// Decryption share formula: `D = U * L_i`,
/// where `L_i` is a lagrange coefficient evaluated at `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptionShare<G: CurveGroup>(pub G);


pub struct Decryptor<CRV: PairingExt> {
    /// Minimal number of shares to decrypt message.
    threshold: NonZeroUsize,
    _curve: core::marker::PhantomData<CRV>,
}

impl<CRV: PairingExt> Decryptor<CRV> {
    pub fn decrypt(
        &self,
        encrypted: EncryptionOutput<CRV>,
        shares: &[DecryptionShare<CRV::G2>],
    ) -> Result<(), Error> {
        if shares.len() < self.threshold.get() {
            return Err(Error::InsufficientShares {
                provided: shares.len(),
                threshold: self.threshold.get(),
            });
        }

        let h = CRV::MapToG1Hasher::new(DOMAIN.as_bytes())?.hash(encrypted.w.as_slice())?;
        let c = shares.iter().map(|share| share.0).sum::<CRV::G2>();
        let symmetric_key = CRV::pairing(h, c.into_affine());

        let mut message = encrypted.ciphertext.clone();
        xor_message(&mut message, &symmetric_key)?;
        if blake3::hash(&message) != encrypted.w {
            todo!()
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use ark_bls12_381::{Fr, G2Projective};
    use ark_ec::{hashing::HashToCurve, pairing::Pairing};
    use ark_std::test_rng;

    use super::*;
    use crate::{
        Scheme,
        tpke::{
            encryption::{Encryptor, ThresholdPublicKey},
            test_curve::Curve,
        },
    };

    const PARTICIPANTS: usize = 5;
    const THRESHOLD: usize = 3;

    fn nz(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    fn decryptor() -> Decryptor<Curve> {
        Decryptor { threshold: nz(THRESHOLD), _curve: PhantomData }
    }

    /// Deals a `THRESHOLD`-of-`PARTICIPANTS` scheme and encrypts `message` under the
    /// public key `secret * g2`, returning the dealt shares and the ciphertext.
    fn deal_and_encrypt(message: Vec<u8>) -> (Scheme<Fr>, EncryptionOutput<Curve>) {
        let mut rng = test_rng();
        let scheme = Scheme::generate(nz(PARTICIPANTS), nz(THRESHOLD), &mut rng).unwrap();
        let public_key = ThresholdPublicKey::from_scalar(scheme.secret);
        let output = Encryptor::<Curve>::new(public_key).encrypt(message, &mut rng).unwrap();
        (scheme, output)
    }

    /// Turns a chosen subset of Shamir shares into decryption shares against `u`.
    /// Each context carries the other subset members' x-coordinates so its
    /// `create_share` bakes in the Lagrange coefficient for this reconstruction set.
    fn decryption_shares(
        u: G2Projective,
        subset: &[Share<Fr>],
    ) -> Vec<DecryptionShare<G2Projective>> {
        subset
            .iter()
            .map(|share| {
                let other_domains = subset.iter().filter(|o| o.x != share.x).map(|o| o.x).collect();
                DecryptionContext { secret_share: *share, other_domains }.create_share(u)
            })
            .collect()
    }

    /// Mirrors `Decryptor::decrypt`'s internal computation to obtain the plaintext,
    /// which the public method itself does not currently return.
    fn recover_plaintext(
        output: &EncryptionOutput<Curve>,
        shares: &[DecryptionShare<G2Projective>],
    ) -> Vec<u8> {
        let h = <Curve as PairingExt>::MapToG1Hasher::new(DOMAIN.as_bytes())
            .unwrap()
            .hash(output.w.as_slice())
            .unwrap();
        let c = shares.iter().map(|s| s.0).sum::<G2Projective>();
        let key = Curve::pairing(h, c.into_affine());
        let mut message = output.ciphertext.clone();
        xor_message::<Curve>(&mut message, &key).unwrap();
        message
    }

    #[test]
    fn decrypt_rejects_insufficient_shares() {
        let (scheme, output) = deal_and_encrypt(b"secret tx".to_vec());
        // Only THRESHOLD - 1 shares supplied.
        let shares = decryption_shares(output.u, &scheme.shares[..THRESHOLD - 1]);

        let result = decryptor().decrypt(output, &shares);
        assert!(matches!(
            result,
            Err(Error::InsufficientShares { provided, threshold })
                if provided == THRESHOLD - 1 && threshold == THRESHOLD
        ));
    }

    #[test]
    fn decrypt_succeeds_with_threshold_shares() {
        let (scheme, output) = deal_and_encrypt(b"secret tx".to_vec());
        let shares = decryption_shares(output.u, &scheme.shares[..THRESHOLD]);

        // Exercises hash-to-curve, share aggregation, pairing and XOR without panicking.
        assert!(decryptor().decrypt(output, &shares).is_ok());
    }

    #[test]
    fn aggregated_shares_reconstruct_secret_times_u() {
        let (scheme, output) = deal_and_encrypt(b"secret tx".to_vec());
        let shares = decryption_shares(output.u, &scheme.shares[..THRESHOLD]);

        // Σ D_i should equal `r * s * g2 == secret * U`, the scalar the decryptor
        // needs to rebuild the symmetric key. This checks the Lagrange logic in
        // `DecryptionContext::create_share` at the group level, without the pairing.
        let c = shares.iter().map(|s| s.0).sum::<G2Projective>();
        assert_eq!(c, output.u.mul(scheme.secret));
    }

    #[test]
    fn shares_reconstruct_symmetric_key_and_recover_plaintext() {
        let message = b"anti-mev transaction".to_vec();
        let (scheme, output) = deal_and_encrypt(message.clone());
        let shares = decryption_shares(output.u, &scheme.shares[..THRESHOLD]);

        assert_eq!(recover_plaintext(&output, &shares), message);
    }

    #[test]
    fn recovers_plaintext_from_scattered_shares() {
        let message = b"anti-mev transaction".to_vec();
        let (scheme, output) = deal_and_encrypt(message.clone());
        // A non-contiguous subset exercises Lagrange with scattered x-coordinates.
        let subset = [scheme.shares[0], scheme.shares[2], scheme.shares[4]];
        let shares = decryption_shares(output.u, &subset);

        assert_eq!(recover_plaintext(&output, &shares), message);
    }

    #[test]
    fn recovers_plaintext_with_more_than_threshold_shares() {
        let message = b"anti-mev transaction".to_vec();
        let (scheme, output) = deal_and_encrypt(message.clone());
        // Four shares still interpolate the same degree-2 polynomial at 0.
        let shares = decryption_shares(output.u, &scheme.shares[..THRESHOLD + 1]);

        assert_eq!(recover_plaintext(&output, &shares), message);
    }
}
