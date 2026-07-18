use ark_ff::Field;
use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DensePolynomial};
use ark_std::rand::Rng;
use core::num::NonZeroUsize;

/// Shamir's secret splitting scheme.
pub struct Scheme<F: Field> {
    /// Polynomial value at `0`.
    pub secret: F,
    /// Polynomial evaluations at `1..participants + 1` points.
    pub shares: Vec<Share<F>>,
    /// Scheme's threshold value.
    threshold: NonZeroUsize,
}

/// Participant's secret info: `y = f(x)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Share<F: Field> {
    pub x: F,
    pub y: F,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error(
        "threshold number exceeds participants: threshold={threshold}, participants={participants}"
    )]
    ThresholdExceedsParticipants { participants: NonZeroUsize, threshold: NonZeroUsize },

    #[error(
        "insufficient amount of shares to reconstruct secret: shares={shares}, threshold={threshold}"
    )]
    InsufficientNumberOfSharesToReconstructSecret { shares: usize, threshold: NonZeroUsize },

    #[error("shares contain duplicate x-coordinates")]
    DuplicateShareX,
}

impl<F: Field> Scheme<F> {
    /// Creates new [`Scheme`] with provided:
    /// - `threshold` - the minimum number of shares to reconstruct a secret
    /// - `participants` - the number of participants to generate shares for.
    pub fn new<R>(
        participants: NonZeroUsize,
        threshold: NonZeroUsize,
        rng: &mut R,
    ) -> Result<Self, Error>
    where
        R: Rng,
    {
        if threshold > participants {
            return Err(Error::ThresholdExceedsParticipants { participants, threshold });
        }

        // Polynomial degree `threshold - 1` allows `threshold` participants reconstruct a secret.
        let poly = DensePolynomial::<F>::rand(threshold.get() - 1, rng);
        let secret = poly.evaluate(&F::ZERO);

        let mut shares = Vec::with_capacity(participants.get());
        (0..participants.get()).into_iter().map(|idx| F::from(idx as u64 + 1)).for_each(|x| {
            let y = poly.evaluate(&x);
            shares.push(Share { x, y });
        });

        Ok(Self { secret, shares, threshold })
    }

    /// Reconstructs the secret using provided shares.
    pub fn reconstruct(&self, shares: &[Share<F>]) -> Result<F, Error> {
        if shares.len() < self.threshold.get() {
            return Err(Error::InsufficientNumberOfSharesToReconstructSecret {
                shares: shares.len(),
                threshold: self.threshold,
            });
        }

        // Distinct x-coordinates are required: a repeated `x` yields a zero denominator
        // (`x_m - x_j == 0`) during interpolation, which would panic on inversion.
        for (j, Share { x: x_j, .. }) in shares.iter().enumerate() {
            if shares[j + 1..].iter().any(|Share { x: x_m, .. }| x_m == x_j) {
                return Err(Error::DuplicateShareX);
            }
        }

        let mut secret = F::ZERO;
        shares.iter().enumerate().for_each(|(j, Share { x: x_j, y: y_j })| {
            let mut product = F::ONE;
            shares.iter().enumerate().for_each(|(m, Share { x: x_m, .. })| {
                if m != j {
                    let rhs = x_m.div(*x_m - *x_j);
                    product = product.mul(rhs);
                }
            });
            secret = secret.add(y_j.mul(product));
        });

        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    /// Builds a 5-participants, 3-threshold scheme over BLS12-381's base field.
    fn test_scheme() -> Scheme<ark_bls12_381::Fq> {
        Scheme::new(NonZeroUsize::new(5).unwrap(), NonZeroUsize::new(3).unwrap(), &mut test_rng())
            .unwrap()
    }

    #[test]
    fn reconstruct_secret() {
        let scheme = test_scheme();
        let shares = scheme.shares.clone().into_iter().take(3).collect::<Vec<_>>();
        let reconstructed_secret = scheme.reconstruct(&shares).unwrap();
        assert_eq!(scheme.secret, reconstructed_secret);
    }

    #[test]
    fn reconstruct_secret_from_scattered_shares() {
        let scheme = test_scheme();
        // Non-contiguous subset exercises Lagrange with scattered x-coordinates.
        let shares = vec![scheme.shares[0], scheme.shares[2], scheme.shares[4]];
        assert_eq!(scheme.secret, scheme.reconstruct(&shares).unwrap());
    }

    #[test]
    fn reconstruct_rejects_insufficient_shares() {
        let scheme = test_scheme();
        let shares = scheme.shares.clone().into_iter().take(2).collect::<Vec<_>>();
        assert!(matches!(
            scheme.reconstruct(&shares),
            Err(Error::InsufficientNumberOfSharesToReconstructSecret { .. })
        ));
    }

    #[test]
    fn reconstruct_rejects_duplicate_shares() {
        let scheme = test_scheme();
        // Same share repeated to satisfy the count check but with duplicate x-coordinates.
        let shares = vec![scheme.shares[0], scheme.shares[1], scheme.shares[1]];
        assert!(matches!(scheme.reconstruct(&shares), Err(Error::DuplicateShareX)));
    }
}
