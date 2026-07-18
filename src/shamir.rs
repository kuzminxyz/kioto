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
}

/// Participant's secret part: `y = f(x)`.
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
        let secret = poly.evaluate(&F::from(0 as u64));

        let mut shares = Vec::with_capacity(participants.get());
        (0..participants.get()).into_iter().map(|idx| F::from(idx as u64 + 1)).for_each(|x| {
            let y = poly.evaluate(&x);
            shares.push(Share { x, y });
        });

        Ok(Self { secret, shares })
    }
}
