//! Shamir's Secret Sharing over an arbitrary prime field.
//!
//! A secret `s` is encoded as the constant term of a random degree-`t-1`
//! polynomial `f`, where `t` is the threshold. Each participant `i` receives the
//! share `(x_i, f(x_i))`. Any `t` distinct shares recover `s = f(0)` via Lagrange
//! interpolation, while any `t-1` shares reveal nothing about it.

use ark_ff::Field;
use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DensePolynomial};
use ark_std::rand::Rng;
use core::num::NonZeroUsize;

/// A dealt Shamir scheme: the secret together with the shares handed to participants.
pub struct Scheme<F: Field> {
    /// The secret, i.e. the polynomial's constant term `f(0)`.
    pub secret: F,
    /// One share per participant, evaluated at `x = 1..=participants`.
    pub shares: Vec<Share<F>>,
    /// Minimum number of distinct shares required to reconstruct [`Self::secret`].
    pub threshold: NonZeroUsize,
}

/// A single participant's share: the point `(x, y)` where `y = f(x)`.
///
/// Note that `x` must never be `0` — that point is the secret itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Share<F: Field> {
    pub x: F,
    pub y: F,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// A scheme cannot require more shares than it hands out.
    #[error("threshold {threshold} exceeds participants {participants}")]
    ThresholdExceedsParticipants { participants: NonZeroUsize, threshold: NonZeroUsize },

    /// Fewer than `threshold` shares were supplied to [`Scheme::reconstruct`].
    #[error("insufficient shares: got {shares}, need at least {threshold}")]
    InsufficientShares { shares: usize, threshold: NonZeroUsize },

    /// Two or more shares share an `x`-coordinate, which is not a valid input set.
    #[error("shares contain duplicate x-coordinates")]
    DuplicateShares,
}

impl<F: Field> Scheme<F> {
    /// Generates a fresh random secret and deals it into `participants` shares,
    /// `threshold` of which are needed to reconstruct it.
    ///
    /// The secret is the constant term of a random degree-`threshold - 1`
    /// polynomial and is exposed via [`Self::secret`] for setup/key-generation use.
    /// To share a secret that already exists, use [`Self::split`] instead.
    pub fn generate<R: Rng>(
        participants: NonZeroUsize,
        threshold: NonZeroUsize,
        rng: &mut R,
    ) -> Result<Self, Error> {
        if threshold > participants {
            return Err(Error::ThresholdExceedsParticipants { participants, threshold });
        }

        // A degree `threshold - 1` polynomial is uniquely determined by `threshold`
        // points, so exactly that many shares are needed to recover it.
        let poly = DensePolynomial::<F>::rand(threshold.get() - 1, rng);

        let secret = poly.evaluate(&F::ZERO);
        let shares = Self::create_shares(&poly, participants);

        Ok(Self { secret, shares, threshold })
    }

    /// Splits an existing `secret` into `participants` shares, `threshold` of
    /// which are needed to reconstruct it.
    ///
    /// The secret is placed as the constant term of a degree-`threshold - 1`
    /// polynomial whose remaining coefficients are random, so any `threshold - 1`
    /// shares reveal nothing about it. Use this when the secret already exists
    /// (e.g. an existing key to distribute); use [`Self::generate`] to deal a fresh one.
    pub fn split<R: Rng>(
        secret: F,
        participants: NonZeroUsize,
        threshold: NonZeroUsize,
        rng: &mut R,
    ) -> Result<Self, Error> {
        if threshold > participants {
            return Err(Error::ThresholdExceedsParticipants { participants, threshold });
        }

        let mut poly = DensePolynomial::<F>::rand(threshold.get() - 1, rng);
        // Safe: contains at least secret as first coefficient.
        *poly.coeffs.first_mut().unwrap() = secret;

        let shares = Self::create_shares(&poly, participants);
        Ok(Self { secret, shares, threshold })
    }

    // Evaluate at x = 1..=participants; x = 0 is skipped as it is the secret.
    fn create_shares(poly: &DensePolynomial<F>, participants: NonZeroUsize) -> Vec<Share<F>> {
        (0..participants.get())
            .map(|idx| {
                let x = F::from(idx as u64 + 1);
                Share { x, y: poly.evaluate(&x) }
            })
            .collect()
    }

    /// Recovers the secret `f(0)` from `shares` via Lagrange interpolation.
    ///
    /// Any `threshold` shares with distinct `x`-coordinates suffice; supplying
    /// more is harmless. The shares are trusted to lie on the original polynomial —
    /// this is plain reconstruction, not verifiable secret sharing.
    pub fn reconstruct(&self, shares: &[Share<F>]) -> Result<F, Error> {
        if shares.len() < self.threshold.get() {
            return Err(Error::InsufficientShares {
                shares: shares.len(),
                threshold: self.threshold,
            });
        }

        let xs = shares.iter().map(|s| s.x).collect::<Vec<_>>();
        let secret = lagrange_at_zero(&xs)?
            .into_iter()
            .zip(shares)
            .map(|(lambda, Share { y, .. })| lambda * y)
            .sum();

        Ok(secret)
    }
}

/// Lagrange basis coefficients at `x = 0`: `λ_j = Π_{m≠j} x_m / (x_m - x_j)`.
///
/// Fails on duplicate x-coordinates, which would yield a zero denominator.
pub fn lagrange_at_zero<F: Field>(xs: &[F]) -> Result<Vec<F>, Error> {
    for (j, x_j) in xs.iter().enumerate() {
        if xs[j + 1..].contains(x_j) {
            return Err(Error::DuplicateShares);
        }
    }

    Ok(xs
        .iter()
        .enumerate()
        .map(|(j, x_j)| {
            xs.iter()
                .enumerate()
                .filter(|(m, _)| *m != j)
                .map(|(_, x_m)| *x_m / (*x_m - *x_j))
                .product()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    /// Builds a 5-participants, 3-threshold scheme over BLS12-381's base field.
    fn test_scheme() -> Scheme<ark_bls12_381::Fq> {
        Scheme::generate(
            NonZeroUsize::new(5).unwrap(),
            NonZeroUsize::new(3).unwrap(),
            &mut test_rng(),
        )
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
        assert!(matches!(scheme.reconstruct(&shares), Err(Error::InsufficientShares { .. })));
    }

    #[test]
    fn reconstruct_rejects_duplicate_shares() {
        let scheme = test_scheme();
        // Same share repeated to satisfy the count check but with duplicate x-coordinates.
        let shares = vec![scheme.shares[0], scheme.shares[1], scheme.shares[1]];
        assert!(matches!(scheme.reconstruct(&shares), Err(Error::DuplicateShares)));
    }

    #[test]
    fn split_preserves_secret() {
        let secret = ark_bls12_381::Fq::from(42u64);
        let scheme = Scheme::split(
            secret,
            NonZeroUsize::new(5).unwrap(),
            NonZeroUsize::new(3).unwrap(),
            &mut test_rng(),
        )
        .unwrap();
        // The given secret must sit at f(0) and survive a reconstruction round-trip.
        assert_eq!(scheme.secret, secret);
        let shares = vec![scheme.shares[0], scheme.shares[2], scheme.shares[4]];
        assert_eq!(secret, scheme.reconstruct(&shares).unwrap());
    }
}
