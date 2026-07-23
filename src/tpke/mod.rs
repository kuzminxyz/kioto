use std::ops::Mul;

use ark_ec::{
    CurveGroup, PrimeGroup,
    hashing::{HashToCurve, HashToCurveError},
    pairing::Pairing,
};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalSerialize, SerializationError};
use ark_std::rand::{CryptoRng, Rng};

const DOMAIN: &str = "KEK";

pub trait PairingExt: Pairing {
    type MapToG1Hasher: HashToCurve<Self::G1>;
}

/// Encryption key is a secret scalar from [Scheme::secret]
/// multiplied by croup generator point.
///
/// [Scheme::secret]: crate::shamir::Scheme::secret
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionKey<Group: CurveGroup>(pub Group::Affine);

impl<Group: CurveGroup> EncryptionKey<Group> {
    pub fn from_scalar(scalar: Group::Scalar) -> Self {
        Self(<Group as PrimeGroup>::generator().mul(scalar).into_affine())
    }
}

/// Ciphertext over `T`
pub struct Ciphertext<T> {
    inner: Vec<u8>,
    _type: core::marker::PhantomData<T>,
}

pub struct EncryptionOutput<CRV: PairingExt> {
    /// `U = r * g2`.
    pub u: CRV::G2,
    /// The hash of initial encrypted ciphertext.
    pub w: blake3::Hash,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("arkworks serialization error: {0}")]
    Serialization(#[from] SerializationError),

    #[error("arkworks hash-to-curve error: {0}")]
    HashToCurveError(#[from] HashToCurveError),
}

pub fn encrypt<CRV: PairingExt, R: Rng + CryptoRng>(
    message: Vec<u8>,
    encryption_key: EncryptionKey<CRV::G2>,
    rng: &mut R,
) -> Result<EncryptionOutput<CRV>, Error> {
    // Generating random scalar using provided random.
    let salt = CRV::ScalarField::rand(rng);
    encrypt_with_salt(message, encryption_key, salt)
}

pub fn encrypt_with_salt<CRV: PairingExt>(
    message: Vec<u8>,
    encryption_key: EncryptionKey<CRV::G2>,
    salt: CRV::ScalarField,
) -> Result<EncryptionOutput<CRV>, Error> {
    let g2 = CRV::G2::generator();
    let u = g2.mul(salt);

    let w = blake3::hash(&message);
    let h = CRV::MapToG1Hasher::new(DOMAIN.as_bytes())?.hash(w.as_slice())?;
    let symmetric_key_gt = CRV::pairing(h, encryption_key.0.mul(salt));

    let mut writer = Vec::<u8>::new();
    symmetric_key_gt.serialize_compressed(&mut writer)?;

    Ok(EncryptionOutput { u, w })
}
