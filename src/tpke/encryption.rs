use std::ops::Mul;

use ark_ec::{
    CurveGroup, PrimeGroup,
    hashing::{HashToCurve, HashToCurveError},
    pairing::PairingOutput,
};
use ark_ff::UniformRand;
use ark_serialize::SerializationError;
use ark_std::rand::{CryptoRng, Rng};

use super::{PairingExt, utils, DOMAIN};


/// Public key of the threshold scheme, shared by encryption and decryption.
///
/// It is the group generator point multiplied by the scheme secret scalar
/// from [Scheme::secret]. The scalar itself is never part of this type.
///
/// [Scheme::secret]: crate::shamir::Scheme::secret
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThresholdPublicKey<Group: CurveGroup>(pub Group::Affine);

impl<Group: CurveGroup> ThresholdPublicKey<Group> {
    /// Creates new public key from provided scalar.
    pub fn from_scalar(scalar: Group::Scalar) -> Self {
        Self(<Group as PrimeGroup>::generator().mul(scalar).into_affine())
    }
}

pub struct EncryptionOutput<CRV: PairingExt> {
    /// `U = r * g2`.
    pub u: CRV::G2,
    /// The hash of initial encrypted ciphertext.
    pub w: blake3::Hash,
    /// Encrypted message.
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("arkworks serialization error: {0}")]
    Serialization(#[from] SerializationError),

    #[error("arkworks hash-to-curve error: {0}")]
    HashToCurveError(#[from] HashToCurveError),

    #[error("failed to xor two vectors")]
    XorError,
}

pub struct Encryptor<CRV: PairingExt> {
    /// Threshold scheme public key.
    key: ThresholdPublicKey<CRV::G2>,
}

impl<CRV: PairingExt> Encryptor<CRV> {
    /// Creates new [`Encryptor`] with provided scheme public key.
    pub fn new(public_key: ThresholdPublicKey<CRV::G2>) -> Self {
        Self { key: public_key }
    }

    /// Returns public key used to encrypt message.
    pub fn public_key(&self) -> ThresholdPublicKey<CRV::G2> {
        self.key
    }

    /// Enctypt bytes with provided random generator
    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        message: Vec<u8>,
        rng: &mut R,
    ) -> Result<EncryptionOutput<CRV>, Error> {
        // Generating random scalar using provided random.
        let salt = CRV::ScalarField::rand(rng);
        self.encrypt_with_salt(message, salt)
    }

    pub fn encrypt_with_salt(
        &self,
        mut message: Vec<u8>,
        salt: CRV::ScalarField,
    ) -> Result<EncryptionOutput<CRV>, Error> {
        let g2 = CRV::G2::generator();
        let u = g2.mul(salt);

        let w = blake3::hash(&message);
        let h = CRV::MapToG1Hasher::new(DOMAIN.as_bytes())?.hash(w.as_slice())?;

        // Encryption key is a result of
        let symmetric_key_gt = CRV::pairing(h, self.key.0.mul(salt));
        hide_message(&mut message, &symmetric_key_gt)?;

        Ok(EncryptionOutput { u, w, ciphertext: message })
    }
}

fn hide_message<CRV: PairingExt>(
    message: &mut [u8],
    symmetric_key_gt: &PairingOutput<CRV>,
) -> Result<(), Error> {
    let serialized_symmetric_key = utils::ark_serialize(&symmetric_key_gt)?;

    let mut mask = vec![0u8; message.len()];
    blake3::Hasher::new_derive_key("yonago encryption")
        .update(&serialized_symmetric_key)
        .finalize_xof()
        .fill(&mut mask);

    // XOR message and mask
    message.iter_mut().zip(mask).for_each(|(d, m)| *d ^= m);
    Ok(())
}
