use std::ops::Mul;

use ark_ec::{
    CurveGroup, PrimeGroup,
    hashing::{HashToCurve, HashToCurveError},
    pairing::PairingOutput,
};
use ark_ff::UniformRand;
use ark_serialize::SerializationError;
use ark_std::rand::Rng;

use super::{DOMAIN, PairingExt, utils};

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

    /// Encrypt bytes with provided random generator
    // TODO: restore the `CryptoRng` bound once tests use a cryptographically
    // secure RNG (ark-std's `test_rng()` is only `Rng`, not `CryptoRng`).
    pub fn encrypt<R: Rng>(
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
        xor_message(&mut message, &symmetric_key_gt)?;

        Ok(EncryptionOutput { u, w, ciphertext: message })
    }
}


pub(crate) fn xor_message<CRV: PairingExt>(
    message: &mut [u8],
    symmetric_key_gt: &PairingOutput<CRV>,
) -> Result<(), SerializationError> {
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

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ec::{CurveGroup, hashing::HashToCurve, pairing::Pairing};
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    use super::*;
    use crate::tpke::test_curve::Curve;

    /// Builds an encryptor whose public key is `secret * g2`, returning both so the
    /// tests can reconstruct the symmetric key the encryptor derives.
    fn setup() -> (Fr, Encryptor<Curve>) {
        let mut rng = test_rng();
        let secret = Fr::rand(&mut rng);
        let public_key = ThresholdPublicKey::from_scalar(secret);
        (secret, Encryptor::new(public_key))
    }

    /// Recomputes the symmetric key the encryptor uses for the given salt:
    /// `K = e(HashToG1(W), secret * g2 * salt)`.
    fn symmetric_key(
        secret: Fr,
        output: &EncryptionOutput<Curve>,
        salt: Fr,
    ) -> PairingOutput<Curve> {
        let h = <Curve as PairingExt>::MapToG1Hasher::new(DOMAIN.as_bytes())
            .unwrap()
            .hash(output.w.as_slice())
            .unwrap();
        let g2 = <Curve as Pairing>::G2::generator();
        Curve::pairing(h, g2.mul(secret * salt).into_affine())
    }

    #[test]
    fn public_key_roundtrips_through_encryptor() {
        let (secret, encryptor) = setup();
        assert_eq!(encryptor.public_key(), ThresholdPublicKey::from_scalar(secret));
    }

    #[test]
    fn encrypt_with_salt_is_deterministic() {
        let (_secret, encryptor) = setup();
        let salt = Fr::from(7u64);
        let message = b"anti-mev payload".to_vec();

        let a = encryptor.encrypt_with_salt(message.clone(), salt).unwrap();
        let b = encryptor.encrypt_with_salt(message, salt).unwrap();

        assert_eq!(a.u, b.u);
        assert_eq!(a.w, b.w);
        assert_eq!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn distinct_salts_produce_distinct_outputs() {
        let (_secret, encryptor) = setup();
        let message = b"anti-mev payload".to_vec();

        let a = encryptor.encrypt_with_salt(message.clone(), Fr::from(1u64)).unwrap();
        let b = encryptor.encrypt_with_salt(message, Fr::from(2u64)).unwrap();

        // `U = salt * g2` and the derived mask both depend on the salt.
        assert_ne!(a.u, b.u);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn ciphertext_keeps_length_and_commits_to_plaintext_hash() {
        let (_secret, encryptor) = setup();
        let message = b"anti-mev payload".to_vec();

        let output = encryptor.encrypt_with_salt(message.clone(), Fr::from(3u64)).unwrap();

        assert_eq!(output.ciphertext.len(), message.len());
        // `W` is the plaintext hash, independent of the salt.
        assert_eq!(output.w, blake3::hash(&message));
        // The stream cipher must not leave the plaintext in the clear.
        assert_ne!(output.ciphertext, message);
    }

    #[test]
    fn encryption_is_invertible_with_matching_key() {
        let (secret, encryptor) = setup();
        let salt = Fr::from(11u64);
        let message = b"anti-mev payload".to_vec();

        let output = encryptor.encrypt_with_salt(message.clone(), salt).unwrap();

        // XORing the ciphertext with the same symmetric key must recover the plaintext.
        let key = symmetric_key(secret, &output, salt);
        let mut recovered = output.ciphertext.clone();
        xor_message::<Curve>(&mut recovered, &key).unwrap();
        assert_eq!(recovered, message);
    }

    #[test]
    fn encrypts_empty_message() {
        let (_secret, encryptor) = setup();

        let output = encryptor.encrypt_with_salt(Vec::new(), Fr::from(5u64)).unwrap();

        assert!(output.ciphertext.is_empty());
        assert_eq!(output.w, blake3::hash(&[]));
    }

    #[test]
    fn encrypt_uses_a_fresh_random_salt_each_call() {
        let (_secret, encryptor) = setup();
        let mut rng = test_rng();
        let message = b"anti-mev payload".to_vec();

        let a = encryptor.encrypt(message.clone(), &mut rng).unwrap();
        let b = encryptor.encrypt(message, &mut rng).unwrap();

        // Independent random salts must yield different `U` values.
        assert_ne!(a.u, b.u);
    }
}
