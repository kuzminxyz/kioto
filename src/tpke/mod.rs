use ark_ec::{hashing::HashToCurve, pairing::Pairing};

mod utils;

mod encryption;
pub use encryption::{EncryptionKey, EncryptionOutput, Encryptor, Error};

/// Extension trait for [Pairing] used in Threshold-Publickey-Encryption scheme.
///
/// This trait provides extra [MapToG1Hasher] used to map ciphertext hash to G1 group point.
/// 
/// [MapToG1Hasher]: Self::MapToG1Hasher
pub trait PairingExt: Pairing {
    /// Hasher to G1 curve point.
    type MapToG1Hasher: HashToCurve<Self::G1>;
}
