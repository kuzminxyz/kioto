use ark_ec::{hashing::HashToCurve, pairing::Pairing};

mod utils;

mod encryption;
pub use encryption::{EncryptionOutput, Encryptor, Error, ThresholdPublicKey};

mod decryption;

pub const DOMAIN: &str = "KEK";

/// Extension trait for [Pairing] used in Threshold-Publickey-Encryption scheme.
///
/// This trait provides extra [MapToG1Hasher] used to map ciphertext hash to G1 group point.
///
/// [MapToG1Hasher]: Self::MapToG1Hasher
pub trait PairingExt: Pairing {
    /// Hasher to G1 curve point.
    type MapToG1Hasher: HashToCurve<Self::G1>;
}

/// Shared test scaffolding: a concrete [`PairingExt`] instance over BLS12-381,
/// wiring the standard WB hash-to-curve for G1. Used by the encryption and
/// decryption unit tests.
#[cfg(test)]
pub(crate) mod test_curve {
    use ark_bls12_381::Bls12_381;
    use ark_ec::hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher};
    use ark_ff::field_hashers::DefaultFieldHasher;
    use sha2::Sha256;

    use super::PairingExt;

    /// Concrete pairing used across the tpke tests.
    pub(crate) type Curve = Bls12_381;

    impl PairingExt for Bls12_381 {
        type MapToG1Hasher = MapToCurveBasedHasher<
            <Bls12_381 as ark_ec::pairing::Pairing>::G1,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<ark_bls12_381::g1::Config>,
        >;
    }
}
