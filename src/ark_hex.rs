//! `#[serde(with = "crate::ark_hex")]` for arkworks types: compressed bytes as a hex string.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserializer, Serializer, de, ser};

pub fn serialize<T: CanonicalSerialize, S: Serializer>(v: &T, s: S) -> Result<S::Ok, S::Error> {
    let mut bytes = Vec::new();
    v.serialize_compressed(&mut bytes).map_err(ser::Error::custom)?;
    const_hex::serialize(bytes, s)
}

/// Validating deserialization: points off the curve or outside the subgroup are rejected.
pub fn deserialize<'de, T: CanonicalDeserialize, D: Deserializer<'de>>(
    d: D,
) -> Result<T, D::Error> {
    let bytes: Vec<u8> = const_hex::deserialize(d)?;
    T::deserialize_compressed(&bytes[..]).map_err(de::Error::custom)
}
