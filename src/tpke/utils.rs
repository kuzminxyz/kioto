use ark_serialize::{CanonicalSerialize, SerializationError};

pub fn ark_serialize<C: CanonicalSerialize>(point: &C) -> Result<Vec<u8>, SerializationError> {
    let mut writer = Vec::with_capacity(point.compressed_size());
    point.serialize_compressed(&mut writer).map(|()| writer)
}
