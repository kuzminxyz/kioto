//! Threshold encryption over a pairing `e: G1 × G2 → GT` (see `docs/threshold-encryption.md`).
//!
//! The group key is `P = s · g2` with `s` Shamir-shared among participants. Anyone encrypts to
//! `P`; any `threshold` participants jointly recover the symmetric key without revealing `s`.

use crate::shamir::{self, Share, lagrange_at_zero};
use ark_bls12_381::Bls12_381;
use ark_ec::{
    AffineRepr, CurveGroup, VariableBaseMSM,
    hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
    pairing::{Pairing, PairingOutput},
};
use ark_ff::{AdditiveGroup, UniformRand, field_hashers::DefaultFieldHasher};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use core::num::NonZeroUsize;
use sha2::{Digest, Sha256};

const HASH_TO_G1_DST: &[u8] = b"SHINOBI-V01-CS01-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
const KDF_DST: &[u8] = b"SHINOBI-KDF-V01";

/// Pairing engines with a hash-to-G1 map, required to derive `H = HashToG1(W)`.
pub trait HashToG1: Pairing {
    fn hash_to_g1(msg: &[u8]) -> Self::G1Affine;
}

impl HashToG1 for Bls12_381 {
    fn hash_to_g1(msg: &[u8]) -> Self::G1Affine {
        type Hasher = MapToCurveBasedHasher<
            ark_bls12_381::G1Projective,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<ark_bls12_381::g1::Config>,
        >;
        Hasher::new(HASH_TO_G1_DST)
            .and_then(|h| h.hash(msg))
            .expect("BLS12-381 hash-to-G1 parameters are valid")
    }
}

/// Encrypted message `{E, W, U}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext<E: Pairing> {
    /// `E = M ⊕ KDF(K)`.
    pub e: Vec<u8>,
    /// `W = sha256(M)`.
    pub w: [u8; 32],
    /// `U = r · g2`.
    pub u: E::G2Affine,
}

/// Participant's decryption share `D_i = s_i · U`, tagged with its Shamir index `x_i`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptionShare<E: Pairing> {
    pub x: E::ScalarField,
    pub d: E::G2Affine,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Shamir(#[from] shamir::Error),

    /// Decrypted plaintext does not match `W`: wrong shares or tampered ciphertext.
    #[error("decrypted message hash does not match W")]
    HashMismatch,
}

/// Group public key `P = s · g2`.
pub fn public_key<E: Pairing>(secret: E::ScalarField) -> E::G2Affine {
    (E::G2Affine::generator() * secret).into_affine()
}

/// Group key in G1, `s · g1`, used to publicly check combined keys (see [`verify_combined`]).
pub fn public_key_g1<E: Pairing>(secret: E::ScalarField) -> E::G1Affine {
    (E::G1Affine::generator() * secret).into_affine()
}

/// Per-participant verification key `V_i = s_i · g1`, used to check decryption shares.
pub fn verification_key<E: Pairing>(share: &Share<E::ScalarField>) -> E::G1Affine {
    (E::G1Affine::generator() * share.y).into_affine()
}

/// Message hash `W = sha256(M)`.
pub fn message_hash(msg: &[u8]) -> [u8; 32] {
    Sha256::digest(msg).into()
}

/// Encrypts `msg` to the group key `pk`.
pub fn encrypt<E: HashToG1, R: Rng>(pk: &E::G2Affine, msg: &[u8], rng: &mut R) -> Ciphertext<E> {
    let r = E::ScalarField::rand(rng);
    let u = (E::G2Affine::generator() * r).into_affine();
    let w = message_hash(msg);
    let h = E::hash_to_g1(&w);
    let k = E::pairing(h, *pk * r);
    Ciphertext { e: xor_keystream::<E>(&k, msg), w, u }
}

/// Computes participant's decryption share for ciphertext header `u`.
pub fn decryption_share<E: Pairing>(
    share: &Share<E::ScalarField>,
    u: &E::G2Affine,
) -> DecryptionShare<E> {
    DecryptionShare { x: share.x, d: (*u * share.y).into_affine() }
}

/// Checks `e(V_i, U) == e(g1, D_i)`, i.e. that `D_i` was computed with the share behind `V_i`.
pub fn verify_share<E: Pairing>(
    vk: &E::G1Affine,
    u: &E::G2Affine,
    share: &DecryptionShare<E>,
) -> bool {
    pairing_eq::<E>(vk, u, &share.d)
}

/// Checks `e(s · g1, U) == e(g1, C)`, i.e. that `C` is the correctly combined `s · U`.
pub fn verify_combined<E: Pairing>(pk_g1: &E::G1Affine, u: &E::G2Affine, c: &E::G2Affine) -> bool {
    pairing_eq::<E>(pk_g1, u, c)
}

/// Combines at least `threshold` shares into `C = Σ λ_i · D_i = r · s · g2`.
pub fn combine<E: Pairing>(
    shares: &[DecryptionShare<E>],
    threshold: NonZeroUsize,
) -> Result<E::G2Affine, Error> {
    if shares.len() < threshold.get() {
        return Err(shamir::Error::InsufficientShares { shares: shares.len(), threshold }.into());
    }
    let shares = &shares[..threshold.get()];
    let xs = shares.iter().map(|s| s.x).collect::<Vec<_>>();
    let lambdas = lagrange_at_zero(&xs)?;
    let ds = shares.iter().map(|s| s.d).collect::<Vec<_>>();
    Ok(E::G2::msm_unchecked(&ds, &lambdas).into_affine())
}

/// Decrypts `ct` with the combined key material `c` and checks `hash(M) == W`.
pub fn decrypt<E: HashToG1>(ct: &Ciphertext<E>, c: &E::G2Affine) -> Result<Vec<u8>, Error> {
    let h = E::hash_to_g1(&ct.w);
    let k = E::pairing(h, *c);
    let msg = xor_keystream::<E>(&k, &ct.e);
    if message_hash(&msg) != ct.w {
        return Err(Error::HashMismatch);
    }
    Ok(msg)
}

// `e(a, b) == e(g1, c)` as a single multi-pairing `e(a, b) · e(-g1, c) == 1`.
fn pairing_eq<E: Pairing>(a: &E::G1Affine, b: &E::G2Affine, c: &E::G2Affine) -> bool {
    let neg_g1 = -E::G1Affine::generator();
    E::multi_pairing([*a, neg_g1], [*b, *c]) == PairingOutput::ZERO
}

// KDF: SHA-256 in counter mode over the serialized GT element, XORed with `data`.
fn xor_keystream<E: Pairing>(k: &PairingOutput<E>, data: &[u8]) -> Vec<u8> {
    let mut k_bytes = Vec::new();
    k.serialize_compressed(&mut k_bytes).expect("GT serialization into Vec cannot fail");

    data.chunks(32)
        .enumerate()
        .flat_map(|(i, chunk)| {
            let block = Sha256::new()
                .chain_update(KDF_DST)
                .chain_update(&k_bytes)
                .chain_update((i as u32).to_be_bytes())
                .finalize();
            chunk.iter().zip(block).map(|(a, b)| a ^ b).collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Scheme;
    use ark_bls12_381::Fr;
    use ark_std::test_rng;

    type E = Bls12_381;

    fn setup() -> (Scheme<Fr>, <E as Pairing>::G2Affine) {
        let scheme = Scheme::<Fr>::generate(
            NonZeroUsize::new(5).unwrap(),
            NonZeroUsize::new(3).unwrap(),
            &mut test_rng(),
        )
        .unwrap();
        let pk = public_key::<E>(scheme.secret);
        (scheme, pk)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (scheme, pk) = setup();
        let msg = b"a message longer than a single 32-byte keystream block!";
        let ct = encrypt::<E, _>(&pk, msg, &mut test_rng());
        assert_ne!(&ct.e[..], &msg[..]);

        let shares = [4, 1, 2]
            .iter()
            .map(|&i| decryption_share::<E>(&scheme.shares[i], &ct.u))
            .collect::<Vec<_>>();
        let c = combine(&shares, scheme.threshold).unwrap();
        assert!(verify_combined::<E>(&public_key_g1::<E>(scheme.secret), &ct.u, &c));
        assert_eq!(decrypt(&ct, &c).unwrap(), msg);
    }

    #[test]
    fn insufficient_shares_rejected() {
        let (scheme, pk) = setup();
        let ct = encrypt::<E, _>(&pk, b"secret", &mut test_rng());
        let shares =
            scheme.shares[..2].iter().map(|s| decryption_share::<E>(s, &ct.u)).collect::<Vec<_>>();
        assert!(matches!(
            combine(&shares, scheme.threshold),
            Err(Error::Shamir(shamir::Error::InsufficientShares { .. }))
        ));
    }

    #[test]
    fn wrong_shares_fail_hash_check() {
        let (scheme, pk) = setup();
        let ct = encrypt::<E, _>(&pk, b"secret", &mut test_rng());
        let mut shares =
            scheme.shares[..3].iter().map(|s| decryption_share::<E>(s, &ct.u)).collect::<Vec<_>>();
        shares[0].d = (shares[0].d + shares[1].d).into_affine();
        let c = combine(&shares, scheme.threshold).unwrap();
        assert!(matches!(decrypt(&ct, &c), Err(Error::HashMismatch)));
    }

    #[test]
    fn share_verification() {
        let (scheme, pk) = setup();
        let ct = encrypt::<E, _>(&pk, b"secret", &mut test_rng());
        let vk = verification_key::<E>(&scheme.shares[0]);
        let good = decryption_share::<E>(&scheme.shares[0], &ct.u);
        let bad = decryption_share::<E>(&scheme.shares[1], &ct.u);
        assert!(verify_share(&vk, &ct.u, &good));
        assert!(!verify_share(&vk, &ct.u, &bad));
    }
}
