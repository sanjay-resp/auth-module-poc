use crate::types::SpicePayload;
use ark_bn254::Fr;

use ark_ff::{BigInteger, BigInteger256, PrimeField};
use blake2::{Blake2b512, Blake2s256, Digest};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use ed25519_dalek::{
    ed25519::signature::SignerMut, Signature, SigningKey, VerifyingKey,
};
use light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonHasher};
use rand::rngs::OsRng;
use sha2::Sha256;
use sp_core::crypto::Ss58Codec;

pub fn generate_ephemeral_keypair() -> (SigningKey, VerifyingKey, EdwardsPoint)
{
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let compressed_bytes = verifying_key.to_bytes();
    let compressed = CompressedEdwardsY(compressed_bytes);
    println!("{:?}, y", compressed);
    let point = compressed
        .decompress()
        .expect("Failed to decompress VerifyingKey into EdwardsPoint");
    // Extract x and y coordinates as Scalars

    (signing_key, verifying_key, point)
}

pub fn nonce_generator(
    verifying_key: &VerifyingKey,
    blinding_factor: &[u8],
) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    hasher.update(verifying_key.as_bytes());
    hasher.update(blinding_factor);
    hasher.finalize().to_vec()
}

pub fn nonce_generator_posidon(
    epk_x: &[u8; 32],
    epk_y: &[u8; 32],
    blinding_factor: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let mut poseidon = Poseidon::<Fr>::new_circom(3).unwrap();
    println!(
        "nonce {:?},{:?}, {:?}",
        epk_x.len(),
        epk_y.len(),
        blinding_factor.len()
    );
    //update hash as well
    let mut hasher = Sha256::new();
    hasher.update(blinding_factor.iter().as_slice());
    let blinding_factor_e: [u8; 32] = hasher.finalize().into();

    let input1 = Fr::from_be_bytes_mod_order(epk_x);
    let input2 = Fr::from_be_bytes_mod_order(epk_y);
    let input3 = Fr::from_be_bytes_mod_order(&blinding_factor_e);
    let pos_hash = poseidon.hash(&[input1, input2, input3]).unwrap();
    let hash = pos_to_bytes(pos_hash);
    println!("{:?}", hash);
    (hash, blinding_factor_e)
}

pub fn sign_txs(txs: &[u8; 128], mut private_key: SigningKey) -> Signature {
    private_key.sign(txs)
}

pub fn create_address(user_id: &[u8], app_id: &[u8], spice: &[u8]) -> String {
    let mut hasher = Blake2b512::new();
    hasher.update(user_id);
    hasher.update(app_id);
    hasher.update(spice);
    let result = hasher.finalize();
    let encoded =
        sp_core::sr25519::Public::from_raw(result[..32].try_into().unwrap())
            .to_ss58check();
    encoded
}

pub fn create_address_posidon(
    user_id: &[u8],
    app_id: &[u8],
    spice: &[u8],
) -> (String, [u8; 32]) {
    let mut poseidon = Poseidon::<Fr>::new_circom(3).unwrap();
    println!("{:?}, user_id", user_id.to_vec());
    let input1 = Fr::from_be_bytes_mod_order(user_id);
    let input2 = Fr::from_be_bytes_mod_order(app_id);
    let input3 = Fr::from_be_bytes_mod_order(spice);
    let pos_hash = poseidon.hash(&[input1, input2, input3]).unwrap();
    let hash = pos_to_bytes(pos_hash);

    let encoded =
        sp_core::sr25519::Public::from_raw(hash[..32].try_into().unwrap())
            .to_ss58check();
    let encoded_value =
        sp_core::sr25519::Public::from_raw(hash[..32].try_into().unwrap());

    (encoded, encoded_value.0)
}

pub fn sign_payload(payload: &[u8], mut private_key: SigningKey) -> Signature {
    private_key.sign(&payload)
}

pub fn verify_signature(payload: SpicePayload) -> bool {
    let pub_key = payload.pub_key;
    pub_key
        .verify_strict(&payload.nonce.to_bytes(), &payload.signature)
        .is_ok()
}

pub fn to_32_bytes(value: &str) -> Vec<u8> {
    let mut hasher = Blake2s256::new();
    hasher.update(value.as_bytes());
    let result = hasher.finalize();
    result.to_vec() // Convert to Vec<u8>
}

fn pos_to_bytes(hash: Fr) -> [u8; 32] {
    let big_int: BigInteger256 = hash.into_bigint();
    let bytes = big_int.to_bytes_le();
    bytes.try_into().expect("Hash should be exactly 32 bytes")
}
