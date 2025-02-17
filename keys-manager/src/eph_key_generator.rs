use blake2::{Blake2b512, Digest};
use ed25519_dalek::{
    ed25519::signature::SignerMut, Signature, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;
use sp_core::crypto::Ss58Codec;

use crate::types::SpicePayload;

pub fn generate_ephemeral_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
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

pub fn sign_payload(payload: &[u8], mut private_key: SigningKey) -> Signature {
    private_key.sign(&payload)
}

pub fn verify_signature(payload: SpicePayload) -> bool {
    let pub_key = payload.pub_key;
    pub_key
        .verify_strict(&payload.nonce.to_bytes(), &payload.signature)
        .is_ok()
}
