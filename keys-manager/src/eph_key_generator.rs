use blake2::{Blake2b512, Digest};
use ed25519_dalek::{
    ed25519::signature::SignerMut, Signature, SigningKey, VerifyingKey,
};

use rand::rngs::OsRng;
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

// pub fn create_address(user_id, app_id, spice){

// }
