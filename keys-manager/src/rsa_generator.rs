use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::BigUint;
use rsa::RsaPrivateKey;

pub fn sign_and_generate(
    sid: Vec<u8>,         // Changed from u128 to Vec<u8>
    aud: Vec<u8>,         // Changed from u128 to Vec<u8>
    input_hash: [u8; 32], // Precomputed hash (e.g., Poseidon output)
) -> (BigUint, BigUint, Vec<u8>, Vec<u8>) {
    let mut rng = OsRng;

    // Generate RSA keypair (2048-bit)
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    let public_key = private_key.to_public_key(); // Get RsaPublicKey directly
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());

    // Compute SHA-256 hash of (sid, aud, input_hash)
    let mut hasher = Sha256::new();
    hasher.update(&sid); // Using Vec<u8> directly
    hasher.update(&aud); // Using Vec<u8> directly
    hasher.update(&input_hash);
    let hashed_data = hasher.finalize();

    // Sign the hashed data
    let signature = signing_key.sign_with_rng(&mut rng, &hashed_data);

    // Extract public key components (e, n) from RsaPublicKey
    let e = public_key.e().clone();
    let n = public_key.n().clone();

    // Return (e, n, sig)
    (e, n, signature.to_vec(), hashed_data.to_vec())
}
// /// Example usage
// fn main() {
//     let sid = 12345u128;
//     let aud = 67890u128;
//     let input_hash = vec![1, 2, 3, 4, 5]; // Example hash (e.g., Poseidon output)

//     let (e, n, sig) = sign_and_generate(sid, aud, input_hash);

//     println!("Public Exponent (e): {}", e);
//     println!("Modulus (n): {}", hex::encode(&n.to_bytes_le()));
//     println!("Signature: {}", hex::encode(&sig));
// }
