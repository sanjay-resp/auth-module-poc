use blake2::{Blake2s256, Digest};
use user_keys_manager::{
    types::{NoncePayload, SpicePayload},
    verify_signature,
};

pub fn spice_generator(
    payload: SpicePayload,
    _blinding_factor: &[u8],
) -> Vec<u8> {
    let valid_sign = verify_signature(payload.clone());
    //add additional check for blinding factor
    match valid_sign {
        true => spice_guard(payload.nonce),
        false => panic!("Invalid signature"),
    }
}

fn spice_guard(jwt_payload: NoncePayload) -> Vec<u8> {
    let mut hasher = Blake2s256::new();
    hasher.update(jwt_payload.user_id.clone());
    hasher.update(jwt_payload.app_id.clone());
    hasher.finalize().to_vec()
}
