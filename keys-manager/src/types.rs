use ed25519_dalek::{Signature, VerifyingKey};

#[derive(Clone)]
pub struct NoncePayload {
    pub user_id: Vec<u8>,
    pub app_id: Vec<u8>,
}

#[derive(Clone)]
pub struct SpicePayload {
    pub nonce: NoncePayload,
    pub signature: Signature,
    pub pub_key: VerifyingKey,
}

impl NoncePayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.user_id);
        bytes.extend_from_slice(&self.app_id);
        bytes
    }
}

#[derive(Clone)]
pub struct CompleteJwt {
    pub user_id: Vec<u8>,
    pub app_id: Vec<u8>,
    pub nonce: Vec<u8>, // H(epk, blinding_factor)
}
