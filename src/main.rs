use spice_guard::spice_generator;
use user_keys_manager::{
    types::{NoncePayload, SpicePayload},
    *,
};
use zk_prover_verifier_service::proof_verify_1;
pub fn main() {
    let (s_key, v_key, point) = generate_ephemeral_keypair();
    let epk_x: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A,
    ];

    let epk_y: [u8; 32] = [
        0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0xA1, 0xB2, 0xC3, 0xD4,
        0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    ];

    println!("{:?}, {:?}", s_key.as_bytes(), v_key.as_bytes());
    let blinding_factor = String::from("random"); // only used for sheilding epk from google
    let nonce = nonce_generator(&v_key, blinding_factor.as_bytes());
    println!("{:?}", point);
    let (nonce_poideon, new_blinding_factor) =
        nonce_generator_posidon(&epk_x, &epk_y, blinding_factor.as_bytes());

    println!("{:?}, poseidon_nonce", nonce_poideon);

    println!("{:?}, normal_nonce", nonce);
    let jwt_requirement = NoncePayload{
        user_id : to_32_bytes(&String::from("102746713635985261613")),
        app_id: to_32_bytes(&String::from("220840900504-ejj0k4k1rs5g55uktgb7m13i2frmosg0.apps.googleusercontent.com"))
    };
    let sign = sign_payload(&jwt_requirement.to_bytes(), s_key);
    let spice_payload = SpicePayload {
        nonce: jwt_requirement.clone(),
        signature: sign,
        pub_key: v_key,
    };

    let spice = spice_generator(spice_payload, &blinding_factor.as_bytes());
    println!("{:?}, spice", spice);
    let address = create_address(
        &jwt_requirement.user_id,
        &jwt_requirement.app_id,
        &spice,
    );
    println!("{:?}, normal hash", address);

    println!(
        "jwt.user_id{:?},jwt.app_id{:?}, spice{:?}",
        jwt_requirement.user_id.len(),
        jwt_requirement.app_id.len(),
        spice.len()
    );
    let (address_posideon, hex_address) = create_address_posidon(
        &jwt_requirement.user_id,
        &jwt_requirement.app_id,
        &spice,
    );
    println!("{:?}, posideon hash", address_posideon);
    let sid = jwt_requirement.user_id.clone();
    let aud = jwt_requirement.app_id.clone();
    let (e, n, sig, hash) = sign_and_generate(
        jwt_requirement.user_id,
        jwt_requirement.app_id,
        nonce_poideon,
    );
    println!("{:?},{:?},{:?}", e, n, sig);
    //prove service

    //verfication

    println!("switching to zk proof");
    let _ = proof_verify_1(
        hash,
        &epk_x,
        &epk_y,
        &hex_address,
        n.to_bytes_le(),
        sig,
        nonce,
        sid,
        aud,
        &new_blinding_factor,
        spice,
    );
}
