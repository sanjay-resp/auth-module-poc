use spice_guard::spice_generator;
use user_keys_manager::{
    types::{NoncePayload, SpicePayload},
    *,
};
use zk_prover_verifier_service::proof_verify_1;

pub fn main() {
    let (s_key, v_key) = generate_ephemeral_keypair();
    println!("{:?}, {:?}", s_key.as_bytes(), v_key.as_bytes());
    let blinding_factor = String::from("random"); // only used for sheilding epk from google
    let nonce = nonce_generator(&v_key, blinding_factor.as_bytes());
    println!("{:?}", nonce);
    let jwt_requirement = NoncePayload{
        user_id : String::from("102746713635985261613").into_bytes(),
        app_id: String::from("9128733114858-bxsg5t2vffphn2il70bmg3mn7cohljv4.apps.googleusercontent.com").into_bytes()
    };
    let sign = sign_payload(&jwt_requirement.to_bytes(), s_key);
    let spice_payload = SpicePayload {
        nonce: jwt_requirement.clone(),
        signature: sign,
        pub_key: v_key,
    };

    let spice = spice_generator(spice_payload, &blinding_factor.as_bytes());
    let address = create_address(
        &jwt_requirement.user_id,
        &jwt_requirement.app_id,
        &spice,
    );

    println!("{:?}", address);

    println!("switching to zk proof");
    let _ = proof_verify_1();
}
